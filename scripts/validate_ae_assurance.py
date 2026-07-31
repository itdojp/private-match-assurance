#!/usr/bin/env python3
"""Validate all ae Assurance authorities, fixtures, and generated packages."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
from typing import Any

try:
    from ae_assurance_common import (
        AssuranceIntegrationError,
        STATUS_VALUES,
        build_schema_registry,
        load_schema,
        read_strict_json,
        resolve_regular_file,
        validate_schema_instance,
    )
    from ae_assurance_implementation import (
        MANIFEST_PATH,
        adapter_source_digest,
        verify_manifest,
    )
    from ae_assurance_output_set import validate_output_directory
    from ae_framework_adapter import (
        _combined_automated_judgment,
        _producer_gate_judgment,
        derive_native_judgment,
        PRODUCER_IDS,
        _parse_time,
        recompute_native_projection_from_assurance_package,
        validate_tool_bindings,
    )
    from ae_assurance_policy import (
        ASSURANCE_CONTENT_DOMAIN,
        ASSURANCE_PACKAGE_DOMAIN,
        EVIDENCE_RECORD_DOMAIN,
        FIXTURE_CATALOG_PATH,
        JSON_REPORT_DOMAIN,
        MARKDOWN_REPORT_DOMAIN,
        NATIVE_PROJECTION_DOMAIN,
        NATIVE_INPUT_MANIFEST_DOMAIN,
        load_authority,
        load_protocol_authority,
        load_schemas,
        protocol_authority_binding,
        verify_fixture_catalog,
    )
    from canonical_json import domain_digest, file_digest, strict_loads
    from render_ae_assurance_report import render_markdown
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import (
        AssuranceIntegrationError,
        STATUS_VALUES,
        build_schema_registry,
        load_schema,
        read_strict_json,
        resolve_regular_file,
        validate_schema_instance,
    )
    from scripts.ae_assurance_implementation import (
        MANIFEST_PATH,
        adapter_source_digest,
        verify_manifest,
    )
    from scripts.ae_assurance_output_set import validate_output_directory
    from scripts.ae_framework_adapter import (
        _combined_automated_judgment,
        _producer_gate_judgment,
        derive_native_judgment,
        PRODUCER_IDS,
        _parse_time,
        recompute_native_projection_from_assurance_package,
        validate_tool_bindings,
    )
    from scripts.ae_assurance_policy import (
        ASSURANCE_CONTENT_DOMAIN,
        ASSURANCE_PACKAGE_DOMAIN,
        EVIDENCE_RECORD_DOMAIN,
        FIXTURE_CATALOG_PATH,
        JSON_REPORT_DOMAIN,
        MARKDOWN_REPORT_DOMAIN,
        NATIVE_PROJECTION_DOMAIN,
        NATIVE_INPUT_MANIFEST_DOMAIN,
        load_authority,
        load_protocol_authority,
        load_schemas,
        protocol_authority_binding,
        verify_fixture_catalog,
    )
    from scripts.canonical_json import domain_digest, file_digest, strict_loads
    from scripts.render_ae_assurance_report import render_markdown


FIXTURE_ROOT = Path("tests/fixtures/ae-framework")


def validate_judgment_approval_boundary(
    automated_state: str, approval_state: str
) -> None:
    if approval_state not in {"required-not-provided", "not-applicable-test-only"}:
        raise AssuranceIntegrationError(
            "current runner cannot represent a live approval"
        )
    if automated_state == "blocked" and approval_state == "required-not-provided":
        return


def validate_package(root: Path, package: dict[str, Any]) -> None:
    pin, inventory, profile = load_authority(root)
    protocol_authority = load_protocol_authority(root)
    expected_protocol_binding = protocol_authority_binding(protocol_authority)
    schemas = load_schemas(root)
    registry = build_schema_registry(schemas.values())
    validate_schema_instance(package, schemas["package"], registry=registry)
    for evidence in package["evidence_records"]:
        validate_schema_instance(evidence, schemas["evidence"], registry=registry)
    validate_schema_instance(
        package["automated_judgment"], schemas["automated"], registry=registry
    )
    validate_schema_instance(
        package["producer_gate_judgment"], schemas["producer_gate"], registry=registry
    )
    validate_schema_instance(
        package["native_ae_judgment"], schemas["native_judgment"], registry=registry
    )
    validate_schema_instance(
        package["human_approval"], schemas["approval"], registry=registry
    )
    if package["integration_profile"] != {
        "id": profile["profile_id"],
        "version": profile["profile_version"],
        "digest": profile["profile_digest"],
    }:
        raise AssuranceIntegrationError("Assurance profile binding does not match")
    if package["protocol_conformance_authority"] != expected_protocol_binding:
        raise AssuranceIntegrationError(
            "Assurance Protocol/conformance authority does not match"
        )
    expected_ae_framework_static = {
        "repository": pin["repository"],
        "commit": pin["commit"],
        "package_name": pin["package"]["name"],
        "package_version": pin["package"]["version"],
        "source_tree_digest": pin["source_manifest"]["source_tree_digest"],
    }
    if any(
        package["ae_framework"].get(key) != value
        for key, value in expected_ae_framework_static.items()
    ):
        raise AssuranceIntegrationError("ae-framework package binding does not match")
    expected_adapter = {
        "id": "private-match-assurance/ae-framework-adapter",
        "version": "0.1",
        "implementation_digest": adapter_source_digest(root),
    }
    if package["adapter"] != expected_adapter:
        raise AssuranceIntegrationError("adapter implementation binding does not match")
    validation_provenance = package["validation_provenance"]
    expected_validation_provenance = {
        "validated_at": validation_provenance["validated_at"],
        "producer_package_created_at": validation_provenance[
            "producer_package_created_at"
        ],
        "producer_package_digest": package["input_producer_package_digest"],
        "integration_profile_digest": profile["profile_digest"],
        "adapter_implementation_digest": expected_adapter["implementation_digest"],
    }
    if validation_provenance != expected_validation_provenance:
        raise AssuranceIntegrationError("validation provenance binding does not match")
    validated_at = _parse_time(validation_provenance["validated_at"])
    producer_created_at = _parse_time(
        validation_provenance["producer_package_created_at"]
    )
    if validated_at < producer_created_at:
        raise AssuranceIntegrationError("validation precedes producer package creation")

    external_by_role = {
        item["tool_role_id"]: item for item in package["external_tool_inventory"]
    }
    if len(external_by_role) != len(package["external_tool_inventory"]):
        raise AssuranceIntegrationError("external tool inventory has duplicate roles")
    output_bindings = [
        {
            "tool_role_id": item["tool_role_id"],
            "producer_type": item["producer_type"],
            "mode": item["mode"],
            "identity": item["tool_id"],
            "version": item["tool_version"],
            "implementation_digest": item["tool_implementation_digest"],
            "input_contract": item["input_contract"],
            "output_contract": item["output_contract"],
            "limitations": item["limitations"],
            "binding_digest": item["tool_binding_digest"],
        }
        for item in package["external_tool_inventory"]
    ]
    ordered_bindings = validate_tool_bindings(
        root, package["execution_mode"], output_bindings, inventory
    )
    expected_external_tools = [
        {
            "tool_role_id": role["tool_id"],
            "producer_type": role["producer_type"],
            "requirement": role["requirement"],
            "mode": binding["mode"],
            "tool_id": binding["identity"],
            "tool_version": binding["version"],
            "tool_implementation_digest": binding["implementation_digest"],
            "input_contract": binding["input_contract"],
            "output_contract": binding["output_contract"],
            "limitations": binding["limitations"],
            "tool_binding_digest": binding["binding_digest"],
        }
        for role, binding in zip(inventory["tools"], ordered_bindings, strict=True)
    ]
    if package["external_tool_inventory"] != expected_external_tools:
        raise AssuranceIntegrationError("external tool inventory does not match")

    refs = {item["evidence_id"]: item for item in package["evidence_record_refs"]}
    evidence_ids: set[str] = set()
    counts = {status: 0 for status in STATUS_VALUES}
    tools_by_id = {tool["tool_id"]: tool for tool in inventory["tools"]}
    expected_producers = []
    expected_order = [binding["identity"] for binding in ordered_bindings]
    observed_order = [record["tool"]["name"] for record in package["evidence_records"]]
    if observed_order != expected_order:
        raise AssuranceIntegrationError("Evidence tool order does not match inventory")
    expected_suite_digest = expected_protocol_binding["conformance_suite"]["digest"]
    for record in package["evidence_records"]:
        if record["id"] in evidence_ids:
            raise AssuranceIntegrationError(
                "Assurance package contains duplicate Evidence IDs"
            )
        evidence_ids.add(record["id"])
        counts[record["status"]] += 1
        ref = refs.get(record["id"])
        if (
            ref is None
            or ref["status"] != record["status"]
            or ref["record_digest"] != domain_digest(EVIDENCE_RECORD_DOMAIN, record)
        ):
            raise AssuranceIntegrationError(
                "Evidence reference does not preserve status"
            )
        configuration = record.get("configuration", {})
        tool_id = configuration.get("tool_role_id")
        tool = tools_by_id.get(tool_id)
        external = external_by_role.get(tool_id)
        producer_type = configuration.get("ae_producer_type")
        producer_version = configuration.get("ae_producer_version")
        if (
            tool is None
            or external is None
            or producer_type != tool["producer_type"]
            or record["producer"]["identity"]
            != PRODUCER_IDS[package["execution_mode"]][producer_type]
            or record["tool"]["name"] != external["tool_id"]
            or record["tool"]["version"] != external["tool_version"]
            or record["tool"]["source"] != external["tool_implementation_digest"]
            or configuration.get("tool_binding_digest")
            != external["tool_binding_digest"]
            or configuration.get("tool_input_contract") != external["input_contract"]
            or configuration.get("tool_output_contract") != external["output_contract"]
            or record["execution"]["required"] != (tool["requirement"] == "required")
            or record["execution"]["ran"]
            != (record["status"] not in {"skip", "unsupported"})
            or not isinstance(producer_version, str)
        ):
            raise AssuranceIntegrationError("Evidence tool binding does not match")
        started_at = _parse_time(record["started_at"])
        completed_at = _parse_time(record["completed_at"])
        if not (started_at <= completed_at <= producer_created_at <= validated_at):
            raise AssuranceIntegrationError("Evidence validation chronology is invalid")
        if record["lifecycle_history"] != [
            {
                "state": "collected",
                "recorded_at": record["started_at"],
                "review_digest": None,
            },
            {
                "state": "validated",
                "recorded_at": validation_provenance["validated_at"],
                "review_digest": package["input_producer_package_digest"],
            },
        ]:
            raise AssuranceIntegrationError(
                "Evidence lifecycle does not match validation provenance"
            )
        if (
            len(record["input_digests"]) != 5
            or record["input_digests"][0] != expected_suite_digest
        ):
            raise AssuranceIntegrationError(
                "Evidence input digests do not match the reviewed suite authority"
            )
        if record["type"] == "conformance":
            if configuration.get("protocol") != {
                "identifier": expected_protocol_binding["protocol"]["identifier"],
                "version": expected_protocol_binding["protocol"]["version"],
            } or configuration.get("conformance_suite") != {
                "identifier": expected_protocol_binding["conformance_suite"][
                    "identifier"
                ],
                "version": expected_protocol_binding["conformance_suite"]["version"],
            }:
                raise AssuranceIntegrationError(
                    "conformance Evidence authority does not match"
                )
        if producer_type == "formal-tool" and (
            record["type"] != "proof-check" or record["model_check"] is not None
        ):
            raise AssuranceIntegrationError(
                "formal-tool Evidence is not the reviewed proof-check contract"
            )
        expected_subject_identifier = (
            "synthetic-private-match-product"
            if package["execution_mode"] == "fixture-test"
            else "private-match-product"
        )
        expected_subject = package["evidence_records"][0]["subject"]
        if (
            record["subject"] != expected_subject
            or record["subject"]["identifier"] != expected_subject_identifier
        ):
            raise AssuranceIntegrationError(
                "Evidence subjects do not share one source revision"
            )
        if package["execution_mode"] == "fixture-test" and (
            configuration.get("test_only") is not True
            or configuration.get("retention_classification")
            != "synthetic-public-fixture"
        ):
            raise AssuranceIntegrationError(
                "fixture Evidence provenance does not match"
            )
        if package["execution_mode"] == "private-candidate" and (
            configuration.get("test_only") is not False
            or configuration.get("retention_classification")
            != "private-assurance-retained"
            or record["subject"]["identifier"] == "synthetic-private-match-product"
            or record["producer"]["identity"] == "synthetic-reviewer"
            or "Public synthetic fixture only" in str(record)
            or "synthetic-public-fixture" in str(record)
        ):
            raise AssuranceIntegrationError(
                "private candidate provenance does not match"
            )
        expected_producers.append(
            {
                "evidence_id": record["id"],
                "producer_type": producer_type,
                "producer_id": record["producer"]["identity"],
                "producer_version": producer_version,
                "tool_role_id": tool_id,
                "tool_id": external["tool_id"],
                "tool_version": record["tool"]["version"],
                "tool_implementation_digest": record["tool"]["source"],
                "tool_binding_digest": external["tool_binding_digest"],
                "status": record["status"],
            }
        )
    if set(refs) != evidence_ids or counts != package["status_counts"]:
        raise AssuranceIntegrationError(
            "Evidence reference or status count does not match"
        )
    if counts != package["producer_gate_judgment"]["status_counts"]:
        raise AssuranceIntegrationError("producer gate status counts do not match")
    if package["producer_inventory"] != expected_producers:
        raise AssuranceIntegrationError("producer inventory does not match Evidence")
    required = package["required_gate_results"]
    optional = package["optional_gate_results"]
    if (
        required != package["producer_gate_judgment"]["required_gate_results"]
        or optional != package["producer_gate_judgment"]["optional_gate_results"]
    ):
        raise AssuranceIntegrationError("gate result surfaces do not match")
    evidence_status_by_tool = {
        record["configuration"]["tool_role_id"]: record["status"]
        for record in package["evidence_records"]
    }
    expected_required = []
    expected_optional = []
    for tool in inventory["tools"]:
        status = evidence_status_by_tool[tool["tool_id"]]
        gate = {
            "tool_id": tool["tool_id"],
            "requirement": tool["requirement"],
            "status": status,
            "gate_state": (
                "satisfied"
                if status == "pass"
                else (
                    "blocked"
                    if tool["requirement"] == "required"
                    else "visible-nonblocking"
                )
            ),
            "limitation": next(
                record["limitations"][0]
                for record in package["evidence_records"]
                if record["configuration"]["tool_role_id"] == tool["tool_id"]
            ),
        }
        (
            expected_required
            if tool["requirement"] == "required"
            else expected_optional
        ).append(gate)
    if required != expected_required or optional != expected_optional:
        raise AssuranceIntegrationError("gate results do not match Evidence and policy")
    expected_producer_gate = _producer_gate_judgment(required, optional, counts)
    if package["producer_gate_judgment"] != expected_producer_gate:
        raise AssuranceIntegrationError("producer gate judgment does not match")
    native_manifest, recomputed_projection = (
        recompute_native_projection_from_assurance_package(root, package, profile)
    )
    expected_ae_framework = {
        **expected_ae_framework_static,
        "native_input_manifest_digest": domain_digest(
            NATIVE_INPUT_MANIFEST_DOMAIN, native_manifest
        ),
        "native_projection_digest": domain_digest(
            NATIVE_PROJECTION_DOMAIN, recomputed_projection
        ),
    }
    if package["native_ae_summary_projection"] != recomputed_projection:
        raise AssuranceIntegrationError(
            "native ae projection does not match bound Evidence"
        )
    if package["ae_framework"] != expected_ae_framework:
        raise AssuranceIntegrationError(
            "recomputed ae-framework binding does not match"
        )
    expected_native = derive_native_judgment(recomputed_projection, profile)
    if package["native_ae_judgment"] != expected_native:
        raise AssuranceIntegrationError("native ae judgment does not match policy")
    expected_automated = _combined_automated_judgment(
        expected_producer_gate, expected_native
    )
    if package["automated_judgment"] != expected_automated:
        raise AssuranceIntegrationError("combined automated judgment does not match")
    content_material = copy.deepcopy(package)
    for field in (
        "human_approval",
        "assurance_content_digest",
        "report_digests",
        "package_digest",
    ):
        content_material.pop(field, None)
    if package["assurance_content_digest"] != domain_digest(
        ASSURANCE_CONTENT_DOMAIN, content_material
    ):
        raise AssuranceIntegrationError("Assurance content digest does not match")
    approval = package["human_approval"]
    if (
        approval["bound_assurance_content_digest"]
        != package["assurance_content_digest"]
    ):
        raise AssuranceIntegrationError("human approval subject does not match")
    validate_judgment_approval_boundary(
        package["automated_judgment"]["state"], approval["state"]
    )
    expected_approval = {
        "schema_version": "0.1",
        "state": (
            "not-applicable-test-only"
            if package["execution_mode"] == "fixture-test"
            else "required-not-provided"
        ),
        "reviewer_role": (
            "synthetic-reviewer"
            if package["execution_mode"] == "fixture-test"
            else None
        ),
        "reviewer_identity_verified": False,
        "bound_assurance_content_digest": package["assurance_content_digest"],
        "boundary_artifact_generated_by_automation": True,
        "approval_decision_generated_by_automation": False,
        "approval_decision_present": False,
        "limitations": [
            "No real reviewer identity or authority is asserted.",
            "Automation and ae-framework cannot create human approval.",
        ],
    }
    if approval != expected_approval:
        raise AssuranceIntegrationError("human approval boundary does not match mode")
    report_material = copy.deepcopy(package)
    report_material.pop("report_digests", None)
    report_material.pop("package_digest", None)
    if package["report_digests"] != {
        "json_model_digest": domain_digest(JSON_REPORT_DOMAIN, report_material),
        "markdown_model_digest": domain_digest(MARKDOWN_REPORT_DOMAIN, report_material),
    }:
        raise AssuranceIntegrationError("report model digests do not match")
    package_material = copy.deepcopy(package)
    package_material.pop("package_digest", None)
    if package["package_digest"] != domain_digest(
        ASSURANCE_PACKAGE_DOMAIN, package_material
    ):
        raise AssuranceIntegrationError("Assurance package digest does not match")
    if package["lifecycle_boundary"] != {
        "maximum_lifecycle": "validated",
        "public_export_eligible": False,
        "publication_approval": "not-created",
        "public_export_invoked": False,
    }:
        raise AssuranceIntegrationError("public export boundary does not match")


def validate_repository(root: Path) -> None:
    schemas = load_schemas(root)
    for schema in schemas.values():
        # check_schema already runs in load_schema; build the complete registry too.
        build_schema_registry(schemas.values())
    load_authority(root)
    native_profile = read_strict_json(
        resolve_regular_file(root, "profiles/private-match-ae-native-profile.v0.1.json")
    )
    native_schema = load_schema(
        root, "vendor/ae-framework/schema/assurance-profile.schema.json"
    )
    validate_schema_instance(native_profile, native_schema)
    catalog = read_strict_json(resolve_regular_file(root, FIXTURE_CATALOG_PATH))
    if not isinstance(catalog, dict):
        raise AssuranceIntegrationError("fixture catalog is invalid")
    validate_schema_instance(
        catalog,
        schemas["catalog"],
        registry=build_schema_registry(schemas.values()),
    )
    verify_fixture_catalog(catalog)
    expected_paths = {FIXTURE_CATALOG_PATH}
    fixture_root = root / FIXTURE_ROOT
    for fixture in catalog["fixtures"]:
        bindings = (
            (fixture["input_path"], fixture["input_digest"]),
            (fixture["expected_json_path"], fixture["expected_json_digest"]),
            (fixture["expected_markdown_path"], fixture["expected_markdown_digest"]),
            (
                fixture["expected_output_set_path"],
                fixture["expected_output_set_digest"],
            ),
        )
        for relative, digest in bindings:
            repository_relative = f"{FIXTURE_ROOT.as_posix()}/{relative}"
            expected_paths.add(repository_relative)
            path = resolve_regular_file(root, repository_relative, max_bytes=2_097_152)
            if file_digest(path.read_bytes()) != digest:
                raise AssuranceIntegrationError("fixture file digest does not match")
        package = read_strict_json(
            resolve_regular_file(fixture_root, fixture["expected_json_path"]),
            max_bytes=2_097_152,
        )
        if not isinstance(package, dict):
            raise AssuranceIntegrationError("expected fixture package is invalid")
        validate_package(root, package)
        if (
            package["status_counts"] != fixture["expected_status_counts"]
            or package["automated_judgment"]["state"]
            != fixture["expected_automated_judgment"]
            or package["human_approval"]["state"]
            != fixture["expected_human_approval_state"]
        ):
            raise AssuranceIntegrationError("fixture expected judgment does not match")
        markdown = resolve_regular_file(
            fixture_root, fixture["expected_markdown_path"]
        ).read_text(encoding="utf-8")
        if markdown != render_markdown(package):
            raise AssuranceIntegrationError(
                "expected Markdown is not generated from JSON"
            )
        output_set_path = resolve_regular_file(
            fixture_root, fixture["expected_output_set_path"]
        )
        validate_output_directory(root, output_set_path.parent)
    actual_paths: set[str] = set()
    for path in fixture_root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise AssuranceIntegrationError("fixture tree contains a symlink")
        if path.is_file():
            actual_paths.add(relative)
    if actual_paths != expected_paths:
        raise AssuranceIntegrationError("fixture tree path set does not match")
    implementation = read_strict_json(
        resolve_regular_file(root, MANIFEST_PATH.as_posix())
    )
    verify_manifest(implementation, root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--package", type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.package:
        raw = strict_loads(args.package.read_bytes(), max_bytes=2_097_152)
        if not isinstance(raw, dict):
            raise AssuranceIntegrationError("package must be an object")
        validate_package(root, raw)
    else:
        validate_repository(root)
    print("ae Assurance validation completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
