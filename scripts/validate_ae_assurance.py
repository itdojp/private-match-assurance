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
    from ae_assurance_policy import (
        ASSURANCE_CONTENT_DOMAIN,
        ASSURANCE_PACKAGE_DOMAIN,
        EVIDENCE_RECORD_DOMAIN,
        FIXTURE_CATALOG_PATH,
        JSON_REPORT_DOMAIN,
        MARKDOWN_REPORT_DOMAIN,
        NATIVE_PROJECTION_DOMAIN,
        load_authority,
        load_schemas,
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
    from scripts.ae_assurance_policy import (
        ASSURANCE_CONTENT_DOMAIN,
        ASSURANCE_PACKAGE_DOMAIN,
        EVIDENCE_RECORD_DOMAIN,
        FIXTURE_CATALOG_PATH,
        JSON_REPORT_DOMAIN,
        MARKDOWN_REPORT_DOMAIN,
        NATIVE_PROJECTION_DOMAIN,
        load_authority,
        load_schemas,
        verify_fixture_catalog,
    )
    from scripts.canonical_json import domain_digest, file_digest, strict_loads
    from scripts.render_ae_assurance_report import render_markdown


FIXTURE_ROOT = Path("tests/fixtures/ae-framework")


def validate_judgment_approval_boundary(
    automated_state: str, approval_state: str
) -> None:
    if automated_state == "blocked" and approval_state == "approved":
        raise AssuranceIntegrationError("human approval cannot override a blocked gate")


def validate_package(root: Path, package: dict[str, Any]) -> None:
    pin, inventory, profile = load_authority(root)
    schemas = load_schemas(root)
    registry = build_schema_registry(schemas.values())
    validate_schema_instance(package, schemas["package"], registry=registry)
    for evidence in package["evidence_records"]:
        validate_schema_instance(evidence, schemas["evidence"], registry=registry)
    validate_schema_instance(
        package["automated_judgment"], schemas["automated"], registry=registry
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
    expected_ae_framework = {
        "repository": pin["repository"],
        "commit": pin["commit"],
        "package_name": pin["package"]["name"],
        "package_version": pin["package"]["version"],
        "source_tree_digest": pin["source_manifest"]["source_tree_digest"],
        "native_projection_digest": domain_digest(
            NATIVE_PROJECTION_DOMAIN, package["native_ae_summary_projection"]
        ),
    }
    if package["ae_framework"] != expected_ae_framework:
        raise AssuranceIntegrationError("ae-framework package binding does not match")
    if package["adapter"] != {
        "id": "private-match-assurance/ae-framework-adapter",
        "version": "0.1",
        "implementation_digest": adapter_source_digest(root),
    }:
        raise AssuranceIntegrationError("adapter implementation binding does not match")

    expected_external_tools = [
        {
            "tool_id": tool["tool_id"],
            "producer_type": tool["producer_type"],
            "requirement": tool["requirement"],
            "identity": tool["identity"],
            "version": tool["version"],
            "implementation_digest": tool["implementation_digest"],
        }
        for tool in inventory["tools"]
    ]
    if package["external_tool_inventory"] != expected_external_tools:
        raise AssuranceIntegrationError("external tool inventory does not match")

    refs = {item["evidence_id"]: item for item in package["evidence_record_refs"]}
    evidence_ids: set[str] = set()
    counts = {status: 0 for status in STATUS_VALUES}
    tools_by_id = {tool["tool_id"]: tool for tool in inventory["tools"]}
    expected_producers = []
    expected_order = [tool["tool_id"] for tool in inventory["tools"]]
    observed_order = [record["tool"]["name"] for record in package["evidence_records"]]
    if observed_order != expected_order:
        raise AssuranceIntegrationError("Evidence tool order does not match inventory")
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
        tool_id = record["tool"]["name"]
        tool = tools_by_id.get(tool_id)
        configuration = record.get("configuration", {})
        producer_type = configuration.get("ae_producer_type")
        producer_version = configuration.get("ae_producer_version")
        if (
            tool is None
            or producer_type != tool["producer_type"]
            or record["tool"]["version"] != tool["version"]
            or record["tool"]["source"] != tool["implementation_digest"]
            or record["execution"]["required"] != (tool["requirement"] == "required")
            or record["execution"]["ran"]
            != (record["status"] not in {"skip", "unsupported"})
            or not isinstance(producer_version, str)
        ):
            raise AssuranceIntegrationError("Evidence tool binding does not match")
        expected_producers.append(
            {
                "evidence_id": record["id"],
                "producer_type": producer_type,
                "producer_id": record["producer"]["identity"],
                "producer_version": producer_version,
                "tool_id": tool_id,
                "tool_version": record["tool"]["version"],
                "status": record["status"],
            }
        )
    if set(refs) != evidence_ids or counts != package["status_counts"]:
        raise AssuranceIntegrationError(
            "Evidence reference or status count does not match"
        )
    if counts != package["automated_judgment"]["status_counts"]:
        raise AssuranceIntegrationError("automated judgment status counts do not match")
    if package["producer_inventory"] != expected_producers:
        raise AssuranceIntegrationError("producer inventory does not match Evidence")
    required = package["required_gate_results"]
    optional = package["optional_gate_results"]
    if (
        required != package["automated_judgment"]["required_gate_results"]
        or optional != package["automated_judgment"]["optional_gate_results"]
    ):
        raise AssuranceIntegrationError("gate result surfaces do not match")
    expected_state = (
        "satisfied" if all(item["status"] == "pass" for item in required) else "blocked"
    )
    if package["automated_judgment"]["state"] != expected_state:
        raise AssuranceIntegrationError(
            "automated judgment does not match required gates"
        )
    evidence_status_by_tool = {
        record["tool"]["name"]: record["status"]
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
                if record["tool"]["name"] == tool["tool_id"]
            ),
        }
        (
            expected_required
            if tool["requirement"] == "required"
            else expected_optional
        ).append(gate)
    if required != expected_required or optional != expected_optional:
        raise AssuranceIntegrationError("gate results do not match Evidence and policy")
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
    if package["execution_mode"] == "fixture-test" and (
        package["artifact_status"] != "test-only"
        or approval["state"]
        not in {
            "not-applicable-test-only",
            "required-not-provided",
        }
    ):
        raise AssuranceIntegrationError("test-only package fabricated a live approval")
    if package["execution_mode"] == "private-candidate" and any(
        record.get("configuration", {}).get("test_only") is True
        for record in package["evidence_records"]
    ):
        raise AssuranceIntegrationError(
            "test-only Evidence cannot become a live candidate"
        )
    report_material = copy.deepcopy(package)
    report_material.pop("report_digests", None)
    report_material.pop("package_digest", None)
    if package["report_digests"] != {
        "json_semantic_digest": domain_digest(JSON_REPORT_DOMAIN, report_material),
        "markdown_semantic_digest": domain_digest(
            MARKDOWN_REPORT_DOMAIN, report_material
        ),
    }:
        raise AssuranceIntegrationError("report semantic digests do not match")
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
