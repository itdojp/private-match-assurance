#!/usr/bin/env python3
"""Invoke the exact pinned ae-framework surface and build an Assurance package."""

from __future__ import annotations

import copy
import datetime as dt
import os
from pathlib import Path
import re
import selectors
import shutil
import subprocess
import time
from typing import Any

try:
    from ae_assurance_common import (
        AssuranceIntegrationError,
        STATUS_VALUES,
        build_schema_registry,
        canonical_json_bytes,
        load_schema,
        read_strict_json,
        validate_schema_instance,
    )
    from ae_assurance_implementation import adapter_source_digest
    from ae_assurance_policy import (
        ASSURANCE_CONTENT_DOMAIN,
        ASSURANCE_PACKAGE_DOMAIN,
        EVIDENCE_RECORD_DOMAIN,
        JSON_REPORT_DOMAIN,
        MARKDOWN_REPORT_DOMAIN,
        NATIVE_PROFILE_PATH,
        NATIVE_PROJECTION_DOMAIN,
        load_authority,
        load_schemas,
        verify_producer_package,
    )
    from canonical_json import domain_digest
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import (
        AssuranceIntegrationError,
        STATUS_VALUES,
        build_schema_registry,
        canonical_json_bytes,
        load_schema,
        read_strict_json,
        validate_schema_instance,
    )
    from scripts.ae_assurance_implementation import adapter_source_digest
    from scripts.ae_assurance_policy import (
        ASSURANCE_CONTENT_DOMAIN,
        ASSURANCE_PACKAGE_DOMAIN,
        EVIDENCE_RECORD_DOMAIN,
        JSON_REPORT_DOMAIN,
        MARKDOWN_REPORT_DOMAIN,
        NATIVE_PROFILE_PATH,
        NATIVE_PROJECTION_DOMAIN,
        load_authority,
        load_schemas,
        verify_producer_package,
    )
    from scripts.canonical_json import domain_digest


AE_ROOT = Path("vendor/ae-framework")
AE_ENTRYPOINT = "scripts/assurance/aggregate-lanes.mjs"
NODE_VERSION = "v22.22.2"
PRIVATE_FIELD_TOKENS = {
    "raw_private_input",
    "raw_input",
    "participant_identity",
    "matching_element",
    "matching_elements",
    "exact_count",
    "plaintext_result",
    "private_key",
    "secret",
    "credential",
    "internal_hostname",
    "disclosure_payload",
    "product_source_code",
    "product_log",
}
PRIVATE_TEXT_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?:^|[\s'\"])/(?:home|Users|root|tmp)/"),
    re.compile(r"[A-Za-z]:\\"),
    re.compile(r"\b(?:localhost|[A-Za-z0-9-]+\.internal)\b", re.IGNORECASE),
    re.compile(r"\bcustomer(?:[_ -]?(?:id|identifier))?\s*[:=]\s*\S+", re.IGNORECASE),
    re.compile(r"\b(?:password|credential|secret|token)\s*[:=]\s*\S+", re.IGNORECASE),
)
PROHIBITED_CLAIM_PATTERNS = (
    re.compile(
        r"\bae-framework\b.{0,80}\b(?:proves?|certif(?:y|ies|ied|ication))\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:proves?|certif(?:y|ies|ied|ication))\b.{0,80}\bae-framework\b",
        re.IGNORECASE,
    ),
)
TYPE_TO_EVIDENCE = {
    "ci": "test",
    "test-runner": "conformance",
    "formal-tool": "proof-check",
    "security-tool": "security-scan",
    "human-review": "review",
}
TYPE_TO_NATIVE = {
    "ci": ("runtime", "runtime-control", "runtime-derived"),
    "test-runner": ("behavior", "integration", "source-derived"),
    "formal-tool": ("model", "model-check", "model-derived"),
    "security-tool": ("adversarial", "fuzz", "source-derived"),
    "human-review": ("spec", "schema", "manual"),
}


def _scan_private(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in PRIVATE_FIELD_TOKENS:
                raise AssuranceIntegrationError(
                    "producer package contains a private field"
                )
            _scan_private(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _scan_private(item, f"{path}[{index}]")
    elif isinstance(value, str):
        if any(pattern.search(value) for pattern in PRIVATE_TEXT_PATTERNS):
            raise AssuranceIntegrationError("producer package contains private text")
        if any(pattern.search(value) for pattern in PROHIBITED_CLAIM_PATTERNS):
            raise AssuranceIntegrationError(
                "producer package contains a prohibited claim"
            )


def _parse_time(value: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AssuranceIntegrationError("producer timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise AssuranceIntegrationError("producer timestamp is not canonical UTC")
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise AssuranceIntegrationError("producer timestamp is not canonical UTC")
    return parsed


def validate_producer_package(
    root: Path,
    package: dict[str, Any],
    inventory: dict[str, Any],
    profile: dict[str, Any],
) -> None:
    schemas = load_schemas(root)
    validate_schema_instance(
        package,
        schemas["producer"],
        registry=build_schema_registry(schemas.values()),
    )
    verify_producer_package(package)
    _scan_private(package)
    if package["mode"] == "fixture-test" and package["artifact_status"] != "test-only":
        raise AssuranceIntegrationError("fixture mode artifact status does not match")
    if package["mode"] == "private-candidate" and any(
        record["test_only"] is True for record in package["records"]
    ):
        raise AssuranceIntegrationError(
            "test-only Evidence cannot become a private candidate"
        )
    tool_by_id = {tool["tool_id"]: tool for tool in inventory["tools"]}
    records = {record["tool_id"]: record for record in package["records"]}
    if set(records) != set(tool_by_id):
        raise AssuranceIntegrationError(
            "producer records do not match the exact tool inventory"
        )
    for tool_id, tool in tool_by_id.items():
        record = records[tool_id]
        if package["mode"] == "fixture-test" and not record["producer_id"].startswith(
            "synthetic-"
        ):
            raise AssuranceIntegrationError(
                "fixture producer identity is not synthetic"
            )
        if (
            record["producer_type"] != tool["producer_type"]
            or record["tool_version"] != tool["version"]
            or record["tool_implementation_digest"] != tool["implementation_digest"]
        ):
            raise AssuranceIntegrationError("producer tool binding does not match")
        mapping = next(
            (
                item
                for item in tool["status_mappings"]
                if item["raw_producer_status"] == record["status"]
            ),
            None,
        )
        if mapping is None or mapping["normalized_evidence_status"] != record["status"]:
            raise AssuranceIntegrationError("producer status mapping is unavailable")
        if mapping["required_limitation"] not in record["limitations"]:
            raise AssuranceIntegrationError("producer status limitation is missing")
        if _parse_time(record["completed_at"]) < _parse_time(record["started_at"]):
            raise AssuranceIntegrationError("producer timestamps are not ordered")
    if profile["accepted_producer_types"] != [
        "ci",
        "formal-tool",
        "test-runner",
        "security-tool",
        "human-review",
    ]:
        raise AssuranceIntegrationError("producer type profile is unavailable")


def _evidence_record(
    record: dict[str, Any], package_digest: str, *, required: bool
) -> dict[str, Any]:
    status = record["status"]
    ran = status not in {"skip", "unsupported"}
    reason = None if ran else record["limitations"][0]
    configuration: dict[str, Any] = {
        "ae_producer_type": record["producer_type"],
        "ae_producer_version": record["producer_version"],
        "protocol_case_digest": record["protocol_case_digest"],
        "protocol_input_digest": record["protocol_input_digest"],
        "test_only": record["test_only"],
        "public_export_eligibility": False,
    }
    evidence_type = TYPE_TO_EVIDENCE[record["producer_type"]]
    if evidence_type == "conformance":
        configuration.update(
            {
                "protocol": {"identifier": "private-match-core", "version": "0.1"},
                "conformance_suite": {
                    "identifier": record["protocol_suite_digest"],
                    "version": "0.1",
                },
            }
        )
    return {
        "schema_version": "0.1",
        "record_type": "evidence",
        "id": record["evidence_id"],
        "type": evidence_type,
        "status": status,
        "lifecycle": "validated",
        "lifecycle_history": [
            {
                "state": "collected",
                "recorded_at": record["started_at"],
                "review_digest": None,
            },
            {
                "state": "validated",
                "recorded_at": record["completed_at"],
                "review_digest": package_digest,
            },
        ],
        "subject": {
            "type": "source-revision",
            "identifier": "synthetic-private-match-product",
            "version": "0.1",
            "digest": record["source_revision_digest"],
        },
        "input_digests": [
            record["protocol_suite_digest"],
            record["protocol_case_digest"],
            record["protocol_input_digest"],
            record["product_implementation_digest"],
            record["product_artifact_digest"],
        ],
        "output_digest": record["product_output_digest"],
        "producer": {
            "type": "human-review"
            if record["producer_type"] == "human-review"
            else "local-runner",
            "identity": record["producer_id"],
        },
        "tool": {
            "name": record["tool_id"],
            "version": record["tool_version"],
            "source": record["tool_implementation_digest"],
        },
        "started_at": record["started_at"],
        "completed_at": record["completed_at"],
        "execution": {"ran": ran, "required": required, "reason": reason},
        "configuration": configuration,
        "model_check": None,
        "summary": record["summary"],
        "private_source_metadata": None,
        "public_artifacts": [],
        "limitations": record["limitations"],
    }


def _native_manifest(package: dict[str, Any]) -> dict[str, Any]:
    entries = []
    for record in package["records"]:
        lane, kind, source_kind = TYPE_TO_NATIVE[record["producer_type"]]
        entries.append(
            {
                "lane": lane,
                "kind": kind,
                "sourceKind": source_kind,
                "origin": "private-match-producer-package",
                "status": "observed" if record["status"] == "pass" else "warning",
                "artifactPath": f"producer-package/{record['evidence_id']}",
                "detail": f"status={record['status']}",
                "claimRefs": ["supplied-evidence-contract"],
                "generatorLineage": record["tool_id"],
            }
        )
    return {"schemaVersion": "assurance-evidence-manifest/v1", "entries": entries}


def _native_projection(summary: dict[str, Any]) -> dict[str, Any]:
    claims = [
        {
            "claim_id": claim["claimId"],
            "status": claim["status"],
            "required_lanes": claim["requiredLanes"],
            "observed_lanes": claim["observedLanes"],
            "missing_lanes": claim["missingLanes"],
            "required_evidence_kinds": claim["requiredEvidenceKinds"],
            "observed_evidence_kinds": claim["observedEvidenceKinds"],
            "missing_evidence_kinds": claim["missingEvidenceKinds"],
            "warning_codes": claim["independenceWarnings"],
        }
        for claim in summary["claims"]
    ]
    return {
        "schema_version": "assurance-summary/v1-safe-projection",
        "generated_at": summary["generatedAt"],
        "summary": summary["summary"],
        "lane_coverage": summary["laneCoverage"],
        "claims": claims,
        "warning_codes": sorted({warning["code"] for warning in summary["warnings"]}),
    }


def _run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout_seconds: int,
    max_output_bytes: int,
) -> subprocess.CompletedProcess[bytes]:
    """Run a fixed command while bounding each captured output stream."""

    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if process.stdout is None or process.stderr is None:  # pragma: no cover
        process.kill()
        process.wait()
        raise AssuranceIntegrationError("pinned process pipes are unavailable")
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                process.kill()
                process.wait()
                raise subprocess.TimeoutExpired(command, timeout_seconds)
            for key, _ in selector.select(min(remaining, 0.1)):
                data = os.read(key.fd, 8192)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                buffer = buffers[key.data]
                buffer.extend(data)
                if len(buffer) > max_output_bytes:
                    process.kill()
                    process.wait()
                    raise AssuranceIntegrationError(
                        "pinned ae-framework output exceeded its bound"
                    )
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout=bytes(buffers["stdout"]),
        stderr=bytes(buffers["stderr"]),
    )


def _run_native(
    root: Path,
    producer_package: dict[str, Any],
    profile: dict[str, Any],
    staging: Path,
) -> dict[str, Any]:
    ae_root = (root / AE_ROOT).resolve()
    node_executable = shutil.which("node")
    if node_executable is None:
        raise AssuranceIntegrationError("pinned Node runtime is unavailable")
    env = {
        "PATH": str(Path(node_executable).parent),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "CI": "true",
        "GIT_COMMIT": "bba9b6846608359b87ed5393cb208e321f3ba8af",
        "GIT_BRANCH": "synthetic-fixture",
        "RUNNER_NAME": "synthetic-runner",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
    }
    node_check = _run_bounded_process(
        [node_executable, "--version"],
        cwd=root,
        env=env,
        timeout_seconds=5,
        max_output_bytes=1_024,
    )
    if (
        node_check.returncode != 0
        or node_check.stdout.decode("ascii", "strict").strip() != NODE_VERSION
    ):
        raise AssuranceIntegrationError("pinned Node runtime is unavailable")
    native_manifest = staging / "native-evidence-manifest.json"
    native_json = staging / "native-summary.json"
    native_md = staging / "native-summary.md"
    native_manifest.write_bytes(
        canonical_json_bytes(_native_manifest(producer_package))
    )
    command = [
        node_executable,
        "--permission",
        f"--allow-fs-read={ae_root}",
        f"--allow-fs-read={(root / 'node_modules').resolve()}",
        f"--allow-fs-read={(root / NATIVE_PROFILE_PATH).resolve()}",
        f"--allow-fs-read={staging.resolve()}",
        f"--allow-fs-write={staging.resolve()}",
        AE_ENTRYPOINT,
        "--assurance-profile",
        str((root / NATIVE_PROFILE_PATH).resolve()),
        "--evidence-manifest",
        str(native_manifest.resolve()),
        "--generated-at",
        producer_package["created_at"],
        "--output-json",
        str(native_json.resolve()),
        "--output-md",
        str(native_md.resolve()),
    ]
    try:
        result = _run_bounded_process(
            command,
            cwd=ae_root,
            env=env,
            timeout_seconds=profile["path_execution_contract"][
                "subprocess_timeout_seconds"
            ],
            max_output_bytes=profile["path_execution_contract"][
                "stdout_stderr_max_bytes"
            ],
        )
    except subprocess.TimeoutExpired as error:
        raise AssuranceIntegrationError(
            "pinned ae-framework invocation timed out"
        ) from error
    if result.returncode != 0:
        raise AssuranceIntegrationError("pinned ae-framework invocation failed")
    native = read_strict_json(native_json, max_bytes=2_097_152)
    if not isinstance(native, dict):
        raise AssuranceIntegrationError("native ae-framework summary is invalid")
    native_schemas = [
        load_schema(root, "vendor/ae-framework/schema/artifact-metadata.schema.json"),
        load_schema(
            root, "vendor/ae-framework/schema/formal-execution-evidence-v1.schema.json"
        ),
        load_schema(root, "vendor/ae-framework/schema/formal-summary-v1.schema.json"),
        load_schema(root, "vendor/ae-framework/schema/formal-summary-v2.schema.json"),
        load_schema(root, "vendor/ae-framework/schema/assurance-summary.schema.json"),
    ]
    validate_schema_instance(
        native,
        native_schemas[-1],
        registry=build_schema_registry(native_schemas),
    )
    projection = _native_projection(native)
    if any(pattern.search(str(projection)) for pattern in PRIVATE_TEXT_PATTERNS):
        raise AssuranceIntegrationError(
            "native safe projection contains a private value"
        )
    return projection


def _gate_results(
    package: dict[str, Any], inventory: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    records = {record["tool_id"]: record for record in package["records"]}
    required = []
    optional = []
    for tool in inventory["tools"]:
        status = records[tool["tool_id"]]["status"]
        if tool["requirement"] == "required":
            state = "satisfied" if status == "pass" else "blocked"
        else:
            state = "satisfied" if status == "pass" else "visible-nonblocking"
        result = {
            "tool_id": tool["tool_id"],
            "requirement": tool["requirement"],
            "status": status,
            "gate_state": state,
            "limitation": records[tool["tool_id"]]["limitations"][0],
        }
        (required if tool["requirement"] == "required" else optional).append(result)
    return required, optional


def build_assurance_package(
    root: Path, producer_package: dict[str, Any], staging: Path
) -> dict[str, Any]:
    pin, inventory, profile = load_authority(root)
    validate_producer_package(root, producer_package, inventory, profile)
    records_by_tool = {
        record["tool_id"]: record for record in producer_package["records"]
    }
    ordered_records = [records_by_tool[tool["tool_id"]] for tool in inventory["tools"]]
    normalized_producer_package = copy.deepcopy(producer_package)
    normalized_producer_package["records"] = ordered_records
    schemas = load_schemas(root)
    producer_digest = producer_package["package_digest"]
    tools_by_id = {tool["tool_id"]: tool for tool in inventory["tools"]}
    evidence = [
        _evidence_record(
            record,
            producer_digest,
            required=tools_by_id[record["tool_id"]]["requirement"] == "required",
        )
        for record in ordered_records
    ]
    registry = build_schema_registry(schemas.values())
    for record in evidence:
        validate_schema_instance(record, schemas["evidence"], registry=registry)
    native_projection = _run_native(root, normalized_producer_package, profile, staging)
    native_digest = domain_digest(NATIVE_PROJECTION_DOMAIN, native_projection)
    required, optional = _gate_results(normalized_producer_package, inventory)
    counts = {status: 0 for status in STATUS_VALUES}
    for record in ordered_records:
        counts[record["status"]] += 1
    automated_state = (
        "satisfied" if all(item["status"] == "pass" for item in required) else "blocked"
    )
    automated = {
        "schema_version": "0.1",
        "policy_id": "private-match-assurance-automated-policy",
        "policy_version": "0.1",
        "state": automated_state,
        "required_gate_results": required,
        "optional_gate_results": optional,
        "status_counts": counts,
        "rationale_codes": [
            "ALL-REQUIRED-PASS"
            if automated_state == "satisfied"
            else "REQUIRED-NONPASS-BLOCKS"
        ],
        "limitations": [
            "Automated judgment is limited to the supplied validated Evidence contracts.",
            "Automated satisfaction is not human approval or publication approval.",
        ],
    }
    evidence_refs = [
        {
            "evidence_id": record["id"],
            "record_digest": domain_digest(EVIDENCE_RECORD_DOMAIN, record),
            "status": record["status"],
        }
        for record in evidence
    ]
    producer_inventory = [
        {
            "evidence_id": record["evidence_id"],
            "producer_type": record["producer_type"],
            "producer_id": record["producer_id"],
            "producer_version": record["producer_version"],
            "tool_id": record["tool_id"],
            "tool_version": record["tool_version"],
            "status": record["status"],
        }
        for record in ordered_records
    ]
    external_tools = [
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
    core: dict[str, Any] = {
        "schema_version": "0.1",
        "artifact_status": producer_package["artifact_status"],
        "execution_mode": producer_package["mode"],
        "integration_profile": {
            "id": profile["profile_id"],
            "version": profile["profile_version"],
            "digest": profile["profile_digest"],
        },
        "ae_framework": {
            "repository": pin["repository"],
            "commit": pin["commit"],
            "package_name": pin["package"]["name"],
            "package_version": pin["package"]["version"],
            "source_tree_digest": pin["source_manifest"]["source_tree_digest"],
            "native_projection_digest": native_digest,
        },
        "adapter": {
            "id": "private-match-assurance/ae-framework-adapter",
            "version": "0.1",
            "implementation_digest": adapter_source_digest(root),
        },
        "input_producer_package_digest": producer_digest,
        "evidence_records": evidence,
        "evidence_record_refs": evidence_refs,
        "producer_inventory": producer_inventory,
        "external_tool_inventory": external_tools,
        "native_ae_summary_projection": native_projection,
        "automated_judgment": automated,
        "required_gate_results": required,
        "optional_gate_results": optional,
        "status_counts": counts,
        "limitations": [
            "ae-framework organizes supplied Evidence and is not an oracle of truth.",
            "This package is neither a security proof nor certification.",
            "Automated satisfaction is not human approval or publication approval.",
            "Synthetic fixtures do not establish Product or Protocol correctness.",
            "No live Product Evidence, private input, or public export is included.",
            "Native ae-framework warnings remain visible and do not rewrite producer statuses.",
        ],
        "lifecycle_boundary": {
            "maximum_lifecycle": "validated",
            "public_export_eligible": False,
            "publication_approval": "not-created",
            "public_export_invoked": False,
        },
    }
    content_digest = domain_digest(ASSURANCE_CONTENT_DOMAIN, core)
    approval = {
        "schema_version": "0.1",
        "state": "not-applicable-test-only"
        if producer_package["mode"] == "fixture-test"
        else "required-not-provided",
        "reviewer_role": "synthetic-reviewer"
        if producer_package["mode"] == "fixture-test"
        else None,
        "reviewer_identity_verified": False,
        "bound_assurance_content_digest": content_digest,
        "generated_by_automation": False,
        "limitations": [
            "No real reviewer identity or authority is asserted.",
            "Automation and ae-framework cannot create human approval.",
        ],
    }
    package = {
        **core,
        "human_approval": approval,
        "assurance_content_digest": content_digest,
    }
    report_material = copy.deepcopy(package)
    package["report_digests"] = {
        "json_semantic_digest": domain_digest(JSON_REPORT_DOMAIN, report_material),
        "markdown_semantic_digest": domain_digest(
            MARKDOWN_REPORT_DOMAIN, report_material
        ),
    }
    package["package_digest"] = domain_digest(ASSURANCE_PACKAGE_DOMAIN, package)
    validate_schema_instance(package, schemas["package"], registry=registry)
    validate_schema_instance(automated, schemas["automated"], registry=registry)
    validate_schema_instance(approval, schemas["approval"], registry=registry)
    return package
