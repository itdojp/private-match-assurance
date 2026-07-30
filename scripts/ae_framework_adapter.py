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
        DIGEST_PATTERN,
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
        CANDIDATE_TOOL_IDENTITIES,
        CANDIDATE_TOOL_LIMITATION,
        FIXTURE_TOOL_BINDINGS,
        FIXTURE_TOOL_LIMITATION,
        load_authority,
        load_schemas,
        tool_binding_digest,
        verify_producer_package,
    )
    from canonical_json import domain_digest
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import (
        AssuranceIntegrationError,
        DIGEST_PATTERN,
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
        CANDIDATE_TOOL_IDENTITIES,
        CANDIDATE_TOOL_LIMITATION,
        FIXTURE_TOOL_BINDINGS,
        FIXTURE_TOOL_LIMITATION,
        load_authority,
        load_schemas,
        tool_binding_digest,
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
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    re.compile(r"(?:\+\d{8,15}|\b\d{2,4}[- )]\d{2,4}[- ]\d{3,4}\b)"),
    re.compile(
        r"\b(?:tenant|account|organization|org|user)(?:[_ -]?(?:id|identifier))?\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:github\.com|gitlab\.com)/[^/\s]+/[^/\s]+", re.IGNORECASE),
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
PRODUCER_IDS = {
    "fixture-test": {
        producer_type: f"synthetic-{producer_type}-producer"
        for producer_type in TYPE_TO_EVIDENCE
    },
    "private-candidate": {
        producer_type: f"private-match-product-{producer_type}"
        for producer_type in TYPE_TO_EVIDENCE
    },
}
MODE_LIMITATION = {
    "fixture-test": "Public synthetic fixture only; no private Product execution is represented.",
    "private-candidate": "Private candidate metadata only; no raw Product data is represented.",
}
MODE_PACKAGE_LIMITATIONS = {
    "fixture-test": [
        "All identifiers and digests are public synthetic fixture values.",
        "The package is not eligible for public export or live approval.",
    ],
    "private-candidate": [
        "All identifiers are closed role IDs and digests bind the private candidate source revision.",
        "The package is retained privately and is not eligible for public export or live approval.",
    ],
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
) -> list[dict[str, Any]]:
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
    expected_subject = {
        "type": "source-revision",
        "identifier": (
            "synthetic-private-match-product"
            if package["mode"] == "fixture-test"
            else "private-match-product"
        ),
        "version": "0.1",
        "digest": package["source_revision_digest"],
    }
    if package["subject"] != expected_subject:
        raise AssuranceIntegrationError("producer subject provenance does not match")
    expected_package_id = (
        None
        if package["mode"] == "fixture-test"
        else "PMAE-PRODUCER-PRIVATE-CANDIDATE-V0-1"
    )
    if expected_package_id is not None and package["package_id"] != expected_package_id:
        raise AssuranceIntegrationError(
            "private candidate package identity is not closed"
        )
    if package["limitations"] != MODE_PACKAGE_LIMITATIONS[package["mode"]]:
        raise AssuranceIntegrationError("producer package limitations are not closed")
    tool_by_id = {tool["tool_id"]: tool for tool in inventory["tools"]}
    bindings = validate_tool_bindings(
        root, package["mode"], package["tool_bindings"], inventory
    )
    binding_by_id = {binding["tool_role_id"]: binding for binding in bindings}
    records = {record["tool_id"]: record for record in package["records"]}
    if set(records) != set(tool_by_id):
        raise AssuranceIntegrationError(
            "producer records do not match the exact tool inventory"
        )
    for tool_id, tool in tool_by_id.items():
        record = records[tool_id]
        binding = binding_by_id[tool_id]
        if (
            record["producer_id"]
            != PRODUCER_IDS[package["mode"]][record["producer_type"]]
        ):
            raise AssuranceIntegrationError("producer identity is not a closed role ID")
        if (
            record["producer_type"] != tool["producer_type"]
            or record["tool_identity"] != binding["identity"]
            or record["tool_version"] != binding["version"]
            or record["tool_implementation_digest"] != binding["implementation_digest"]
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
        if record["limitations"] != [
            mapping["required_limitation"],
            MODE_LIMITATION[package["mode"]],
        ]:
            raise AssuranceIntegrationError("producer limitations are not closed")
        expected_summary = (
            "Synthetic" if package["mode"] == "fixture-test" else "Private candidate"
        ) + f" {record['producer_type']} status record."
        if record["summary"] != expected_summary:
            raise AssuranceIntegrationError("producer summary is not a closed value")
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
    return bindings


def validate_tool_bindings(
    root: Path,
    mode: str,
    bindings: list[dict[str, Any]],
    inventory: dict[str, Any],
) -> list[dict[str, Any]]:
    """Validate one exact mode-specific execution binding per policy role."""

    schemas = load_schemas(root)
    registry = build_schema_registry(schemas.values())
    role_by_id = {role["tool_id"]: role for role in inventory["tools"]}
    binding_by_id: dict[str, dict[str, Any]] = {}
    identities: set[str] = set()
    for binding in bindings:
        validate_schema_instance(binding, schemas["tool_binding"], registry=registry)
        role_id = binding["tool_role_id"]
        if role_id in binding_by_id or binding["identity"] in identities:
            raise AssuranceIntegrationError(
                "tool binding role or identity is duplicate"
            )
        binding_by_id[role_id] = binding
        identities.add(binding["identity"])
    if set(binding_by_id) != set(role_by_id):
        raise AssuranceIntegrationError("tool bindings do not match policy roles")
    fixture_digests = {item[1] for item in FIXTURE_TOOL_BINDINGS.values()}
    ordered: list[dict[str, Any]] = []
    for role in inventory["tools"]:
        role_id = role["tool_id"]
        binding = binding_by_id[role_id]
        if (
            binding["mode"] != mode
            or binding["producer_type"] != role["producer_type"]
            or binding["input_contract"] != role["input_contract"]
            or binding["output_contract"] != role["output_contract"]
            or binding["binding_digest"] != tool_binding_digest(binding)
        ):
            raise AssuranceIntegrationError("tool binding does not match policy role")
        if mode == "fixture-test":
            fixture_identity, fixture_digest = FIXTURE_TOOL_BINDINGS[role_id]
            if (
                binding["identity"] != fixture_identity
                or binding["version"] != "1.0.0"
                or binding["implementation_digest"] != fixture_digest
                or binding["limitations"] != [FIXTURE_TOOL_LIMITATION]
            ):
                raise AssuranceIntegrationError(
                    "fixture tool binding does not match reviewed authority"
                )
        elif mode == "private-candidate":
            if (
                binding["identity"] != CANDIDATE_TOOL_IDENTITIES[role_id]
                or binding["implementation_digest"] in fixture_digests
                or binding["limitations"] != [CANDIDATE_TOOL_LIMITATION]
            ):
                raise AssuranceIntegrationError(
                    "private-candidate tool binding is synthetic or unreviewed"
                )
        else:  # Schema validation normally catches this first.
            raise AssuranceIntegrationError("tool binding mode is unavailable")
        ordered.append(binding)
    return ordered


def _evidence_record(
    record: dict[str, Any],
    binding: dict[str, Any],
    package_digest: str,
    subject: dict[str, Any],
    *,
    required: bool,
) -> dict[str, Any]:
    status = record["status"]
    ran = status not in {"skip", "unsupported"}
    reason = None if ran else record["limitations"][0]
    configuration: dict[str, Any] = {
        "ae_producer_type": record["producer_type"],
        "ae_producer_version": record["producer_version"],
        "tool_role_id": binding["tool_role_id"],
        "tool_binding_digest": binding["binding_digest"],
        "tool_input_contract": binding["input_contract"],
        "tool_output_contract": binding["output_contract"],
        "protocol_case_digest": record["protocol_case_digest"],
        "protocol_input_digest": record["protocol_input_digest"],
        "test_only": record["test_only"],
        "retention_classification": record["retention_classification"],
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
        "subject": copy.deepcopy(subject),
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
            "name": binding["identity"],
            "version": binding["version"],
            "source": binding["implementation_digest"],
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


def native_generator_lineage(binding: dict[str, Any]) -> str:
    """Derive native implementation lineage from one validated tool binding."""

    implementation_digest = binding.get("implementation_digest")
    if (
        not isinstance(implementation_digest, str)
        or DIGEST_PATTERN.fullmatch(implementation_digest) is None
    ):
        raise AssuranceIntegrationError(
            "native generator lineage implementation digest is invalid"
        )
    return f"implementation/{implementation_digest}"


def _native_manifest(package: dict[str, Any]) -> dict[str, Any]:
    bindings = {
        binding["tool_role_id"]: binding for binding in package["tool_bindings"]
    }
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
                "generatorLineage": native_generator_lineage(
                    bindings[record["tool_id"]]
                ),
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


def _producer_gate_judgment(
    required: list[dict[str, Any]],
    optional: list[dict[str, Any]],
    counts: dict[str, int],
) -> dict[str, Any]:
    state = (
        "satisfied" if all(item["status"] == "pass" for item in required) else "blocked"
    )
    return {
        "schema_version": "0.1",
        "state": state,
        "required_gate_results": required,
        "optional_gate_results": optional,
        "status_counts": counts,
        "rationale_codes": [
            "ALL-REQUIRED-PASS" if state == "satisfied" else "REQUIRED-NONPASS-BLOCKS"
        ],
        "limitations": [
            "Producer-gate judgment is limited to supplied validated Evidence statuses.",
            "Optional non-pass statuses remain visible and are not promoted.",
        ],
    }


def derive_native_judgment(
    native_projection: dict[str, Any], profile: dict[str, Any]
) -> dict[str, Any]:
    """Evaluate the native summary against the closed reviewed warning policy."""

    policy = profile["native_ae_judgment_policy"]
    blocking = set(policy["blocking_warning_codes"])
    visible = set(policy["visible_nonblocking_warning_codes"])
    observed_codes = set(native_projection["warning_codes"])
    for claim in native_projection["claims"]:
        observed_codes.update(claim["warning_codes"])
    unknown = observed_codes - blocking - visible
    if unknown:
        raise AssuranceIntegrationError("native ae warning code is not reviewed")
    has_missing_required = any(
        claim["missing_lanes"] or claim["missing_evidence_kinds"]
        for claim in native_projection["claims"]
    )
    if has_missing_required or observed_codes & blocking:
        state = "blocked"
        treatment = "blocking"
        rationale = ["NATIVE-REQUIRED-SURFACE-BLOCKED"]
    elif observed_codes:
        state = "warning"
        treatment = "visible-nonblocking"
        rationale = ["NATIVE-WARNING-REVIEWED-NONBLOCKING"]
    elif all(claim["status"] == "satisfied" for claim in native_projection["claims"]):
        state = "satisfied"
        treatment = "not-applicable"
        rationale = ["NATIVE-CLAIMS-SATISFIED"]
    else:
        raise AssuranceIntegrationError("native ae judgment is not determinable")
    return {
        "schema_version": "0.1",
        "state": state,
        "claim_results": copy.deepcopy(native_projection["claims"]),
        "warning_codes": sorted(observed_codes),
        "policy_treatment": treatment,
        "rationale_codes": rationale,
        "limitations": [
            "Native ae judgment organizes supplied lanes and does not prove correctness.",
            "Unknown native warnings fail closed instead of becoming satisfied.",
        ],
    }


def _combined_automated_judgment(
    producer_gate: dict[str, Any], native_judgment: dict[str, Any]
) -> dict[str, Any]:
    if producer_gate["state"] == "blocked" or native_judgment["state"] == "blocked":
        state = "blocked"
        rationale = "PRODUCER-OR-NATIVE-BLOCKED"
    elif native_judgment["state"] == "warning":
        state = "satisfied-with-warnings"
        rationale = "REVIEWED-NATIVE-WARNING-VISIBLE"
    elif native_judgment["state"] == "satisfied":
        state = "satisfied"
        rationale = "PRODUCER-AND-NATIVE-SATISFIED"
    else:
        state = "not-evaluated"
        rationale = "NATIVE-JUDGMENT-NOT-EVALUATED"
    return {
        "schema_version": "0.1",
        "policy_id": "private-match-assurance-automated-policy",
        "policy_version": "0.1",
        "state": state,
        "producer_gate_state": producer_gate["state"],
        "native_ae_state": native_judgment["state"],
        "rationale_codes": [rationale],
        "limitations": [
            "Combined automated judgment is limited to the two declared judgment surfaces.",
            "Automated satisfaction is not human approval or publication approval.",
        ],
    }


def build_assurance_package(
    root: Path, producer_package: dict[str, Any], staging: Path
) -> dict[str, Any]:
    pin, inventory, profile = load_authority(root)
    bindings = validate_producer_package(root, producer_package, inventory, profile)
    bindings_by_role = {binding["tool_role_id"]: binding for binding in bindings}
    records_by_tool = {
        record["tool_id"]: record for record in producer_package["records"]
    }
    ordered_records = [records_by_tool[tool["tool_id"]] for tool in inventory["tools"]]
    normalized_producer_package = copy.deepcopy(producer_package)
    normalized_producer_package["records"] = ordered_records
    normalized_producer_package["tool_bindings"] = bindings
    schemas = load_schemas(root)
    producer_digest = producer_package["package_digest"]
    tools_by_id = {tool["tool_id"]: tool for tool in inventory["tools"]}
    evidence = [
        _evidence_record(
            record,
            bindings_by_role[record["tool_id"]],
            producer_digest,
            normalized_producer_package["subject"],
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
    producer_gate = _producer_gate_judgment(required, optional, counts)
    native_judgment = derive_native_judgment(native_projection, profile)
    automated = _combined_automated_judgment(producer_gate, native_judgment)
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
            "tool_role_id": record["tool_id"],
            "tool_id": bindings_by_role[record["tool_id"]]["identity"],
            "tool_version": bindings_by_role[record["tool_id"]]["version"],
            "tool_implementation_digest": bindings_by_role[record["tool_id"]][
                "implementation_digest"
            ],
            "tool_binding_digest": bindings_by_role[record["tool_id"]][
                "binding_digest"
            ],
            "status": record["status"],
        }
        for record in ordered_records
    ]
    external_tools = [
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
        for role, binding in zip(inventory["tools"], bindings, strict=True)
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
        "native_ae_judgment": native_judgment,
        "producer_gate_judgment": producer_gate,
        "automated_judgment": automated,
        "required_gate_results": required,
        "optional_gate_results": optional,
        "status_counts": counts,
        "limitations": [
            "ae-framework organizes supplied Evidence and is not an oracle of truth.",
            "This package is neither a security proof nor certification.",
            "Automated satisfaction is not human approval or publication approval.",
            (
                "Synthetic fixtures do not establish Product or Protocol correctness."
                if producer_package["mode"] == "fixture-test"
                else "Private-candidate digest metadata does not establish Product or Protocol correctness."
            ),
            (
                "No live Product Evidence, private input, or public export is included."
                if producer_package["mode"] == "fixture-test"
                else "No raw Product Evidence, private input, or public export is included."
            ),
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
        "boundary_artifact_generated_by_automation": True,
        "approval_decision_generated_by_automation": False,
        "approval_decision_present": False,
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
        "json_model_digest": domain_digest(JSON_REPORT_DOMAIN, report_material),
        "markdown_model_digest": domain_digest(MARKDOWN_REPORT_DOMAIN, report_material),
    }
    package["package_digest"] = domain_digest(ASSURANCE_PACKAGE_DOMAIN, package)
    validate_schema_instance(package, schemas["package"], registry=registry)
    validate_schema_instance(automated, schemas["automated"], registry=registry)
    validate_schema_instance(producer_gate, schemas["producer_gate"], registry=registry)
    validate_schema_instance(
        native_judgment, schemas["native_judgment"], registry=registry
    )
    validate_schema_instance(approval, schemas["approval"], registry=registry)
    return package
