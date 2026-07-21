#!/usr/bin/env python3
"""Validate Private Match public assurance records."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator, FormatChecker

try:
    from canonical_json import (
        CanonicalJSONError,
        domain_digest,
        file_digest,
        strict_loads,
    )
    from exporter_manifest import (
        MANIFEST_PATH,
        ImplementationManifestError,
        manifest_file_digest,
        verify_implementation_manifest,
    )
except ImportError:  # pragma: no cover - package import during unit tests
    from scripts.canonical_json import (
        CanonicalJSONError,
        domain_digest,
        file_digest,
        strict_loads,
    )
    from scripts.exporter_manifest import (
        MANIFEST_PATH,
        ImplementationManifestError,
        manifest_file_digest,
        verify_implementation_manifest,
    )


@dataclasses.dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


SCHEMA_FILES = {
    "claim": "claim.schema.json",
    "assumption": "assumption.schema.json",
    "evidence": "evidence-item.schema.json",
    "evidence-manifest": "evidence-manifest.schema.json",
    "known-limitation": "known-limitation.schema.json",
    "assurance-notice": "correction-withdrawal-notice.schema.json",
}
EXPORT_SCHEMA_FILES = {
    "evidence-export-candidate": "evidence-export-candidate.v0.1.schema.json",
    "evidence-export-configuration": "evidence-export-configuration.v0.1.schema.json",
    "evidence-export-fixture-catalog": "evidence-export-fixture-catalog.v0.1.schema.json",
    "evidence-export-profile": "evidence-export-profile.v0.1.schema.json",
    "evidence-exporter-implementation": "evidence-exporter-implementation.v0.1.schema.json",
    "public-evidence-export": "public-evidence-export.v0.1.schema.json",
}

PROFILE_DOMAIN = "private-match-evidence-export-profile/v0.1"
EXPORTED_EVIDENCE_DOMAIN = "private-match-exported-evidence/v0.1"
BUNDLE_DOMAIN = "private-match-public-evidence-bundle/v0.1"
EXPORT_CANDIDATE_MODE = "export-candidate"
TEST_FIXTURE_MODE = "test-fixture"
REVIEW_SCOPES = {"privacy", "security-boundary", "ip", "vulnerability"}
REVIEW_STATUS_FIELDS = {
    "privacy": ("privacy", "privacy_review_marker", {"approved"}),
    "security-boundary": (
        "security_boundary",
        "security_review_marker",
        {"approved"},
    ),
    "ip": ("ip", "ip_review_marker", {"approved", "not-applicable"}),
    "vulnerability": (
        "vulnerability",
        "vulnerability_review_marker",
        {"approved", "not-applicable"},
    ),
}
EXPORTABLE_EVIDENCE_TYPES = {
    "test",
    "conformance",
    "model-check",
    "provenance",
    "review",
}
CONFIGURATION_SCHEMA_FILE = "evidence-export-configuration.v0.1.schema.json"
FIXTURE_CATALOG_PATH = "tests/fixtures/export/fixture-catalog.v0.1.json"

EXCLUDED_DIRS = {".git", ".venv", "artifacts", "__pycache__", "node_modules", "tests"}
RECORD_DIR = "assurance"
LIFECYCLE_TRANSITIONS = {
    "collected": {"validated", "withdrawn"},
    "validated": {"sanitized", "withdrawn"},
    "sanitized": {"published", "withdrawn"},
    "published": {"superseded", "withdrawn"},
    "superseded": set(),
    "withdrawn": set(),
}


class ExportArtifactError(ValueError):
    """A repository-owned export artifact failed strict local validation."""


def _iter_json(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.json"):
        if not path.is_file() or any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        yield path


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> Any:
    return strict_loads(path.read_bytes(), max_bytes=1_048_576)


def load_schemas(root: Path) -> dict[str, Draft202012Validator]:
    validators: dict[str, Draft202012Validator] = {}
    for record_type, filename in SCHEMA_FILES.items():
        schema = load_json(root / "schema" / filename)
        Draft202012Validator.check_schema(schema)
        validators[record_type] = Draft202012Validator(
            schema, format_checker=FormatChecker()
        )
    return validators


def load_evidence_schema(root: Path) -> Draft202012Validator:
    """Load only the authoritative Evidence Schema used by export validation."""

    schema = load_json(root / "schema" / SCHEMA_FILES["evidence"])
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def load_export_schemas(root: Path) -> dict[str, Draft202012Validator]:
    validators: dict[str, Draft202012Validator] = {}
    for artifact_type, filename in EXPORT_SCHEMA_FILES.items():
        schema = load_json(root / "schema" / filename)
        Draft202012Validator.check_schema(schema)
        validators[artifact_type] = Draft202012Validator(
            schema, format_checker=FormatChecker()
        )
    return validators


def load_export_fixture_catalog(root: Path) -> tuple[dict[str, Any], str]:
    """Strictly load, Schema-check, and uniquely index the fixture catalog."""

    path = root / FIXTURE_CATALOG_PATH
    try:
        raw = path.read_bytes()
        catalog = strict_loads(raw, max_bytes=1_048_576)
    except (OSError, CanonicalJSONError) as error:
        raise ExportArtifactError("fixture catalog is not strict JSON") from error
    validator = load_export_schemas(root)["evidence-export-fixture-catalog"]
    if list(validator.iter_errors(catalog)):
        raise ExportArtifactError("fixture catalog does not match its Schema")
    if not isinstance(catalog, dict):
        raise ExportArtifactError("fixture catalog must be an object")
    identifiers: set[str] = set()
    paths: set[str] = set()
    for entry in catalog["fixtures"]:
        identifier = entry["fixture_id"]
        relative_path = entry["relative_input_path"]
        if identifier in identifiers or relative_path in paths:
            raise ExportArtifactError(
                "fixture catalog identifiers and paths must be unique"
            )
        identifiers.add(identifier)
        paths.add(relative_path)
    return catalog, file_digest(raw)


def validate_public_bundle_bindings(
    bundle: Any,
    path: str,
    root: Path,
    profile: dict[str, Any],
    mode: str,
    manifest: dict[str, Any] | None,
) -> list[Finding]:
    """Cross-check public review, fixture, and visible profile bindings."""

    if not isinstance(bundle, dict):
        return []
    findings: list[Finding] = []

    profile_material = dict(profile)
    profile_material.pop("profile_digest", None)
    expected_profile = domain_digest(PROFILE_DOMAIN, profile_material)
    visible_profile = bundle.get("export_profile")
    digest_bindings = bundle.get("digest_bindings")
    if (
        profile.get("profile_digest") != expected_profile
        or not isinstance(visible_profile, dict)
        or visible_profile.get("digest") != expected_profile
        or not isinstance(digest_bindings, dict)
        or digest_bindings.get("export_profile_digest") != expected_profile
    ):
        findings.append(
            Finding(
                "error",
                "profile-digest",
                path,
                "visible, bound, and current export profile digests must match",
            )
        )

    provenance = bundle.get("review_provenance")
    requirements = bundle.get("review_requirements")
    report = bundle.get("sanitization_report")
    by_scope: dict[str, dict[str, Any]] = {}
    if isinstance(provenance, list):
        for item in provenance:
            if isinstance(item, dict) and isinstance(item.get("scope"), str):
                by_scope.setdefault(item["scope"], item)
    if not isinstance(requirements, dict) or not isinstance(report, dict):
        findings.append(
            Finding(
                "error",
                "review-status",
                path,
                "review status surfaces are incomplete",
            )
        )
    else:
        for scope, (
            requirement_field,
            report_field,
            allowed,
        ) in REVIEW_STATUS_FIELDS.items():
            item = by_scope.get(scope)
            values = (
                item.get("status") if isinstance(item, dict) else None,
                requirements.get(requirement_field),
                report.get(report_field),
            )
            if values[0] not in allowed or len(set(values)) != 1:
                findings.append(
                    Finding(
                        "error",
                        "review-status",
                        f"{path}:review_provenance.{scope}",
                        "review provenance, requirements, and report status must match",
                    )
                )

    fixture = bundle.get("fixture_provenance")
    if mode == TEST_FIXTURE_MODE:
        try:
            catalog, catalog_digest = load_export_fixture_catalog(root)
        except ExportArtifactError:
            findings.append(
                Finding(
                    "error",
                    "fixture-provenance",
                    path,
                    "the authorized fixture catalog does not validate",
                )
            )
        else:
            trust_entries = (
                [
                    entry
                    for entry in manifest.get("test_trust_artifacts", [])
                    if isinstance(entry, dict)
                    and entry.get("path") == FIXTURE_CATALOG_PATH
                ]
                if isinstance(manifest, dict)
                else []
            )
            fixture_id = (
                fixture.get("fixture_id") if isinstance(fixture, dict) else None
            )
            matches = [
                entry
                for entry in catalog["fixtures"]
                if entry.get("fixture_id") == fixture_id
            ]
            valid_entry = matches[0] if len(matches) == 1 else None
            if (
                bundle.get("artifact_status") != "test-only"
                or not isinstance(fixture, dict)
                or fixture.get("fixture_catalog_digest") != catalog_digest
                or len(trust_entries) != 1
                or trust_entries[0].get("digest") != catalog_digest
                or valid_entry is None
                or valid_entry.get("artifact_status") != "test-only"
                or valid_entry.get("candidate_digest")
                != bundle.get("export_candidate_digest")
            ):
                findings.append(
                    Finding(
                        "error",
                        "fixture-provenance",
                        path,
                        "test bundle does not bind one authorized catalog entry",
                    )
                )
    elif fixture is not None:
        findings.append(
            Finding(
                "error",
                "fixture-provenance",
                path,
                "candidate bundle must not claim synthetic fixture provenance",
            )
        )
    return findings


def validate_export_configuration(
    evidence: Any,
    path: str,
    root: Path,
    profile: dict[str, Any],
) -> list[Finding]:
    """Validate the complete configuration against its closed type contract."""

    if not isinstance(evidence, dict):
        return [
            Finding(
                "error",
                "configuration-contract",
                path,
                "Evidence record must be an object",
            )
        ]
    evidence_type = evidence.get("type")
    configuration = evidence.get("configuration")
    contracts = profile.get("configuration_contracts")
    if (
        evidence_type not in EXPORTABLE_EVIDENCE_TYPES
        or not isinstance(configuration, dict)
        or not isinstance(contracts, dict)
        or not isinstance(contracts.get(evidence_type), dict)
    ):
        return [
            Finding(
                "error",
                "configuration-contract",
                path,
                "Evidence type has no reviewed export configuration contract",
            )
        ]

    contract = contracts[evidence_type]
    expected_id = f"private-match-evidence-export-configuration/{evidence_type}"
    schema_path = root / "schema" / CONFIGURATION_SCHEMA_FILE
    try:
        schema_digest = file_digest(schema_path.read_bytes())
    except OSError:
        return [
            Finding(
                "error",
                "configuration-contract",
                path,
                "configuration contract is unavailable",
            )
        ]
    if (
        contract.get("id") != expected_id
        or contract.get("version") != "0.1"
        or contract.get("digest") != schema_digest
    ):
        return [
            Finding(
                "error",
                "configuration-contract",
                path,
                "configuration contract binding does not match",
            )
        ]

    validator = load_export_schemas(root)["evidence-export-configuration"]
    wrapper = {"evidence_type": evidence_type, "configuration": configuration}
    return [
        Finding(
            "error",
            "configuration-contract",
            path,
            f"{_json_path(error)}: closed configuration contract violation",
        )
        for error in sorted(
            validator.iter_errors(wrapper), key=lambda item: list(item.absolute_path)
        )
    ]


def _detached_digest(domain: str, value: dict[str, Any], field: str) -> str:
    material = dict(value)
    material.pop(field, None)
    return domain_digest(domain, material)


def validate_export_bundle(
    bundle: Any,
    path: str,
    root: Path,
    *,
    profile: dict[str, Any] | None = None,
    mode: str = EXPORT_CANDIDATE_MODE,
) -> list[Finding]:
    """Validate a public export without treating it as a publication approval."""

    validator = load_export_schemas(root)["public-evidence-export"]
    findings: list[Finding] = []
    for error in sorted(
        validator.iter_errors(bundle), key=lambda item: list(item.absolute_path)
    ):
        findings.append(
            Finding(
                "error",
                "export-schema",
                path,
                f"{_json_path(error)}: contract violation",
            )
        )
    if not isinstance(bundle, dict):
        return findings

    expected_artifact_status = (
        "export-candidate" if mode == EXPORT_CANDIDATE_MODE else "test-only"
    )
    if mode not in {EXPORT_CANDIDATE_MODE, TEST_FIXTURE_MODE}:
        findings.append(
            Finding("error", "export-mode", path, "unsupported validation mode")
        )
    elif bundle.get("artifact_status") != expected_artifact_status:
        findings.append(
            Finding(
                "error",
                "export-mode",
                path,
                "artifact status does not match the trusted validation mode",
            )
        )

    evidence = bundle.get("evidence_record")
    findings.extend(
        validate_record(
            evidence,
            f"{path}:evidence_record",
            {"evidence": load_evidence_schema(root)},
        )
    )
    if isinstance(evidence, dict):
        if profile is not None:
            findings.extend(
                validate_export_configuration(
                    evidence,
                    f"{path}:evidence_record.configuration",
                    root,
                    profile,
                )
            )
        if evidence.get("lifecycle") != "sanitized":
            findings.append(
                Finding(
                    "error",
                    "export-lifecycle",
                    path,
                    "exported Evidence lifecycle must be sanitized",
                )
            )
        bindings = bundle.get("digest_bindings")
        if isinstance(bindings, dict):
            expected = domain_digest(EXPORTED_EVIDENCE_DOMAIN, evidence)
            if bindings.get("exported_evidence_record_digest") != expected:
                findings.append(
                    Finding(
                        "error",
                        "export-evidence-digest",
                        path,
                        "exported Evidence digest does not match",
                    )
                )
            if bindings.get("evidence_output_digest") != evidence.get("output_digest"):
                findings.append(
                    Finding(
                        "error",
                        "export-output-digest",
                        path,
                        "Evidence output digest binding does not match",
                    )
                )
        report = bundle.get("sanitization_report")
        if (
            not isinstance(report, dict)
            or report.get("input_status") != report.get("output_status")
            or report.get("output_status") != evidence.get("status")
            or report.get("output_lifecycle") != evidence.get("lifecycle")
        ):
            findings.append(
                Finding(
                    "error",
                    "export-status-preservation",
                    path,
                    "sanitization report does not prove exact status/lifecycle preservation",
                )
            )

    if bundle.get("bundle_digest") != _detached_digest(
        BUNDLE_DOMAIN, bundle, "bundle_digest"
    ):
        findings.append(
            Finding(
                "error", "export-bundle-digest", path, "bundle digest does not match"
            )
        )

    publication = bundle.get("publication")
    expected_publication = "candidate" if mode == EXPORT_CANDIDATE_MODE else "test-only"
    if (
        not isinstance(publication, dict)
        or publication.get("status") != expected_publication
        or publication.get("automation_permitted") is not False
    ):
        findings.append(
            Finding(
                "error",
                "export-publication-gate",
                path,
                "publication state must remain non-published and match the mode",
            )
        )
    requirements = bundle.get("review_requirements")
    expected_final_approval = (
        "required-not-provided"
        if mode == EXPORT_CANDIDATE_MODE
        else "not-applicable-test-only"
    )
    if (
        not isinstance(requirements, dict)
        or requirements.get("final_publication_approval") != expected_final_approval
    ):
        findings.append(
            Finding(
                "error",
                "export-publication-approval",
                path,
                "human publication approval must remain absent",
            )
        )
    provenance = bundle.get("review_provenance")
    expected_role = (
        "authorized-human" if mode == EXPORT_CANDIDATE_MODE else "synthetic-reviewer"
    )
    subject_digest = bundle.get("review_subject_digest")
    if not isinstance(provenance, list):
        findings.append(
            Finding(
                "error",
                "export-review-provenance",
                path,
                "review provenance is missing",
            )
        )
    else:
        scopes = [item.get("scope") for item in provenance if isinstance(item, dict)]
        if len(scopes) != 4 or set(scopes) != REVIEW_SCOPES:
            findings.append(
                Finding(
                    "error",
                    "export-review-provenance",
                    path,
                    "all review scopes must occur exactly once",
                )
            )
        for item in provenance:
            if not isinstance(item, dict):
                continue
            if (
                item.get("reviewed_subject_digest") != subject_digest
                or item.get("reviewer_role") != expected_role
            ):
                findings.append(
                    Finding(
                        "error",
                        "export-review-provenance",
                        path,
                        "review subject or reviewer role does not match the artifact mode",
                    )
                )
    omissions = bundle.get("omissions")
    if isinstance(omissions, list):
        permitted = {"path", "rule_id", "category", "action", "human_review_digest"}
        for index, omission in enumerate(omissions):
            if not isinstance(omission, dict) or set(omission) != permitted:
                findings.append(
                    Finding(
                        "error",
                        "export-omission-log",
                        path,
                        f"omissions[{index}] contains non-public fields",
                    )
                )

    if profile is not None:
        profile_material = dict(profile)
        profile_material.pop("profile_digest", None)
        expected_profile = domain_digest(PROFILE_DOMAIN, profile_material)
        verified_manifest: dict[str, Any] | None = None
        manifest_path = root / MANIFEST_PATH
        try:
            manifest = load_json(manifest_path)
            validator = load_export_schemas(root)["evidence-exporter-implementation"]
            manifest_schema_errors = list(validator.iter_errors(manifest))
            if manifest_schema_errors:
                raise ImplementationManifestError(
                    "implementation manifest schema failure"
                )
            verify_implementation_manifest(manifest, root, expected_profile)
        except (OSError, CanonicalJSONError, ImplementationManifestError):
            findings.append(
                Finding(
                    "error",
                    "exporter-implementation",
                    path,
                    "complete exporter implementation manifest does not validate",
                )
            )
        else:
            verified_manifest = manifest
            exporter = bundle.get("exporter")
            bindings = bundle.get("digest_bindings")
            if (
                not isinstance(exporter, dict)
                or exporter.get("implementation_manifest_digest")
                != manifest_file_digest(manifest)
                or exporter.get("implementation_digest")
                != manifest.get("implementation_digest")
                or not isinstance(bindings, dict)
                or bindings.get("exporter_implementation_digest")
                != manifest.get("implementation_digest")
            ):
                findings.append(
                    Finding(
                        "error",
                        "exporter-implementation",
                        path,
                        "bundle does not bind the complete current exporter implementation",
                    )
                )
        findings.extend(
            validate_public_bundle_bindings(
                bundle,
                path,
                root,
                profile,
                mode,
                verified_manifest,
            )
        )

    return findings


def _json_path(error: Any) -> str:
    parts = [str(item) for item in error.absolute_path]
    return ".".join(parts) if parts else "$"


def _parse_datetime(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def _validate_lifecycle(record: dict[str, Any], path: str) -> list[Finding]:
    history = record.get("lifecycle_history")
    if not isinstance(history, list) or not history:
        return []
    entries = [entry for entry in history if isinstance(entry, dict)]
    if len(entries) != len(history):
        return []

    findings: list[Finding] = []
    states = [entry.get("state") for entry in entries]
    if states[0] != "collected":
        findings.append(
            Finding(
                "error",
                "lifecycle-start",
                path,
                "lifecycle_history must start with collected",
            )
        )
    if states[-1] != record.get("lifecycle"):
        findings.append(
            Finding(
                "error",
                "lifecycle-current",
                path,
                "lifecycle must match the last lifecycle_history state",
            )
        )

    previous_time: dt.datetime | None = None
    for index, entry in enumerate(entries):
        current_time = _parse_datetime(entry.get("recorded_at"))
        if previous_time and current_time and current_time <= previous_time:
            findings.append(
                Finding(
                    "error",
                    "lifecycle-time-order",
                    path,
                    f"lifecycle_history[{index}].recorded_at must increase",
                )
            )
        if current_time:
            previous_time = current_time

    for index, (source, target) in enumerate(zip(states, states[1:]), start=1):
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        if (
            source not in LIFECYCLE_TRANSITIONS
            or target not in LIFECYCLE_TRANSITIONS[source]
        ):
            findings.append(
                Finding(
                    "error",
                    "lifecycle-transition",
                    path,
                    f"invalid lifecycle transition at index {index}: {source!r} -> {target!r}",
                )
            )
    return findings


def _validate_model_check(record: dict[str, Any], path: str) -> list[Finding]:
    model_check = record.get("model_check")
    if record.get("type") != "model-check" or not isinstance(model_check, dict):
        return []
    findings: list[Finding] = []
    bounds = model_check.get("state_space_bounds")
    explored = model_check.get("explored_state_space")
    if isinstance(bounds, dict):
        parameters = bounds.get("parameters")
        if isinstance(parameters, list):
            names = [
                name
                for item in parameters
                if isinstance(item, dict)
                and isinstance((name := item.get("name")), str)
            ]
            if len(names) != len(set(names)):
                findings.append(
                    Finding(
                        "error",
                        "model-check-duplicate-parameter",
                        path,
                        "model-check parameter names must be unique",
                    )
                )
            for parameter in parameters:
                if (
                    not isinstance(parameter, dict)
                    or parameter.get("kind") != "integer-range"
                ):
                    continue
                minimum = parameter.get("minimum")
                maximum = parameter.get("maximum")
                if (
                    isinstance(minimum, int)
                    and isinstance(maximum, int)
                    and maximum < minimum
                ):
                    findings.append(
                        Finding(
                            "error",
                            "model-check-range",
                            path,
                            f"parameter {parameter.get('name')!r} maximum must not be below minimum",
                        )
                    )
        if isinstance(explored, dict):
            generated = explored.get("generated_states")
            distinct = explored.get("distinct_states")
            if (
                isinstance(generated, int)
                and isinstance(distinct, int)
                and distinct > generated
            ):
                findings.append(
                    Finding(
                        "error",
                        "model-check-state-count",
                        path,
                        "distinct_states must not exceed generated_states",
                    )
                )
            configured_states = bounds.get("max_states")
            if (
                isinstance(configured_states, int)
                and isinstance(generated, int)
                and generated > configured_states
            ):
                findings.append(
                    Finding(
                        "error",
                        "model-check-state-bound",
                        path,
                        "generated_states must not exceed the configured max_states",
                    )
                )
            configured_depth = bounds.get("max_depth")
            explored_depth = explored.get("maximum_depth")
            if (
                isinstance(configured_depth, int)
                and isinstance(explored_depth, int)
                and explored_depth > configured_depth
            ):
                findings.append(
                    Finding(
                        "error",
                        "model-check-depth",
                        path,
                        "explored maximum_depth must not exceed the configured max_depth",
                    )
                )
    return findings


def validate_semantics(record: dict[str, Any], path: str) -> list[Finding]:
    findings: list[Finding] = []
    record_type = record.get("record_type")

    if record_type == "evidence":
        started = _parse_datetime(record.get("started_at"))
        completed = _parse_datetime(record.get("completed_at"))
        if started and completed and completed < started:
            findings.append(
                Finding(
                    "error",
                    "time-order",
                    path,
                    "completed_at must not be before started_at",
                )
            )
        findings.extend(_validate_lifecycle(record, path))
        findings.extend(_validate_model_check(record, path))

    elif record_type == "claim":
        valid_from = _parse_datetime(record.get("valid_from"))
        valid_until = _parse_datetime(record.get("valid_until"))
        if valid_from and valid_until and valid_until < valid_from:
            findings.append(
                Finding(
                    "error",
                    "time-order",
                    path,
                    "valid_until must not be before valid_from",
                )
            )

    elif record_type == "assumption":
        reviewed = _parse_datetime(record.get("reviewed_at"))
        next_review = _parse_datetime(record.get("next_review_at"))
        if reviewed and next_review and next_review < reviewed:
            findings.append(
                Finding(
                    "error",
                    "time-order",
                    path,
                    "next_review_at must not be before reviewed_at",
                )
            )

    elif record_type == "known-limitation":
        identified = _parse_datetime(record.get("identified_at"))
        reviewed = _parse_datetime(record.get("reviewed_at"))
        next_review = _parse_datetime(record.get("next_review_at"))
        if identified and reviewed and reviewed < identified:
            findings.append(
                Finding(
                    "error",
                    "time-order",
                    path,
                    "reviewed_at must not be before identified_at",
                )
            )
        if reviewed and next_review and next_review < reviewed:
            findings.append(
                Finding(
                    "error",
                    "time-order",
                    path,
                    "next_review_at must not be before reviewed_at",
                )
            )

    elif record_type == "evidence-manifest":
        publication = record.get("publication")
        approvals = record.get("approvals")
        if (
            isinstance(publication, dict)
            and publication.get("status") == "published"
            and isinstance(approvals, list)
            and not any(
                isinstance(item, dict)
                and item.get("type") == "publication"
                and item.get("status") == "approved"
                for item in approvals
            )
        ):
            findings.append(
                Finding(
                    "error",
                    "publication-approval",
                    path,
                    "published manifest requires an approved human publication review",
                )
            )

    return findings


def validate_record(
    record: Any,
    path: str,
    validators: dict[str, Draft202012Validator],
) -> list[Finding]:
    if not isinstance(record, dict):
        return [Finding("error", "record-shape", path, "record must be a JSON object")]
    record_type = record.get("record_type")
    validator = validators.get(record_type)
    if validator is None:
        return [
            Finding(
                "error",
                "unknown-record-type",
                path,
                f"unsupported record_type: {record_type!r}",
            )
        ]

    findings: list[Finding] = []
    for error in sorted(
        validator.iter_errors(record), key=lambda item: list(item.absolute_path)
    ):
        findings.append(
            Finding("error", "schema", path, f"{_json_path(error)}: {error.message}")
        )
    findings.extend(validate_semantics(record, path))
    return findings


def _reference_sets(records: list[dict[str, Any]]) -> dict[str, set[str]]:
    result = {record_type: set() for record_type in SCHEMA_FILES}
    for record in records:
        record_type = record.get("record_type")
        record_id = record.get("id")
        if record_type in result and isinstance(record_id, str):
            result[record_type].add(record_id)
    return result


def _record_path(record: dict[str, Any], paths: dict[str, str]) -> str:
    internal_path = record.get("_path")
    if isinstance(internal_path, str):
        return internal_path
    record_id = record.get("id")
    if isinstance(record_id, str):
        return paths.get(record_id, record_id)
    return "unknown"


def validate_cross_references(
    records: list[dict[str, Any]], paths: dict[str, str]
) -> list[Finding]:
    findings: list[Finding] = []
    refs = _reference_sets(records)
    all_ids: dict[str, str] = {}
    evidence_by_id: dict[str, dict[str, Any]] = {}
    for record in records:
        record_id = record.get("id")
        if not isinstance(record_id, str):
            continue
        path = _record_path(record, paths)
        if record_id in all_ids:
            findings.append(
                Finding(
                    "error",
                    "duplicate-id",
                    path,
                    f"duplicate id also present in {all_ids[record_id]}",
                )
            )
        else:
            all_ids[record_id] = path
        if record.get("record_type") == "evidence":
            evidence_by_id.setdefault(record_id, record)

    for record in records:
        path = _record_path(record, paths)
        if record.get("record_type") == "claim":
            mappings = [
                ("assumptions", "assumption"),
                ("evidence", "evidence"),
                ("limitations", "known-limitation"),
            ]
        elif record.get("record_type") == "evidence-manifest":
            mappings = [
                ("claims", "claim"),
                ("assumptions", "assumption"),
                ("evidence", "evidence"),
                ("limitations", "known-limitation"),
            ]
        elif record.get("record_type") == "known-limitation":
            mappings = [("affected_claims", "claim")]
        elif record.get("record_type") == "assurance-notice":
            mappings = [("affected_claims", "claim")]
        else:
            mappings = []

        for field, target_type in mappings:
            targets = record.get(field, [])
            if not isinstance(targets, list):
                continue
            for target in targets:
                if not isinstance(target, str):
                    continue
                if target not in refs[target_type]:
                    findings.append(
                        Finding(
                            "error",
                            "missing-reference",
                            path,
                            f"{field} references unknown {target_type} id {target}",
                        )
                    )

        if record.get("record_type") == "claim" and record.get("status") in {
            "supported",
            "supported-with-assumptions",
        }:
            evidence_ids = record.get("evidence", [])
            if isinstance(evidence_ids, list):
                for evidence_id in evidence_ids:
                    if not isinstance(evidence_id, str):
                        continue
                    evidence = evidence_by_id.get(evidence_id)
                    if evidence and evidence.get("lifecycle") in {
                        "superseded",
                        "withdrawn",
                    }:
                        findings.append(
                            Finding(
                                "error",
                                "inactive-evidence-reference",
                                path,
                                f"active claim references {evidence.get('lifecycle')} evidence {evidence_id}",
                            )
                        )

        if record.get("record_type") == "evidence-manifest":
            evidence_ids = record.get("evidence", [])
            digests = record.get("digests")
            if not isinstance(evidence_ids, list) or not isinstance(digests, dict):
                continue
            record_digests = digests.get("evidence_record_digests")
            if isinstance(record_digests, list) and len(record_digests) != len(
                evidence_ids
            ):
                findings.append(
                    Finding(
                        "error",
                        "evidence-record-digest-count",
                        path,
                        "evidence_record_digests must have one entry per referenced Evidence record",
                    )
                )
            expected_output_digests = {
                evidence["output_digest"]
                for evidence_id in evidence_ids
                if isinstance(evidence_id, str)
                if (evidence := evidence_by_id.get(evidence_id))
                and isinstance(evidence.get("output_digest"), str)
            }
            output_digests = digests.get("evidence_output_digests")
            if (
                isinstance(output_digests, list)
                and all(isinstance(item, str) for item in output_digests)
                and set(output_digests) != expected_output_digests
            ):
                findings.append(
                    Finding(
                        "error",
                        "evidence-output-digest-set",
                        path,
                        "evidence_output_digests must equal referenced Evidence output digests",
                    )
                )
    return findings


def validate_repository(root: Path) -> tuple[list[Finding], list[dict[str, Any]]]:
    validators = load_schemas(root)
    findings: list[Finding] = []
    records: list[dict[str, Any]] = []
    paths: dict[str, str] = {}
    assurance_root = root / RECORD_DIR
    if not assurance_root.exists():
        return findings, records

    for path in _iter_json(assurance_root):
        rel = _relative(path, root)
        try:
            record = load_json(path)
        except Exception as exc:
            findings.append(Finding("error", "json-parse", rel, str(exc)))
            continue
        findings.extend(validate_record(record, rel, validators))
        if isinstance(record, dict):
            stored_record = dict(record)
            stored_record["_path"] = rel
            records.append(stored_record)
            if isinstance(record.get("id"), str):
                paths.setdefault(record["id"], rel)

    findings.extend(validate_cross_references(records, paths))
    return findings, records


def render_markdown(findings: list[Finding], records_count: int) -> str:
    counts = {
        severity: sum(1 for item in findings if item.severity == severity)
        for severity in ("error", "warning", "info")
    }
    lines = [
        "# Assurance Schema Validation Report",
        "",
        f"- generated_at: {dt.datetime.now(dt.timezone.utc).isoformat()}",
        f"- records: {records_count}",
        f"- errors: {counts['error']}",
        f"- warnings: {counts['warning']}",
        f"- info: {counts['info']}",
        "",
    ]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    lines.extend(["| Severity | Code | Path | Message |", "|---|---|---|---|"])
    for item in sorted(
        findings,
        key=lambda value: (
            value.severity != "error",
            value.path,
            value.code,
            value.message,
        ),
    ):
        escaped_path = item.path.replace("|", "\\|")
        escaped_message = item.message.replace("|", "\\|")
        lines.append(
            f"| {item.severity} | `{item.code}` | `{escaped_path}` | {escaped_message} |"
        )
    return "\n".join(lines) + "\n"


def write_reports(
    report_dir: Path, findings: list[Finding], records_count: int
) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "records": records_count,
        "summary": {
            "errors": sum(1 for item in findings if item.severity == "error"),
            "warnings": sum(1 for item in findings if item.severity == "warning"),
            "info": sum(1 for item in findings if item.severity == "info"),
        },
        "findings": [dataclasses.asdict(item) for item in findings],
    }
    (report_dir / "assurance-schema-report.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )
    (report_dir / "assurance-schema-report.md").write_text(
        render_markdown(findings, records_count), encoding="utf-8"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--report-dir", type=Path, default=Path("artifacts"))
    parser.add_argument(
        "--export-bundle",
        type=Path,
        action="append",
        default=[],
        help="also validate a public export bundle within the repository",
    )
    parser.add_argument(
        "--export-mode",
        choices=(EXPORT_CANDIDATE_MODE, TEST_FIXTURE_MODE),
        default=EXPORT_CANDIDATE_MODE,
        help="trusted mode for all explicitly supplied export bundles",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    report_dir = (
        args.report_dir if args.report_dir.is_absolute() else root / args.report_dir
    )
    findings, records = validate_repository(root)
    profile: dict[str, Any] | None = None
    profile_path = root / "profiles" / "public-evidence-export.v0.1.json"
    if profile_path.exists():
        try:
            loaded_profile = load_json(profile_path)
        except (OSError, CanonicalJSONError):
            findings.append(
                Finding(
                    "error",
                    "export-profile-parse",
                    _relative(profile_path, root),
                    "profile is not strict JSON",
                )
            )
        else:
            if isinstance(loaded_profile, dict):
                profile = loaded_profile
            else:
                findings.append(
                    Finding(
                        "error",
                        "export-profile-shape",
                        _relative(profile_path, root),
                        "profile must be an object",
                    )
                )
    for requested in args.export_bundle:
        bundle_path = requested if requested.is_absolute() else root / requested
        try:
            bundle_path.resolve().relative_to(root)
            bundle = load_json(bundle_path)
        except (OSError, ValueError, CanonicalJSONError):
            findings.append(
                Finding(
                    "error",
                    "export-bundle-parse",
                    _relative(bundle_path, root),
                    "bundle is not a strict repository JSON file",
                )
            )
            continue
        findings.extend(
            validate_export_bundle(
                bundle,
                _relative(bundle_path, root),
                root,
                profile=profile,
                mode=args.export_mode,
            )
        )
    write_reports(report_dir, findings, len(records))
    errors = sum(1 for item in findings if item.severity == "error")
    warnings = sum(1 for item in findings if item.severity == "warning")
    print(
        f"assurance-schema: records={len(records)} errors={errors} warnings={warnings} report={report_dir}"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
