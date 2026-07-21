#!/usr/bin/env python3
"""Create a deterministic, public-candidate Evidence bundle from one staged file."""

from __future__ import annotations

import argparse
import base64
import copy
import dataclasses
import ipaddress
import os
import re
import stat
import sys
import unicodedata
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import unquote, urlsplit

from jsonschema import Draft202012Validator, FormatChecker

try:
    from canonical_json import (
        CanonicalJSONError,
        canonicalize,
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
    from validate_assurance import (
        load_evidence_schema,
        validate_export_configuration,
        validate_record,
    )
except ImportError:  # pragma: no cover - package import during unit tests
    from scripts.canonical_json import (
        CanonicalJSONError,
        canonicalize,
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
    from scripts.validate_assurance import (
        load_evidence_schema,
        validate_export_configuration,
        validate_record,
    )


VERSION = "0.1"
DEFAULT_INPUT_LIMIT = 262_144
PROFILE_DOMAIN = "private-match-evidence-export-profile/v0.1"
CANDIDATE_DOMAIN = "private-match-evidence-export-candidate/v0.1"
REVIEW_SUBJECT_DOMAIN = "private-match-evidence-export-review-subject/v0.1"
SOURCE_EVIDENCE_DOMAIN = "private-match-source-evidence-record/v0.1"
EXPORTED_EVIDENCE_DOMAIN = "private-match-exported-evidence/v0.1"
BUNDLE_DOMAIN = "private-match-public-evidence-bundle/v0.1"
OUTPUT_FILENAME = "public-evidence-export.v0.1.json"
EXPORT_CANDIDATE_MODE = "export-candidate"
TEST_FIXTURE_MODE = "test-fixture"
FIXTURE_STAGING_ROOT = Path("tests/fixtures/export/input")
FIXTURE_CATALOG_PATH = Path("tests/fixtures/export/fixture-catalog.v0.1.json")
REVIEW_SCOPES = {
    "privacy": "privacy",
    "security_boundary": "security-boundary",
    "ip": "ip",
    "vulnerability": "vulnerability",
}
EXPECTED_PROFILE_FIELDS = {
    "schema_version",
    "profile_id",
    "profile_version",
    "profile_digest",
    "input_contract",
    "output_contract",
    "allowed_candidate_fields",
    "allowed_evidence_fields",
    "configuration_contracts",
    "allowed_output_fields",
    "prohibited_field_names",
    "prohibited_value_classes",
    "allowed_omission_rules",
    "status_preservation",
    "lifecycle_rule",
    "path_policy",
    "identifier_policy",
    "vulnerability_ip_policy",
    "reviewed_protocol_binding",
    "serialization",
}


@dataclasses.dataclass(frozen=True)
class ExportError(Exception):
    """A bounded, value-free rejection suitable for a public CI log."""

    code: str
    path: str
    detail: str = "export contract rejected the candidate"

    def __str__(self) -> str:
        return f"export: error [{self.code}] {self.path}: {self.detail}"


def _reject(code: str, path: str, detail: str) -> None:
    raise ExportError(code, path, detail)


def _schema_path(error: Any) -> str:
    path = "$"
    for item in error.absolute_path:
        path += f"[{item}]" if isinstance(item, int) else f".{item}"
    return path


def _load_schema(root: Path, name: str) -> dict[str, Any]:
    try:
        raw = (root / "schema" / name).read_bytes()
        schema = strict_loads(raw, max_bytes=1_048_576)
    except (OSError, CanonicalJSONError) as error:
        raise ExportError(
            "schema-invalid", "$.schema", "required schema is unavailable or invalid"
        ) from error
    if not isinstance(schema, dict):
        _reject("schema-invalid", "$", "schema root must be an object")
    Draft202012Validator.check_schema(schema)
    return schema


def _validate_schema(value: Any, schema: dict[str, Any], *, code: str) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(value), key=lambda item: list(item.path))
    if errors:
        _reject(code, _schema_path(errors[0]), "closed contract validation failed")


def _parts_are_safe(candidate: Path) -> bool:
    return (
        not candidate.is_absolute() and candidate.parts and ".." not in candidate.parts
    )


def _resolve_repo_subpath(root: Path, candidate: Path, *, kind: str) -> Path:
    if not _parts_are_safe(candidate):
        _reject(
            "path-boundary",
            f"$.{kind}",
            "path must be a non-empty repository-relative path",
        )
    root = root.resolve()
    path = root.joinpath(candidate)
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, ValueError):
        _reject("path-boundary", f"$.{kind}", "path leaves the repository root")
    current = root
    for part in candidate.parts:
        current = current / part
        if current.is_symlink():
            _reject("path-symlink", f"$.{kind}", "symlinks are forbidden")
    return resolved


def resolve_input_path(root: Path, staging_root: Path, input_name: Path) -> Path:
    staging = _resolve_repo_subpath(root, staging_root, kind="staging_root")
    if not staging.exists() or not staging.is_dir():
        _reject(
            "path-boundary",
            "$.staging_root",
            "staging root must be an existing directory",
        )
    if not _parts_are_safe(input_name):
        _reject("path-boundary", "$.input", "input must be a relative file path")
    candidate = staging.joinpath(input_name)
    current = staging
    for part in input_name.parts:
        current = current / part
        if current.is_symlink():
            _reject("path-symlink", "$.input", "input symlinks are forbidden")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(staging)
    except FileNotFoundError:
        _reject("path-missing", "$.input", "input file does not exist")
    except (OSError, ValueError):
        _reject("path-boundary", "$.input", "input leaves the staging root")
    if not resolved.is_file() or not stat.S_ISREG(resolved.stat().st_mode):
        _reject("path-type", "$.input", "input must be one regular file")
    return resolved


def resolve_profile_path(root: Path, profile_name: Path) -> Path:
    path = _resolve_repo_subpath(root, profile_name, kind="profile")
    profile_root = (root / "profiles").resolve()
    try:
        path.relative_to(profile_root)
    except ValueError:
        _reject("path-boundary", "$.profile", "profile must be under profiles/")
    if not path.exists() or not path.is_file() or path.is_symlink():
        _reject(
            "path-type", "$.profile", "profile must be one regular non-symlink file"
        )
    return path


def resolve_output_dir(root: Path, output_name: Path) -> Path:
    output = _resolve_repo_subpath(root, output_name, kind="output_dir")
    if output.exists() and (not output.is_dir() or output.is_symlink()):
        _reject(
            "output-boundary",
            "$.output_dir",
            "output root must be a non-symlink directory",
        )
    return output


def profile_digest(profile: dict[str, Any]) -> str:
    material = copy.deepcopy(profile)
    material.pop("profile_digest", None)
    return domain_digest(PROFILE_DOMAIN, material)


def bundle_digest(bundle: dict[str, Any]) -> str:
    material = copy.deepcopy(bundle)
    material.pop("bundle_digest", None)
    return domain_digest(BUNDLE_DOMAIN, material)


def _sort_semantic_sets(evidence: dict[str, Any]) -> None:
    """Sort only arrays whose existing schemas declare set-like uniqueness."""

    for field in ("input_digests", "public_artifacts"):
        values = evidence.get(field)
        if isinstance(values, list) and all(isinstance(item, str) for item in values):
            values.sort()
    model = evidence.get("model_check")
    if isinstance(model, dict):
        for field in ("properties",):
            values = model.get(field)
            if isinstance(values, list) and all(
                isinstance(item, str) for item in values
            ):
                values.sort()
        bounds = model.get("state_space_bounds")
        if isinstance(bounds, dict):
            constraints = bounds.get("constraints")
            if isinstance(constraints, list) and all(
                isinstance(item, str) for item in constraints
            ):
                constraints.sort()
            parameters = bounds.get("parameters")
            if isinstance(parameters, list):
                for parameter in parameters:
                    if (
                        isinstance(parameter, dict)
                        and parameter.get("kind") == "finite-set"
                    ):
                        values = parameter.get("values")
                        if isinstance(values, list):
                            values.sort(
                                key=lambda item: (type(item).__name__, str(item))
                            )


def _candidate_digest(candidate: dict[str, Any]) -> str:
    material = copy.deepcopy(candidate)
    evidence = material.get("evidence_record")
    if isinstance(evidence, dict):
        _sort_semantic_sets(evidence)
    omissions = material.get("requested_omissions")
    if isinstance(omissions, list):
        omissions.sort(key=lambda item: (item.get("path", ""), item.get("rule_id", "")))
    return domain_digest(CANDIDATE_DOMAIN, material)


def review_subject_digest(candidate: dict[str, Any]) -> str:
    """Bind every review to all candidate material except the reviews themselves."""

    material = copy.deepcopy(candidate)
    material.pop("review_markers", None)
    material.pop("review_subject_digest", None)
    evidence = material.get("evidence_record")
    if isinstance(evidence, dict):
        _sort_semantic_sets(evidence)
    omissions = material.get("requested_omissions")
    if isinstance(omissions, list):
        omissions.sort(key=lambda item: (item.get("path", ""), item.get("rule_id", "")))
    return domain_digest(REVIEW_SUBJECT_DOMAIN, material)


def source_evidence_digest(evidence: dict[str, Any]) -> str:
    material = copy.deepcopy(evidence)
    _sort_semantic_sets(material)
    return domain_digest(SOURCE_EVIDENCE_DOMAIN, material)


def _load_closed_json(root: Path, relative: Path, schema_name: str, code: str) -> Any:
    path = _resolve_repo_subpath(root, relative, kind=code)
    if path.is_symlink() or not path.is_file():
        _reject(code, f"$.{code}", "required repository artifact is unavailable")
    try:
        value = strict_loads(path.read_bytes(), max_bytes=1_048_576)
    except (OSError, CanonicalJSONError) as error:
        raise ExportError(
            code, f"$.{code}", "required artifact is not strict JSON"
        ) from error
    _validate_schema(value, _load_schema(root, schema_name), code=code)
    return value


def _load_fixture_catalog(root: Path) -> tuple[dict[str, Any], str]:
    value = _load_closed_json(
        root,
        FIXTURE_CATALOG_PATH,
        "evidence-export-fixture-catalog.v0.1.schema.json",
        "fixture-catalog",
    )
    if not isinstance(value, dict):
        _reject("fixture-catalog", "$.fixture_catalog", "catalog must be an object")
    ids: set[str] = set()
    paths: set[str] = set()
    for entry in value["fixtures"]:
        if entry["fixture_id"] in ids or entry["relative_input_path"] in paths:
            _reject(
                "fixture-catalog",
                "$.fixture_catalog",
                "fixture identifiers and paths must be unique",
            )
        ids.add(entry["fixture_id"])
        paths.add(entry["relative_input_path"])
    return value, file_digest(canonicalize(value) + b"\n")


def _load_implementation_manifest(
    root: Path, profile: dict[str, Any]
) -> tuple[dict[str, Any], str]:
    value = _load_closed_json(
        root,
        MANIFEST_PATH,
        "evidence-exporter-implementation.v0.1.schema.json",
        "implementation-manifest",
    )
    if not isinstance(value, dict):
        _reject("implementation-manifest", "$.exporter", "manifest must be an object")
    try:
        verify_implementation_manifest(value, root, profile["profile_digest"])
    except ImplementationManifestError as error:
        raise ExportError(
            "implementation-manifest",
            "$.exporter",
            "implementation manifest or a listed file does not match",
        ) from error
    return value, manifest_file_digest(value)


def _load_profile(path: Path) -> dict[str, Any]:
    try:
        profile = strict_loads(path.read_bytes(), max_bytes=262_144)
    except (OSError, CanonicalJSONError) as error:
        raise ExportError(
            "profile-parse", "$.profile", "profile is not strict JSON"
        ) from error
    if not isinstance(profile, dict) or set(profile) != EXPECTED_PROFILE_FIELDS:
        _reject(
            "profile-allowlist",
            "$.profile",
            "profile fields do not match the reviewed contract",
        )
    schema_path = (
        path.parent.parent / "schema" / "evidence-export-profile.v0.1.schema.json"
    )
    try:
        schema = strict_loads(schema_path.read_bytes(), max_bytes=1_048_576)
    except (OSError, CanonicalJSONError) as error:
        raise ExportError(
            "profile-schema", "$.profile", "profile schema is unavailable"
        ) from error
    if not isinstance(schema, dict):
        _reject("profile-schema", "$.profile", "profile schema root must be an object")
    _validate_schema(profile, schema, code="profile-schema")
    expected = profile_digest(profile)
    if profile.get("profile_digest") != expected:
        _reject(
            "profile-digest",
            "$.profile.profile_digest",
            "profile digest does not match",
        )
    if (
        profile.get("profile_id") != "private-match-public-evidence-export"
        or profile.get("profile_version") != VERSION
    ):
        _reject("profile-version", "$.profile", "unsupported export profile")
    serialization = profile.get("serialization")
    if not isinstance(serialization, dict) or serialization.get("format") != "RFC8785":
        _reject(
            "profile-serialization", "$.profile.serialization", "RFC 8785 is required"
        )
    return profile


def _iter_leaves(value: Any, path: str = "$") -> Iterable[tuple[str, str, str | None]]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            yield child_path, key, None
            yield from _iter_leaves(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_leaves(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, "", value


_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----", re.I),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{10,}\b", re.I),
    re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b"),
    re.compile(r"\b(?:password|passwd|secret|token|client_secret)\s*[:=]\s*\S+", re.I),
    re.compile(r"[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@", re.I),
)
_EMAIL = re.compile(r"(?<![\w.+-])[\w.+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w.-])")
_PHONE = re.compile(r"(?<!\d)(?:\+\d{1,3}[ .-]?)?(?:\d[ .-]?){9,14}(?!\d)")
_WINDOWS_PATH = re.compile(
    r"(?:^|\s)[A-Za-z]:\\(?:Users|Windows|ProgramData|private|home)\\", re.I
)
_POSIX_PATH = re.compile(
    r"(?:^|[\s('])/(?:home|Users|root|etc|var|srv|opt|mnt|private)/", re.I
)
_ACCOUNT_ID = re.compile(r"(?<![0-9a-f])\d{12}(?![0-9a-f])", re.I)
_STRUCTURED_IDENTIFIER = re.compile(
    r"\b(?:account|customer|cust|project|subscription|tenant)[-_][A-Za-z0-9]{4,}\b",
    re.I,
)
_CONTROL_OR_BIDI = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]"
)
_PRIVATE_LOCATOR = re.compile(
    r"(?:private-match-product|git@|ssh://|(?:^|/)\.git(?:/|$))", re.I
)
_VULNERABILITY_DETAIL = re.compile(
    r"(?:exploit\s+(?:code|command)|reproduction\s+command|vulnerable\s+private\s+endpoint|attack\s+prerequisite)",
    re.I,
)


def _decoded_forms(value: str) -> list[str]:
    forms = [value, unicodedata.normalize("NFKC", value), unquote(value)]
    compact = value.strip()
    if (
        8 <= len(compact) <= 8192
        and len(compact) % 4 == 0
        and re.fullmatch(r"[A-Za-z0-9+/=]+", compact)
    ):
        try:
            decoded = base64.b64decode(compact, validate=True).decode(
                "utf-8", errors="strict"
            )
        except (ValueError, UnicodeError):
            pass
        else:
            forms.append(decoded)
    return list(dict.fromkeys(forms))


def _is_nonpublic_host(text: str) -> bool:
    candidates: set[str] = set()
    stripped = text.strip("[](){}<>,.;'\" ")
    if "://" in stripped:
        try:
            host = urlsplit(stripped).hostname
        except ValueError:
            host = None
        if host:
            candidates.add(host)
    for token in re.findall(
        r"\[?[0-9a-fA-F:.]+\]?|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|localhost", stripped
    ):
        candidates.add(token.strip("[]"))
    for host in candidates:
        lowered = host.lower().rstrip(".")
        if lowered == "localhost" or lowered.endswith(
            (".localhost", ".internal", ".local", ".lan")
        ):
            return True
        if lowered in {"metadata.google.internal", "instance-data"}:
            return True
        try:
            address = ipaddress.ip_address(lowered)
        except ValueError:
            continue
        if not address.is_global:
            return True
    return False


def _sensitive_value_class(value: str) -> str | None:
    if re.fullmatch(r"sha256:[0-9a-f]{64}", value) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z", value
    ):
        return None
    for form in _decoded_forms(value):
        if _CONTROL_OR_BIDI.search(form):
            return "control-or-bidi-character"
        if any(pattern.search(form) for pattern in _SECRET_PATTERNS):
            return "private-key-or-token"
        if _PRIVATE_LOCATOR.search(form):
            return "private-repository-locator"
        if (
            _WINDOWS_PATH.search(form)
            or _POSIX_PATH.search(form)
            or re.match(r"^[A-Za-z]:\\", form)
            or form.startswith(("/", "~/", "file:///"))
            or re.search(r"(?:^|[/\\])\.\.(?:$|[/\\])", form)
        ):
            return "private-repository-locator"
        if _is_nonpublic_host(form):
            return "internal-host-or-address"
        if _ACCOUNT_ID.search(form):
            return "account-identifier"
        if (
            _EMAIL.search(form)
            or _PHONE.search(form)
            or _STRUCTURED_IDENTIFIER.search(form)
        ):
            return "customer-or-personal-identifier"
        if _VULNERABILITY_DETAIL.search(form):
            return "raw-vulnerability-detail"
    return None


def _validate_allowlist(
    candidate: dict[str, Any], profile: dict[str, Any], root: Path
) -> None:
    if set(candidate) != set(profile["allowed_candidate_fields"]):
        _reject("candidate-allowlist", "$", "candidate fields do not match the profile")
    evidence = candidate.get("evidence_record")
    if not isinstance(evidence, dict) or set(evidence) != set(
        profile["allowed_evidence_fields"]
    ):
        _reject(
            "evidence-allowlist",
            "$.evidence_record",
            "Evidence fields do not match the profile",
        )
    configuration_findings = validate_export_configuration(
        evidence, "$.evidence_record.configuration", root, profile
    )
    if configuration_findings:
        _reject(
            "configuration-contract",
            "$.evidence_record.configuration",
            "configuration violates its closed type-specific contract",
        )
    if evidence.get("type") == "conformance":
        configuration = evidence["configuration"]
        protocol = configuration["protocol"]
        suite = configuration["conformance_suite"]
        protocol_binding = candidate["protocol_binding"]
        suite_binding = candidate["conformance_suite_binding"]
        if (
            protocol["identifier"] != protocol_binding["protocol_profile"]
            or protocol["version"] != protocol_binding["protocol_version"]
            or suite["identifier"] != suite_binding["identifier"]
            or suite["version"] != suite_binding["version"]
        ):
            _reject(
                "configuration-binding",
                "$.evidence_record.configuration",
                "conformance configuration does not match reviewed bindings",
            )
    prohibited = set(profile["prohibited_field_names"])
    for path, key, _value in _iter_leaves(evidence, "$.evidence_record"):
        if key.lower() in prohibited:
            _reject("prohibited-field", path, "a prohibited field name is present")


def _scan_sensitive_values(candidate: dict[str, Any]) -> None:
    evidence = candidate["evidence_record"]
    for path, _key, value in _iter_leaves(evidence, "$.evidence_record"):
        if value is None:
            continue
        category = _sensitive_value_class(value)
        if category:
            _reject("sensitive-value", path, f"prohibited value class: {category}")


def _validate_protocol_binding(
    candidate: dict[str, Any], profile: dict[str, Any]
) -> None:
    actual = candidate["protocol_binding"]
    pin = profile["reviewed_protocol_binding"]
    for field in (
        "protocol_profile",
        "protocol_version",
        "source_revision_digest",
        "state_machine_digest",
        "message_registry_digest",
    ):
        if actual.get(field) != pin.get(field):
            _reject(
                "protocol-binding",
                f"$.protocol_binding.{field}",
                "binding does not match the reviewed Protocol main pin",
            )
    if candidate["conformance_suite_binding"].get("digest") != pin.get(
        "conformance_suite_digest"
    ):
        _reject(
            "protocol-binding",
            "$.conformance_suite_binding.digest",
            "suite binding does not match the reviewed Protocol main pin",
        )


def _fixture_entry(
    candidate: dict[str, Any], catalog: dict[str, Any], input_name: Path | None
) -> dict[str, Any] | None:
    digest = _candidate_digest(candidate)
    matches = [
        entry for entry in catalog["fixtures"] if entry["candidate_digest"] == digest
    ]
    if len(matches) != 1:
        return None
    entry = matches[0]
    if input_name is not None and entry["relative_input_path"] != input_name.as_posix():
        return None
    return entry


def _validate_execution_mode(
    candidate: dict[str, Any],
    mode: str,
    catalog: dict[str, Any],
    input_name: Path | None,
) -> dict[str, Any] | None:
    if mode not in {EXPORT_CANDIDATE_MODE, TEST_FIXTURE_MODE}:
        _reject("execution-mode", "$.mode", "unsupported trusted execution mode")
    expected_status = (
        "export-candidate" if mode == EXPORT_CANDIDATE_MODE else "test-only"
    )
    if candidate.get("artifact_status") != expected_status:
        _reject(
            "execution-mode",
            "$.artifact_status",
            "candidate status does not match the trusted execution mode",
        )
    entry = _fixture_entry(candidate, catalog, input_name)
    if mode == TEST_FIXTURE_MODE and entry is None:
        _reject(
            "fixture-catalog",
            "$.input",
            "test fixture is not catalogued with the accepted candidate digest",
        )
    if mode == EXPORT_CANDIDATE_MODE and entry is not None:
        _reject(
            "execution-mode",
            "$.artifact_status",
            "catalogued synthetic fixture cannot be exported as a candidate",
        )
    return entry


def _validate_reviews(
    candidate: dict[str, Any],
    mode: str,
    catalog: dict[str, Any],
) -> None:
    expected_role = (
        "authorized-human" if mode == EXPORT_CANDIDATE_MODE else "synthetic-reviewer"
    )
    actual_subject = review_subject_digest(candidate)
    if candidate["review_subject_digest"] != actual_subject:
        _reject(
            "review-subject",
            "$.review_subject_digest",
            "review subject digest does not match candidate material",
        )
    fixture_review_digests = {
        digest
        for entry in catalog["fixtures"]
        for digest in entry["synthetic_review_digests"]
    }
    reviews = candidate["review_markers"]
    for name, expected_scope in REVIEW_SCOPES.items():
        review = reviews[name]
        if review["status"] not in {"approved", "not-applicable"}:
            _reject(
                "review-required",
                f"$.review_markers.{name}.status",
                "required human review is not approved",
            )
        if review["reviewer_role"] != expected_role:
            _reject(
                "review-role",
                f"$.review_markers.{name}.reviewer_role",
                "reviewer role does not match the trusted execution mode",
            )
        if review["review_scope"] != expected_scope:
            _reject(
                "review-scope",
                f"$.review_markers.{name}.review_scope",
                "review scope does not match its closed marker slot",
            )
        if review["reviewed_subject_digest"] != actual_subject:
            _reject(
                "review-subject",
                f"$.review_markers.{name}.reviewed_subject_digest",
                "review marker does not bind the complete candidate subject",
            )
        if (
            mode == EXPORT_CANDIDATE_MODE
            and review["review_digest"] in fixture_review_digests
        ):
            _reject(
                "review-role",
                f"$.review_markers.{name}.review_digest",
                "fixture-only review digest is invalid in candidate mode",
            )
    ip_review = reviews["ip"]
    if ip_review["unpublished_invention"] or ip_review["patent_candidate"]:
        _reject(
            "ip-gate",
            "$.review_markers.ip",
            "unpublished or patent-candidate material is not exportable",
        )
    vuln = reviews["vulnerability"]
    if vuln["embargo_status"] != "not-embargoed":
        _reject(
            "vulnerability-gate",
            "$.review_markers.vulnerability.embargo_status",
            "embargoed material is not exportable",
        )
    if vuln["contains_vulnerability_information"] and (
        vuln["status"] != "approved" or not vuln["remediation_approved"]
    ):
        _reject(
            "vulnerability-gate",
            "$.review_markers.vulnerability",
            "vulnerability material lacks approved remediation review",
        )
    markers = candidate["sensitivity_markers"]
    if any(markers.values()):
        _reject(
            "sensitivity-gate",
            "$.sensitivity_markers",
            "candidate declares prohibited sensitive content",
        )


def _validate_bindings(candidate: dict[str, Any], profile: dict[str, Any]) -> None:
    evidence = candidate["evidence_record"]
    source = candidate["source_binding"]
    artifact = candidate["artifact_binding"]
    if candidate["export_profile"]["digest"] != profile["profile_digest"]:
        _reject(
            "profile-digest",
            "$.export_profile.digest",
            "candidate profile binding does not match",
        )
    if source["source_evidence_record_digest"] != source_evidence_digest(evidence):
        _reject(
            "source-digest",
            "$.source_binding.source_evidence_record_digest",
            "source Evidence digest does not match",
        )
    if source["original_status"] != evidence.get("status"):
        _reject(
            "status-preservation",
            "$.source_binding.original_status",
            "source status does not match Evidence status",
        )
    if source["original_lifecycle"] != evidence.get("lifecycle"):
        _reject(
            "lifecycle-preservation",
            "$.source_binding.original_lifecycle",
            "source lifecycle does not match Evidence lifecycle",
        )
    if artifact["subject_artifact_digest"] != evidence.get("subject", {}).get("digest"):
        _reject(
            "artifact-binding",
            "$.artifact_binding.subject_artifact_digest",
            "subject artifact digest does not match",
        )
    if artifact["evidence_output_digest"] != evidence.get("output_digest"):
        _reject(
            "artifact-binding",
            "$.artifact_binding.evidence_output_digest",
            "Evidence output digest does not match",
        )
    _validate_protocol_binding(candidate, profile)


def _validate_lifecycle_precondition(
    candidate: dict[str, Any], profile: dict[str, Any]
) -> None:
    """Require private-side validation before any export construction."""

    evidence = candidate.get("evidence_record")
    source = candidate.get("source_binding")
    if not isinstance(evidence, dict) or not isinstance(source, dict):
        return
    lifecycle = evidence.get("lifecycle") if isinstance(evidence, dict) else None
    original = source.get("original_lifecycle")
    if lifecycle is None or original is None:
        return
    if lifecycle == "collected" or original == "collected":
        _reject(
            "lifecycle-not-validated",
            "$.evidence_record.lifecycle",
            "private-side Evidence must be validated before export",
        )
    allowed = profile.get("lifecycle_rule", {}).get("allowed_input", [])
    if lifecycle not in allowed or original not in allowed:
        _reject(
            "lifecycle-limit",
            "$.evidence_record.lifecycle",
            "Evidence lifecycle is not accepted by the export profile",
        )


def _construct_evidence(
    candidate: dict[str, Any], profile: dict[str, Any]
) -> tuple[dict[str, Any], list[dict[str, str]]]:
    evidence = copy.deepcopy(candidate["evidence_record"])
    _sort_semantic_sets(evidence)
    omissions: list[dict[str, str]] = []
    reviewed_rules = {
        (item["path"], item["rule_id"]): item
        for item in profile["allowed_omission_rules"]
    }
    for omission in candidate["requested_omissions"]:
        rule = reviewed_rules.get((omission["path"], omission["rule_id"]))
        if rule is None:
            _reject(
                "omission-rule",
                "$.requested_omissions",
                "omission is not permitted by the profile",
            )
        evidence["public_artifacts"] = []
        omissions.append(
            {
                "path": rule["path"],
                "rule_id": rule["rule_id"],
                "category": rule["category"],
                "action": rule["action"],
                "human_review_digest": omission["human_review_digest"],
            }
        )
    lifecycle = evidence["lifecycle"]
    event = candidate["sanitization_event"]
    if lifecycle == "validated":
        evidence["lifecycle_history"].append(
            {
                "state": "sanitized",
                "recorded_at": event["recorded_at"],
                "review_digest": event["review_digest"],
            }
        )
        evidence["lifecycle"] = "sanitized"
    elif lifecycle == "sanitized":
        last = evidence["lifecycle_history"][-1]
        if (
            last.get("state") != "sanitized"
            or last.get("review_digest") != event["review_digest"]
            or last.get("recorded_at") != event["recorded_at"]
        ):
            _reject(
                "lifecycle-preservation",
                "$.sanitization_event",
                "existing sanitized history must match the reviewed event",
            )
    elif lifecycle == "collected":
        _reject(
            "lifecycle-not-validated",
            "$.evidence_record.lifecycle",
            "private-side Evidence must be validated before export",
        )
    else:
        _reject(
            "lifecycle-limit",
            "$.evidence_record.lifecycle",
            "export input lifecycle exceeds sanitized",
        )
    if evidence["status"] != candidate["source_binding"]["original_status"]:
        _reject(
            "status-preservation",
            "$.evidence_record.status",
            "Evidence status changed during export",
        )
    return evidence, omissions


def _validate_evidence(evidence: dict[str, Any], root: Path, path: str) -> None:
    findings = validate_record(
        evidence,
        path,
        {"evidence": load_evidence_schema(root)},
    )
    if findings:
        first = findings[0]
        _reject(f"evidence-{first.code}", path, "Evidence record validation failed")


def _construct_bundle(
    candidate: dict[str, Any],
    profile: dict[str, Any],
    evidence: dict[str, Any],
    omissions: list[dict[str, str]],
    implementation_manifest: dict[str, Any],
    implementation_manifest_digest: str,
    fixture_entry: dict[str, Any] | None,
    fixture_catalog_digest: str,
) -> dict[str, Any]:
    candidate_digest = _candidate_digest(candidate)
    evidence_digest = domain_digest(EXPORTED_EVIDENCE_DOMAIN, evidence)
    source = candidate["source_binding"]
    artifact = candidate["artifact_binding"]
    protocol = candidate["protocol_binding"]
    suite = candidate["conformance_suite_binding"]
    reviews = candidate["review_markers"]
    artifact_status = candidate["artifact_status"]
    test_only = artifact_status == "test-only"
    if test_only and fixture_entry is None:
        _reject(
            "fixture-catalog",
            "$.fixture_provenance",
            "test-only export lacks an authorized fixture entry",
        )
    review_provenance = [
        {
            "scope": REVIEW_SCOPES[name],
            "status": reviews[name]["status"],
            "reviewer_role": reviews[name]["reviewer_role"],
            "review_digest": reviews[name]["review_digest"],
            "reviewed_subject_digest": reviews[name]["reviewed_subject_digest"],
        }
        for name in REVIEW_SCOPES
    ]
    bundle: dict[str, Any] = {
        "schema_version": VERSION,
        "artifact_status": artifact_status,
        "record_type": "public-evidence-export",
        "export_profile": {
            "id": profile["profile_id"],
            "version": profile["profile_version"],
            "digest": profile["profile_digest"],
        },
        "export_candidate_id": candidate["export_candidate_id"],
        "export_candidate_digest": candidate_digest,
        "review_subject_digest": candidate["review_subject_digest"],
        "exporter": {
            "identity": "private-match-assurance/evidence-exporter",
            "version": VERSION,
            "implementation_manifest_digest": implementation_manifest_digest,
            "implementation_digest": implementation_manifest["implementation_digest"],
        },
        "fixture_provenance": (
            {
                "fixture_id": fixture_entry["fixture_id"],
                "fixture_catalog_digest": fixture_catalog_digest,
            }
            if fixture_entry is not None
            else None
        ),
        "evidence_record": evidence,
        "digest_bindings": {
            "private_source_revision_digest": source["private_source_revision_digest"],
            "source_evidence_set_digest": source["source_evidence_set_digest"],
            "source_evidence_record_digest": source["source_evidence_record_digest"],
            "input_candidate_digest": candidate_digest,
            "subject_artifact_digest": artifact["subject_artifact_digest"],
            "evidence_output_digest": artifact["evidence_output_digest"],
            "protocol_source_revision_digest": protocol["source_revision_digest"],
            "protocol_state_machine_digest": protocol["state_machine_digest"],
            "protocol_message_registry_digest": protocol["message_registry_digest"],
            "protocol_conformance_suite_digest": suite["digest"],
            "export_profile_digest": profile["profile_digest"],
            "exporter_implementation_digest": implementation_manifest[
                "implementation_digest"
            ],
            "exported_evidence_record_digest": evidence_digest,
        },
        "sanitization_report": {
            "outcome": "exported",
            "checks_executed": [
                "allowlist",
                "candidate-schema",
                "digest-bindings",
                "evidence-schema",
                "lifecycle-limit",
                "path-boundary",
                "prohibited-field-scan",
                "prohibited-value-scan",
                "review-gates",
                "review-subject-binding",
                "status-preservation",
                "trusted-execution-mode",
                "exporter-implementation-manifest",
            ],
            "allowlist_result": "pass",
            "prohibited_field_scan_result": "pass",
            "prohibited_value_scan_result": "pass",
            "status_preservation_result": "pass",
            "input_status": source["original_status"],
            "output_status": evidence["status"],
            "input_lifecycle": source["original_lifecycle"],
            "output_lifecycle": evidence["lifecycle"],
            "digest_binding_result": "pass",
            "privacy_review_marker": reviews["privacy"]["status"],
            "security_review_marker": reviews["security_boundary"]["status"],
            "ip_review_marker": reviews["ip"]["status"],
            "vulnerability_review_marker": reviews["vulnerability"]["status"],
        },
        "omissions": omissions,
        "review_provenance": review_provenance,
        "review_requirements": {
            "privacy": reviews["privacy"]["status"],
            "security_boundary": reviews["security_boundary"]["status"],
            "ip": reviews["ip"]["status"],
            "vulnerability": reviews["vulnerability"]["status"],
            "final_publication_approval": (
                "not-applicable-test-only" if test_only else "required-not-provided"
            ),
        },
        "publication": {
            "status": "test-only" if test_only else "candidate",
            "automation_permitted": False,
        },
    }
    bundle["bundle_digest"] = bundle_digest(bundle)
    return bundle


def validate_public_bundle(
    bundle: Any,
    root: Path,
    profile: dict[str, Any],
    *,
    mode: str = EXPORT_CANDIDATE_MODE,
) -> None:
    schema = _load_schema(root, "public-evidence-export.v0.1.schema.json")
    _validate_schema(bundle, schema, code="bundle-schema")
    if not isinstance(bundle, dict):
        _reject("bundle-shape", "$", "bundle must be an object")
    if set(bundle) != set(profile["allowed_output_fields"]):
        _reject("bundle-allowlist", "$", "bundle fields do not match the profile")
    expected_status = (
        "export-candidate" if mode == EXPORT_CANDIDATE_MODE else "test-only"
    )
    if mode not in {EXPORT_CANDIDATE_MODE, TEST_FIXTURE_MODE}:
        _reject("execution-mode", "$.mode", "unsupported validation mode")
    if bundle["artifact_status"] != expected_status:
        _reject(
            "execution-mode",
            "$.artifact_status",
            "bundle status does not match the trusted validation mode",
        )
    if bundle["bundle_digest"] != bundle_digest(bundle):
        _reject("bundle-digest", "$.bundle_digest", "bundle digest does not match")
    if bundle["digest_bindings"]["export_profile_digest"] != profile["profile_digest"]:
        _reject(
            "profile-digest",
            "$.digest_bindings.export_profile_digest",
            "bundle profile digest does not match",
        )
    if (
        bundle["digest_bindings"]["input_candidate_digest"]
        != bundle["export_candidate_digest"]
    ):
        _reject(
            "candidate-digest",
            "$.digest_bindings.input_candidate_digest",
            "candidate digest binding does not match",
        )
    if (
        bundle["digest_bindings"]["exporter_implementation_digest"]
        != bundle["exporter"]["implementation_digest"]
    ):
        _reject(
            "exporter-digest",
            "$.digest_bindings.exporter_implementation_digest",
            "exporter implementation digest binding does not match",
        )
    implementation, implementation_manifest_digest = _load_implementation_manifest(
        root, profile
    )
    if (
        bundle["exporter"]["implementation_manifest_digest"]
        != implementation_manifest_digest
        or bundle["exporter"]["implementation_digest"]
        != implementation["implementation_digest"]
    ):
        _reject(
            "exporter-digest",
            "$.exporter",
            "bundle does not bind the current complete exporter implementation",
        )
    fixture_provenance = bundle["fixture_provenance"]
    trust_digests = {
        item["path"]: item["digest"] for item in implementation["test_trust_artifacts"]
    }
    if mode == TEST_FIXTURE_MODE:
        if not isinstance(fixture_provenance, dict) or fixture_provenance.get(
            "fixture_catalog_digest"
        ) != trust_digests.get(FIXTURE_CATALOG_PATH.as_posix()):
            _reject(
                "fixture-provenance",
                "$.fixture_provenance",
                "test-only bundle does not bind the authorized fixture catalog",
            )
    elif fixture_provenance is not None:
        _reject(
            "fixture-provenance",
            "$.fixture_provenance",
            "candidate bundle must not claim synthetic fixture provenance",
        )
    if bundle["review_subject_digest"] not in {
        item.get("reviewed_subject_digest")
        for item in bundle["review_provenance"]
        if isinstance(item, dict)
    }:
        _reject(
            "review-subject",
            "$.review_provenance",
            "review provenance does not bind the bundle review subject",
        )
    provenance = bundle["review_provenance"]
    by_scope = {item["scope"]: item for item in provenance if isinstance(item, dict)}
    if set(by_scope) != set(REVIEW_SCOPES.values()) or len(provenance) != len(by_scope):
        _reject(
            "review-scope",
            "$.review_provenance",
            "all review scopes must occur exactly once",
        )
    expected_role = (
        "authorized-human" if mode == EXPORT_CANDIDATE_MODE else "synthetic-reviewer"
    )
    for scope, item in by_scope.items():
        if (
            item["reviewed_subject_digest"] != bundle["review_subject_digest"]
            or item["reviewer_role"] != expected_role
        ):
            _reject(
                "review-provenance",
                f"$.review_provenance.{scope}",
                "review provenance subject or role does not match",
            )
    expected_publication = "candidate" if mode == EXPORT_CANDIDATE_MODE else "test-only"
    expected_approval = (
        "required-not-provided"
        if mode == EXPORT_CANDIDATE_MODE
        else "not-applicable-test-only"
    )
    if (
        bundle["publication"]["status"] != expected_publication
        or bundle["review_requirements"]["final_publication_approval"]
        != expected_approval
    ):
        _reject(
            "publication-mode",
            "$.publication",
            "publication state does not match the artifact mode",
        )
    evidence = bundle["evidence_record"]
    report = bundle["sanitization_report"]
    if (
        report["input_status"] != report["output_status"]
        or report["output_status"] != evidence.get("status")
        or report["output_lifecycle"] != evidence.get("lifecycle")
    ):
        _reject(
            "status-preservation",
            "$.sanitization_report",
            "status or lifecycle preservation evidence does not match",
        )
    if bundle["digest_bindings"]["exported_evidence_record_digest"] != domain_digest(
        EXPORTED_EVIDENCE_DOMAIN, evidence
    ):
        _reject(
            "evidence-digest",
            "$.digest_bindings.exported_evidence_record_digest",
            "exported Evidence digest does not match",
        )
    if (
        evidence.get("status") not in profile["status_preservation"]["allowed"]
        or evidence.get("lifecycle") != "sanitized"
    ):
        _reject(
            "lifecycle-limit",
            "$.evidence_record",
            "bundle Evidence status or lifecycle is invalid",
        )
    _validate_evidence(evidence, root, "$.evidence_record")
    if validate_export_configuration(
        evidence, "$.evidence_record.configuration", root, profile
    ):
        _reject(
            "configuration-contract",
            "$.evidence_record.configuration",
            "bundle configuration violates its closed type-specific contract",
        )
    _scan_sensitive_values({"evidence_record": evidence})


def export_candidate(
    candidate: Any,
    profile: dict[str, Any],
    root: Path,
    *,
    mode: str = EXPORT_CANDIDATE_MODE,
    input_name: Path | None = None,
) -> dict[str, Any]:
    if not isinstance(candidate, dict):
        _reject("candidate-shape", "$", "candidate root must be an object")
    _validate_lifecycle_precondition(candidate, profile)
    candidate_schema = _load_schema(root, "evidence-export-candidate.v0.1.schema.json")
    _validate_schema(candidate, candidate_schema, code="candidate-schema")
    catalog, fixture_catalog_digest = _load_fixture_catalog(root)
    _validate_allowlist(candidate, profile, root)
    _validate_evidence(candidate["evidence_record"], root, "$.evidence_record")
    _validate_bindings(candidate, profile)
    _scan_sensitive_values(candidate)
    _validate_reviews(candidate, mode, catalog)
    fixture_entry = _validate_execution_mode(candidate, mode, catalog, input_name)
    evidence, omissions = _construct_evidence(candidate, profile)
    _validate_evidence(evidence, root, "$.evidence_record")
    implementation, implementation_manifest_digest = _load_implementation_manifest(
        root, profile
    )
    bundle = _construct_bundle(
        candidate,
        profile,
        evidence,
        omissions,
        implementation,
        implementation_manifest_digest,
        fixture_entry,
        fixture_catalog_digest,
    )
    validate_public_bundle(bundle, root, profile, mode=mode)
    return bundle


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.tmp"
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _read_bounded_regular(path: Path, limit: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                _reject("path-type", "$.input", "input must be one regular file")
            if metadata.st_size > limit:
                _reject(
                    "input-size", "$.input", "input exceeds the configured size limit"
                )
            payload = stream.read(limit + 1)
    except ExportError:
        raise
    except OSError as error:
        raise ExportError(
            "input-read", "$.input", "input file could not be read"
        ) from error
    if len(payload) > limit:
        _reject("input-size", "$.input", "input exceeds the configured size limit")
    return payload


def run_export(
    *,
    root: Path,
    staging_root: Path,
    input_name: Path,
    profile_name: Path,
    output_dir: Path,
    mode: str = EXPORT_CANDIDATE_MODE,
) -> tuple[Path, dict[str, Any]]:
    root = root.resolve()
    if mode == TEST_FIXTURE_MODE and staging_root != FIXTURE_STAGING_ROOT:
        _reject(
            "fixture-root",
            "$.staging_root",
            "test mode is restricted to the committed fixture staging root",
        )
    input_path = resolve_input_path(root, staging_root, input_name)
    profile_path = resolve_profile_path(root, profile_name)
    output_root = resolve_output_dir(root, output_dir)
    profile = _load_profile(profile_path)
    limit = profile["path_policy"]["maximum_input_bytes"]
    raw = _read_bounded_regular(input_path, limit)
    try:
        candidate = strict_loads(raw, max_bytes=limit)
    except CanonicalJSONError as error:
        raise ExportError("input-parse", "$.input", str(error)) from error
    bundle = export_candidate(
        candidate, profile, root, mode=mode, input_name=input_name
    )
    payload = canonicalize(bundle) + b"\n"
    output_path = output_root / OUTPUT_FILENAME
    try:
        _atomic_write(output_path, payload)
    except OSError as error:
        raise ExportError(
            "output-write", "$.output_dir", "output could not be written atomically"
        ) from error
    return output_path, bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument(
        "--staging-root", type=Path, default=Path("staging/evidence-export")
    )
    parser.add_argument(
        "--mode",
        choices=(EXPORT_CANDIDATE_MODE, TEST_FIXTURE_MODE),
        default=EXPORT_CANDIDATE_MODE,
        help="trusted caller mode; test-fixture is limited to the committed catalog",
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument(
        "--profile",
        type=Path,
        default=Path("profiles/public-evidence-export.v0.1.json"),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        output_path, bundle = run_export(
            root=args.root,
            staging_root=args.staging_root,
            input_name=args.input,
            profile_name=args.profile,
            output_dir=args.output_dir,
            mode=args.mode,
        )
    except ExportError as error:
        print(error, file=sys.stderr)
        return 1
    print(
        "export: "
        f"status={bundle['publication']['status']} "
        f"lifecycle={bundle['evidence_record']['lifecycle']} output={output_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
