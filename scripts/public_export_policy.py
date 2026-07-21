#!/usr/bin/env python3
"""Shared fail-closed policy for public Evidence export artifacts."""

from __future__ import annotations

import base64
import dataclasses
import ipaddress
from pathlib import Path
import re
from typing import Any, Iterable
import unicodedata
from urllib.parse import unquote, urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

try:
    from canonical_json import CanonicalJSONError, domain_digest, strict_loads
except ImportError:  # pragma: no cover - package import during unit tests
    from scripts.canonical_json import CanonicalJSONError, domain_digest, strict_loads


PROFILE_DOMAIN = "private-match-evidence-export-profile/v0.1"
PROFILE_PATH = Path("profiles/public-evidence-export.v0.1.json")
PROFILE_SCHEMA_PATH = Path("schema/evidence-export-profile.v0.1.schema.json")
SUPPORTED_PROFILE_ID = "private-match-public-evidence-export"
SUPPORTED_PROFILE_VERSION = "0.1"
EXPORT_CANDIDATE_MODE = "export-candidate"
TEST_FIXTURE_MODE = "test-fixture"
PROGRAMMATIC_INTERFACE = "programmatic"
STAGED_FILE_INTERFACE = "staged-file"
OPAQUE_CANDIDATE_ID = re.compile(r"^PM-EXPORT-CANDIDATE-[0-9A-F]{32}$")
SYNTHETIC_CANDIDATE_ID = re.compile(r"^PM-EXPORT-CANDIDATE-[A-Z0-9-]{4,64}$")


class PublicExportPolicyError(ValueError):
    """A value-free, stable public-export policy failure."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclasses.dataclass(frozen=True)
class PublicStringFinding:
    path: str
    category: str


def compute_profile_digest(profile: dict[str, Any]) -> str:
    material = dict(profile)
    material.pop("profile_digest", None)
    return domain_digest(PROFILE_DOMAIN, material)


def _safe_repository_file(
    root: Path,
    candidate: Path,
    *,
    code: str,
) -> Path:
    root = root.resolve()
    if not candidate.is_absolute() and (not candidate.parts or ".." in candidate.parts):
        raise PublicExportPolicyError(code, "repository file path is invalid")
    path = candidate if candidate.is_absolute() else root / candidate
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise PublicExportPolicyError(
            code, "repository file is outside root"
        ) from error
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise PublicExportPolicyError(code, "repository file uses a symlink")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise PublicExportPolicyError(code, "repository file is unavailable") from error
    if not resolved.is_file():
        raise PublicExportPolicyError(code, "repository file is not regular")
    return resolved


def load_required_export_profile(
    root: Path,
    profile_path: Path = PROFILE_PATH,
) -> dict[str, Any]:
    """Load the supported profile from one safe repository file."""

    path = _safe_repository_file(root, profile_path, code="export-profile-required")
    try:
        raw = path.read_bytes()
        profile = strict_loads(raw, max_bytes=262_144)
    except (OSError, CanonicalJSONError) as error:
        raise PublicExportPolicyError(
            "export-profile-parse", "export profile is not strict UTF-8 JSON"
        ) from error

    schema_path = _safe_repository_file(
        root, PROFILE_SCHEMA_PATH, code="export-profile-schema"
    )
    try:
        schema = strict_loads(schema_path.read_bytes(), max_bytes=1_048_576)
        Draft202012Validator.check_schema(schema)
        errors = list(
            Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(
                profile
            )
        )
    except (OSError, CanonicalJSONError, SchemaError, TypeError, ValueError) as error:
        raise PublicExportPolicyError(
            "export-profile-schema", "export profile Schema is invalid"
        ) from error
    if errors or not isinstance(profile, dict):
        raise PublicExportPolicyError(
            "export-profile-schema", "export profile violates its Schema"
        )
    if (
        profile.get("profile_id") != SUPPORTED_PROFILE_ID
        or profile.get("profile_version") != SUPPORTED_PROFILE_VERSION
    ):
        raise PublicExportPolicyError(
            "export-profile-schema", "export profile ID or version is unsupported"
        )
    if profile.get("profile_digest") != compute_profile_digest(profile):
        raise PublicExportPolicyError(
            "export-profile-digest", "export profile digest does not match"
        )
    return profile


def candidate_identifier_is_valid(identifier: Any, mode: str) -> bool:
    if not isinstance(identifier, str):
        return False
    if mode == EXPORT_CANDIDATE_MODE:
        return OPAQUE_CANDIDATE_ID.fullmatch(identifier) is not None
    if mode == TEST_FIXTURE_MODE:
        return SYNTHETIC_CANDIDATE_ID.fullmatch(identifier) is not None
    return False


def expected_sanitization_checks(
    profile: dict[str, Any], mode: str, input_interface: str
) -> list[str]:
    """Derive the exact reviewed check set for a closed execution context."""

    contract = profile.get("required_sanitization_checks")
    if not isinstance(contract, dict):
        return []
    checks = list(contract.get("common", []))
    if input_interface == STAGED_FILE_INTERFACE:
        checks.extend(contract.get("file-interface", []))
    elif input_interface != PROGRAMMATIC_INTERFACE:
        return []
    if mode == TEST_FIXTURE_MODE:
        checks.extend(contract.get("test-fixture", []))
    elif mode != EXPORT_CANDIDATE_MODE:
        return []
    return sorted(set(checks))


def _iter_string_leaves(value: Any, path: str = "$") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_string_leaves(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_string_leaves(child, f"{path}[{index}]")
    elif isinstance(value, str):
        yield path, value


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
        r"\[?[0-9a-fA-F:.]+\]?|[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+|localhost",
        stripped,
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


def sensitive_value_class(value: str) -> str | None:
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


def scan_public_strings(value: Any, path: str = "$") -> list[PublicStringFinding]:
    findings: list[PublicStringFinding] = []
    for leaf_path, leaf in _iter_string_leaves(value, path):
        category = sensitive_value_class(leaf)
        if category is not None:
            findings.append(PublicStringFinding(leaf_path, category))
    return findings
