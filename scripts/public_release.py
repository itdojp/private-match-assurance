#!/usr/bin/env python3
"""Fixture-first signed public Assurance release construction and verification."""

from __future__ import annotations

import base64
from contextlib import contextmanager
import copy
import datetime as dt
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
from typing import Any, Iterable

from jsonschema import Draft202012Validator

try:
    from ae_assurance_common import (
        atomic_write_file,
        build_schema_registry,
        canonical_json_bytes,
        read_strict_json,
        resolve_new_directory,
        resolve_regular_file,
        resolve_trusted_directory,
        validate_relative_path,
        validate_schema_instance,
    )
    from canonical_json import canonicalize, domain_digest, file_digest, strict_loads
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import (
        atomic_write_file,
        build_schema_registry,
        canonical_json_bytes,
        read_strict_json,
        resolve_new_directory,
        resolve_regular_file,
        resolve_trusted_directory,
        validate_relative_path,
        validate_schema_instance,
    )
    from scripts.canonical_json import (
        canonicalize,
        domain_digest,
        file_digest,
        strict_loads,
    )


SCHEMA_VERSION = "0.1"
ARTIFACT_STATUS = "test-only"
MODE = "fixture-test"
RELEASE_PAYLOAD_TYPE = (
    "application/vnd.itdo.private-match.assurance-release-manifest.v0.1+json"
)
STATUS_PAYLOAD_TYPE = (
    "application/vnd.itdo.private-match.assurance-release-status-set.v0.1+json"
)
ALGORITHM = "ed25519-rfc8032"
TRUST_DOMAIN = "itdo-private-match-assurance-fixture-v0.1"
RELEASE_KEY_ID = (
    "sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9"
)
STATUS_KEY_ID = (
    "sha256:deb2ded39dc26fce0e6085b6fc34bf6b5941913bbfe2ea614113cff9e004c170"
)
RELEASE_ID = "private-match-assurance-fixture-release-0.1.0"
BUNDLE_ID = "PMA-PUBLIC-RELEASE-FIXTURE-V0-1"
FIXTURE_ID = "PUBLIC-RELEASE-IMMUTABLE-V0-1"

CREATED_AT = "2026-08-01T00:00:00Z"
VALID_FROM = "2026-08-01T00:00:00Z"
VALID_UNTIL = "2027-08-01T00:00:00Z"
VERIFICATION_TIME = "2026-08-04T00:00:00Z"

STANDARDS_PATH = "config/public-release-signing-standards.v0.1.json"
SIGNING_PROFILE_PATH = "profiles/public-release-signing.v0.1.json"
VERIFICATION_PROFILE_PATH = "profiles/public-release-verification.v0.1.json"
TRUST_ROOT_PATH = "tests/fixtures/public-release/trust/fixture-trust-root.v0.1.json"
FIXTURE_CATALOG_PATH = "tests/fixtures/public-release/fixture-catalog.v0.1.json"
EXPECTED_FIXTURE_ROOT_PATH = "tests/fixtures/public-release/expected"
EXPECTED_BUNDLE_PATH = f"{EXPECTED_FIXTURE_ROOT_PATH}/bundle"
EXPECTED_STATUS_CHAINS_PATH = f"{EXPECTED_FIXTURE_ROOT_PATH}/status-chains"
EXPECTED_VERIFICATION_RESULTS_PATH = (
    f"{EXPECTED_FIXTURE_ROOT_PATH}/verification-results"
)
IMPLEMENTATION_MANIFEST_PATH = (
    "manifests/public-release-verifier-implementation.v0.1.json"
)
FIXTURE_PRIVATE_KEY_PATHS = (
    "tests/fixtures/public-release/keys/release-private.pem",
    "tests/fixtures/public-release/keys/status-private.pem",
)

MANIFEST_PATH = "manifest/public-release-bundle-manifest.v0.1.json"
RELEASE_ENVELOPE_PATH = "signatures/public-release-manifest.dsse.v0.1.json"
STATUS_SET_FILENAME = "public-release-status-set.v0.1.json"
STATUS_ENVELOPE_FILENAME = "public-release-status-set.dsse.v0.1.json"
STATUS_SET_PATH = f"revisions/0001/{STATUS_SET_FILENAME}"
STATUS_ENVELOPE_PATH = f"revisions/0001/{STATUS_ENVELOPE_FILENAME}"
STATUS_CHAIN_MANIFEST_PATH = (
    "chain-manifest/public-release-status-chain-manifest.v0.1.json"
)
STATUS_CHAIN_OUTPUT_SET_PATH = "public-release-status-chain-output-set.v0.1.json"
STATIC_REPORT_JSON_PATH = "reports/public-release-content-report.v0.1.json"
STATIC_REPORT_MD_PATH = "reports/public-release-content-report.v0.1.md"
VERIFICATION_RESULT_JSON_FILENAME = "public-release-verification-result.v0.1.json"
VERIFICATION_RESULT_MD_FILENAME = "public-release-verification-result.v0.1.md"
# Backwards-compatible source aliases inside this Draft branch. Both now name
# immutable static content and are never verifier-output destinations.
REPORT_JSON_PATH = STATIC_REPORT_JSON_PATH
REPORT_MD_PATH = STATIC_REPORT_MD_PATH
OUTPUT_SET_PATH = "public-release-output-set.v0.1.json"

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_BUNDLE_FILE_BYTES = 8 * 1024 * 1024
MAX_BUNDLE_FILES = 128
MAX_CRYPTO_OUTPUT_BYTES = 64 * 1024
CRYPTO_TIMEOUT_SECONDS = 10

MANIFEST_DOMAIN = "private-match-public-release-manifest/v0.1"
CONTENT_TREE_DOMAIN = "private-match-public-release-content-tree/v0.1"
RECORD_SET_DOMAIN = "private-match-public-release-record-set/v0.1"
STATUS_ENTRY_DOMAIN = "private-match-public-release-status-entry/v0.1"
STATUS_ENTRY_SET_DOMAIN = "private-match-public-release-status-entry-set/v0.1"
STATUS_SET_DOMAIN = "private-match-public-release-status-set/v0.1"
STATUS_CHAIN_TREE_DOMAIN = "private-match-public-release-status-chain-tree/v0.1"
STATUS_CHAIN_MANIFEST_DOMAIN = "private-match-public-release-status-chain-manifest/v0.1"
STATUS_CHAIN_OUTPUT_SET_DOMAIN = (
    "private-match-public-release-status-chain-output-set/v0.1"
)
TRUST_ROOT_DOMAIN = "private-match-public-release-trust-root/v0.1"
REPORT_MODEL_DOMAIN = "private-match-public-release-report-model/v0.1"
VERIFICATION_RESULT_DOMAIN = "private-match-public-release-verification-result/v0.1"
OUTPUT_SET_DOMAIN = "private-match-public-release-output-set/v0.1"
PROFILE_DOMAIN = "private-match-public-release-profile/v0.1"
STANDARDS_DOMAIN = "private-match-public-release-signing-standards/v0.1"
FIXTURE_CATALOG_DOMAIN = "private-match-public-release-fixture-catalog/v0.1"
IMPLEMENTATION_DOMAIN = "private-match-public-release-verifier-implementation/v0.1"

RELEASE_LIMITATIONS = [
    "Synthetic fixture data and fixture keys do not establish a Product release.",
    "Signature validity establishes origin and integrity only relative to the supplied trust root; it is not security certification.",
    "The supplied fixture trust root is an external verifier input whose authenticity is not established by the bundle.",
    "No trusted timestamp or transparency log is used; compromise revocation applies conservatively to all signatures under the affected key.",
    "The verifier validates the complete supplied status chain but cannot prove that it is the globally latest distributed revision.",
    "Production signing, key custody, publication approval, and automated publication are unsupported in Draft 0.1.",
]

STATUS_CHAIN_VARIANTS = {
    "active": {
        "latest_revision": 1,
        "key_status": "active",
        "release_state": "active",
        "expected_overall": "verified-fixture-with-limitations",
        "expected_exit_code": 0,
    },
    "revoked": {
        "latest_revision": 2,
        "key_status": "revoked",
        "release_state": "active",
        "expected_overall": "revoked-key",
        "expected_exit_code": 3,
    },
    "withdrawn": {
        "latest_revision": 2,
        "key_status": "active",
        "release_state": "withdrawn",
        "expected_overall": "withdrawn-release",
        "expected_exit_code": 4,
    },
    "superseded": {
        "latest_revision": 2,
        "key_status": "active",
        "release_state": "superseded",
        "expected_overall": "superseded-release",
        "expected_exit_code": 4,
    },
    "corrected": {
        "latest_revision": 2,
        "key_status": "active",
        "release_state": "corrected",
        "expected_overall": "corrected-release",
        "expected_exit_code": 4,
    },
    "expired": {
        "latest_revision": 2,
        "key_status": "active",
        "release_state": "expired",
        "expected_overall": "expired-release",
        "expected_exit_code": 4,
    },
}

CLAIM_RESULT_VALUES = (
    "supported",
    "supported-with-assumptions",
    "not-supported",
    "not-evaluated",
    "invalid-reference",
)
CLAIM_EVALUATION_POLICY = {
    "verification_time_applies_to_claim_validity": True,
    "claim_validity_interval": "inclusive",
    "positive_claim_assumption_contract": {
        "supported": {"minimum_assumptions": 0, "maximum_assumptions": 0},
        "supported-with-assumptions": {"minimum_assumptions": 1},
    },
    "positive_evidence_statuses": ["pass"],
    "supporting_evidence_lifecycles": [
        "collected",
        "validated",
        "sanitized",
        "published",
    ],
    "non_supporting_evidence_lifecycles": ["superseded", "withdrawn"],
    "supporting_assumption_statuses": ["active"],
    "invalidated_assumption_result": "not-supported",
    "expired_assumption_result": "not-evaluated",
}
OVERALL_VALUES = (
    "verified-fixture",
    "verified-fixture-with-limitations",
    "invalid-signature",
    "untrusted-key",
    "revoked-key",
    "unsupported-algorithm",
    "invalid-structure",
    "incomplete-bundle",
    "invalid-report-linkage",
    "withdrawn-release",
    "superseded-release",
    "corrected-release",
    "expired-release",
    "claims-not-supported",
    "not-evaluated",
)

PUBLIC_RELEASE_SCHEMAS = {
    "standards": "schema/public-release-signing-standards.v0.1.schema.json",
    "signing_profile": "schema/public-release-signing-profile.v0.1.schema.json",
    "verification_profile": "schema/public-release-verification-profile.v0.1.schema.json",
    "trust_root": "schema/public-release-trust-root.v0.1.schema.json",
    "status_entry": "schema/public-release-status-entry.v0.1.schema.json",
    "status_set": "schema/public-release-status-set.v0.1.schema.json",
    "status_chain_manifest": (
        "schema/public-release-status-chain-manifest.v0.1.schema.json"
    ),
    "status_chain_output_set": (
        "schema/public-release-status-chain-output-set.v0.1.schema.json"
    ),
    "dsse": "schema/public-release-dsse-envelope.v0.1.schema.json",
    "manifest": "schema/public-release-bundle-manifest.v0.1.schema.json",
    "output_set": "schema/public-release-output-set.v0.1.schema.json",
    "content_report": "schema/public-release-content-report.v0.1.schema.json",
    "verification_result": (
        "schema/public-release-verification-result.v0.1.schema.json"
    ),
    "fixture_catalog": "schema/public-release-fixture-catalog.v0.1.schema.json",
    "implementation": (
        "schema/public-release-verifier-implementation.v0.1.schema.json"
    ),
}
A1_SCHEMAS = {
    "claim": "schema/claim.schema.json",
    "assumption": "schema/assumption.schema.json",
    "evidence": "schema/evidence-item.schema.json",
    "known-limitation": "schema/known-limitation.schema.json",
}


class PublicReleaseError(ValueError):
    """A bounded, value-free public-release contract failure."""


class VerificationFailure(PublicReleaseError):
    """A stable verifier classification with no untrusted diagnostic text."""

    def __init__(self, status: str, exit_code: int, reason_code: str) -> None:
        super().__init__(reason_code)
        self.status = status
        self.exit_code = exit_code
        self.reason_code = reason_code


def detached_digest(domain: str, value: dict[str, Any], field: str) -> str:
    material = copy.deepcopy(value)
    material.pop(field, None)
    return domain_digest(domain, material)


def detached_jcs_sha256(value: dict[str, Any], field: str) -> str:
    """SHA-256 over exact RFC 8785 bytes with one detached digest field absent."""

    material = copy.deepcopy(value)
    material.pop(field, None)
    return file_digest(canonicalize(material))


def parse_timestamp(value: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise PublicReleaseError("timestamp is not canonical UTC")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise PublicReleaseError("timestamp is invalid") from error
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise PublicReleaseError("timestamp is not canonical UTC")
    return parsed


def load_public_release_schemas(root: Path) -> dict[str, dict[str, Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    for name, relative in {**PUBLIC_RELEASE_SCHEMAS, **A1_SCHEMAS}.items():
        value = read_strict_json(resolve_regular_file(root, relative))
        if not isinstance(value, dict):
            raise PublicReleaseError("Schema is not an object")
        try:
            Draft202012Validator.check_schema(value)
        except Exception as error:
            raise PublicReleaseError("Schema is invalid") from error
        schemas[name] = value
    return schemas


def validate_named_schema(
    value: Any,
    name: str,
    schemas: dict[str, dict[str, Any]],
) -> None:
    registry = build_schema_registry(schemas.values())
    try:
        validate_schema_instance(value, schemas[name], registry=registry)
    except Exception as error:
        raise PublicReleaseError(
            "artifact does not match its reviewed Schema"
        ) from error


def _profile_digest(value: dict[str, Any]) -> str:
    return detached_digest(PROFILE_DOMAIN, value, "profile_digest")


def load_release_authority(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    schemas = load_public_release_schemas(root)
    standards = read_strict_json(resolve_regular_file(root, STANDARDS_PATH))
    signing = read_strict_json(resolve_regular_file(root, SIGNING_PROFILE_PATH))
    verification = read_strict_json(
        resolve_regular_file(root, VERIFICATION_PROFILE_PATH)
    )
    if not all(isinstance(value, dict) for value in (standards, signing, verification)):
        raise PublicReleaseError("release authority is invalid")
    validate_named_schema(standards, "standards", schemas)
    validate_named_schema(signing, "signing_profile", schemas)
    validate_named_schema(verification, "verification_profile", schemas)
    if standards.get("standards_digest") != detached_digest(
        STANDARDS_DOMAIN, standards, "standards_digest"
    ):
        raise PublicReleaseError("signing standards digest is invalid")
    for profile in (signing, verification):
        if profile.get("profile_digest") != _profile_digest(profile):
            raise PublicReleaseError("release profile digest is invalid")
    if (
        signing.get("artifact_status") != ARTIFACT_STATUS
        or signing.get("mode") != MODE
        or signing.get("algorithm") != ALGORITHM
        or signing.get("trust_domain_id") != TRUST_DOMAIN
        or signing.get("release_manifest_payload_type") != RELEASE_PAYLOAD_TYPE
        or signing.get("release_status_payload_type") != STATUS_PAYLOAD_TYPE
        or signing.get("production_signing") != "unsupported"
        or signing.get("automation_permitted") is not False
        or verification.get("overall_status_vocabulary") != list(OVERALL_VALUES)
        or verification.get("claim_result_vocabulary") != list(CLAIM_RESULT_VALUES)
        or verification.get("claim_evaluation_policy") != CLAIM_EVALUATION_POLICY
    ):
        raise PublicReleaseError("release profile authority is unsupported")
    return standards, signing, verification


def validate_fixture_private_key_boundary(root: Path) -> None:
    """Confine PEM fixture private material to the two reviewed fixture paths."""

    _, signing, _ = load_release_authority(root)
    configured = signing.get("fixture_key_paths", {})
    if (
        configured.get("release_private") != FIXTURE_PRIVATE_KEY_PATHS[0]
        or configured.get("status_private") != FIXTURE_PRIVATE_KEY_PATHS[1]
    ):
        raise PublicReleaseError("fixture private-key catalog is invalid")
    excluded = {
        ".git",
        ".venv",
        ".codex-local",
        ".worktrees",
        "node_modules",
        "__pycache__",
    }
    found: set[str] = set()
    for path in root.rglob("*"):
        if any(part in excluded for part in path.relative_to(root).parts):
            continue
        if path.is_symlink() or not path.is_file():
            continue
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise PublicReleaseError("fixture private-key scan failed") from error
        if (
            b"-----BEGIN PRIVATE KEY-----\n" in raw
            and b"\n-----END PRIVATE KEY-----" in raw
        ):
            found.add(path.relative_to(root).as_posix())
    if found != set(FIXTURE_PRIVATE_KEY_PATHS):
        raise PublicReleaseError(
            "fixture private-key material is outside its allowlist"
        )


def _controlled_environment(root: Path) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str((root / ".codex-local" / "tmp" / "public-release-home").resolve()),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "NO_COLOR": "1",
    }
    return env


def resolve_external_regular_file(path: Path) -> Path:
    """Resolve one explicit file without accepting a symlink in its path."""

    parent = resolve_trusted_directory(path.parent)
    return resolve_regular_file(parent, path.name, max_bytes=MAX_BUNDLE_FILE_BYTES)


def atomic_write_new_output(path: Path, data: bytes) -> Path:
    """Atomically create a new output below an existing non-symlink directory."""

    target: Path | None = None
    try:
        parent = resolve_trusted_directory(path.parent)
        target = parent / path.name
        if os.path.lexists(target):
            raise PublicReleaseError("output target already exists")
        atomic_write_file(target, data)
    except Exception as error:
        if target is not None:
            target.unlink(missing_ok=True)
            target.with_name(target.name + ".partial").unlink(missing_ok=True)
        raise PublicReleaseError("output write failed") from error
    return target


def create_public_release_process_scratch(root: Path) -> Path:
    """Create one private scratch directory below a verified local hierarchy."""

    trusted_root = resolve_trusted_directory(root)
    current = trusted_root
    for name in (".codex-local", "tmp"):
        child = current / name
        if os.path.lexists(child):
            try:
                mode = child.lstat().st_mode
            except OSError as error:
                raise PublicReleaseError("scratch hierarchy is unavailable") from error
            if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
                raise PublicReleaseError("scratch hierarchy is not trusted")
        else:
            try:
                child.mkdir(mode=0o700)
            except OSError as error:
                raise PublicReleaseError("scratch hierarchy creation failed") from error
        current = child
    try:
        process = Path(tempfile.mkdtemp(prefix="public-release-", dir=current))
        process.chmod(0o700)
        mode = process.lstat().st_mode
    except OSError as error:
        raise PublicReleaseError("process scratch creation failed") from error
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        shutil.rmtree(process, ignore_errors=True)
        raise PublicReleaseError("process scratch is not trusted")
    if os.name == "posix" and stat.S_IMODE(mode) & 0o077:
        shutil.rmtree(process, ignore_errors=True)
        raise PublicReleaseError("process scratch permissions are not private")
    return process


@contextmanager
def public_release_process_scratch(root: Path) -> Iterable[Path]:
    """Yield one process-owned scratch directory and remove it on every exit."""

    process = create_public_release_process_scratch(root)
    try:
        yield process
    finally:
        shutil.rmtree(process, ignore_errors=True)


def _node_executable() -> str:
    candidate = shutil.which("node")
    if not candidate:
        raise PublicReleaseError("pinned Node runtime is unavailable")
    try:
        resolved = subprocess.run(
            [candidate, "-p", "process.execPath"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
            shell=False,
            check=False,
            env=os.environ.copy(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PublicReleaseError("pinned Node runtime is unavailable") from error
    if resolved.returncode != 0 or len(resolved.stdout) > 4096:
        raise PublicReleaseError("pinned Node runtime is unavailable")
    path = Path(resolved.stdout.decode("utf-8", errors="strict").strip())
    if not path.is_absolute() or not path.is_file():
        raise PublicReleaseError("pinned Node runtime is unavailable")
    version = subprocess.run(
        [str(path), "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        shell=False,
        check=False,
        env=_controlled_environment(Path.cwd()),
    )
    if version.returncode != 0 or version.stdout.strip() != b"v22.22.2":
        raise PublicReleaseError("pinned Node runtime is unavailable")
    return str(path)


def _run_crypto(
    root: Path,
    operation: str,
    value: dict[str, Any] | None = None,
    usage: str | None = None,
) -> dict[str, Any]:
    script = resolve_regular_file(root, "scripts/public_release_crypto.mjs")
    command = [_node_executable()]
    command.extend([str(script), operation])
    if usage:
        command.append(usage)
    data = b"" if value is None else canonical_json_bytes(value)
    try:
        result = subprocess.run(
            command,
            cwd=root,
            env=_controlled_environment(root),
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=CRYPTO_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PublicReleaseError("fixture crypto operation failed") from error
    if (
        result.returncode != 0
        or len(result.stdout) > MAX_CRYPTO_OUTPUT_BYTES
        or len(result.stderr) > MAX_CRYPTO_OUTPUT_BYTES
    ):
        raise PublicReleaseError("fixture crypto operation failed")
    try:
        output = strict_loads(result.stdout, max_bytes=MAX_CRYPTO_OUTPUT_BYTES)
    except ValueError as error:
        raise PublicReleaseError("fixture crypto output is invalid") from error
    if not isinstance(output, dict):
        raise PublicReleaseError("fixture crypto output is invalid")
    return output


def verify_rfc8032_vector(root: Path) -> dict[str, Any]:
    result = _run_crypto(root, "rfc8032-test")
    if result != {
        "algorithm": ALGORITHM,
        "vectors": ["RFC8032-7.1-TEST-1", "RFC8032-7.1-TEST-2"],
        "verified": True,
    }:
        raise PublicReleaseError("RFC 8032 vector validation failed")
    return result


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    if not isinstance(payload_type, str) or not payload_type:
        raise PublicReleaseError("DSSE payload type is invalid")
    try:
        type_bytes = payload_type.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise PublicReleaseError("DSSE payload type is invalid") from error
    return b"".join(
        [
            b"DSSEv1 ",
            str(len(type_bytes)).encode("ascii"),
            b" ",
            type_bytes,
            b" ",
            str(len(payload)).encode("ascii"),
            b" ",
            payload,
        ]
    )


def sign_fixture_dsse(
    root: Path,
    payload_type: str,
    payload: bytes,
    usage: str,
) -> dict[str, Any]:
    expected_payload_type = {
        "release-signing": RELEASE_PAYLOAD_TYPE,
        "release-status-signing": STATUS_PAYLOAD_TYPE,
    }.get(usage)
    if expected_payload_type != payload_type:
        raise PublicReleaseError("fixture key usage is not permitted")
    expected_key = RELEASE_KEY_ID if usage == "release-signing" else STATUS_KEY_ID
    result = _run_crypto(
        root,
        "sign-fixture",
        {
            "artifact_status": ARTIFACT_STATUS,
            "payload": base64.b64encode(payload).decode("ascii"),
            "payload_type": payload_type,
            "usage": usage,
        },
        usage,
    )
    if (
        result.get("algorithm") != ALGORITHM
        or result.get("keyid") != expected_key
        or not isinstance(result.get("sig"), str)
    ):
        raise PublicReleaseError("fixture signature authority is invalid")
    envelope = {
        "payload": base64.b64encode(payload).decode("ascii"),
        "payloadType": payload_type,
        "signatures": [{"keyid": result["keyid"], "sig": result["sig"]}],
        "signingProfile": {
            "id": "private-match-public-release-signing",
            "version": SCHEMA_VERSION,
            "algorithm": ALGORITHM,
        },
    }
    return envelope


def _strict_base64(value: Any) -> bytes:
    if not isinstance(value, str):
        raise PublicReleaseError("base64 value is invalid")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise PublicReleaseError("base64 value is invalid") from error
    if base64.b64encode(decoded).decode("ascii") != value:
        raise PublicReleaseError("base64 value is not canonical")
    return decoded


def verify_dsse_signature(
    root: Path,
    envelope: dict[str, Any],
    payload_type: str,
    trust_key: dict[str, Any],
) -> bytes:
    if (
        envelope.get("payloadType") != payload_type
        or envelope.get("signingProfile")
        != {
            "id": "private-match-public-release-signing",
            "version": SCHEMA_VERSION,
            "algorithm": ALGORITHM,
        }
        or not isinstance(envelope.get("signatures"), list)
        or len(envelope["signatures"]) != 1
    ):
        raise PublicReleaseError("DSSE envelope profile is unsupported")
    signature = envelope["signatures"][0]
    if (
        not isinstance(signature, dict)
        or set(signature) != {"keyid", "sig"}
        or signature.get("keyid") != trust_key.get("key_id")
    ):
        raise PublicReleaseError("DSSE signing key is not trusted")
    payload = _strict_base64(envelope.get("payload"))
    signature_bytes = _strict_base64(signature.get("sig"))
    if len(signature_bytes) != 64:
        raise PublicReleaseError("DSSE signature is invalid")
    result = _run_crypto(
        root,
        "verify",
        {
            "algorithm": trust_key.get("algorithm"),
            "payload": envelope["payload"],
            "payload_type": payload_type,
            "public_key_spki": trust_key.get("public_key"),
            "signature": signature["sig"],
        },
    )
    if (
        result.get("keyid") != trust_key.get("key_id")
        or result.get("verified") is not True
    ):
        raise PublicReleaseError("DSSE signature is invalid")
    return payload


def _public_key_der(root: Path, role: str) -> bytes:
    pem = resolve_regular_file(
        root, f"tests/fixtures/public-release/keys/{role}-public.pem", max_bytes=4096
    ).read_bytes()
    lines = [line for line in pem.splitlines() if not line.startswith(b"-----")]
    try:
        return base64.b64decode(b"".join(lines), validate=True)
    except ValueError as error:
        raise PublicReleaseError("fixture public key is malformed") from error


def build_fixture_trust_root(root: Path) -> dict[str, Any]:
    keys = []
    for role, usage, key_id in (
        ("release", "release-signing", RELEASE_KEY_ID),
        ("status", "release-status-signing", STATUS_KEY_ID),
    ):
        der = _public_key_der(root, role)
        digest = file_digest(der)
        if digest != key_id:
            raise PublicReleaseError("fixture public key identity is invalid")
        keys.append(
            {
                "key_id": key_id,
                "usage": usage,
                "algorithm": ALGORITHM,
                "public_key_format": "spki-der-base64",
                "public_key": base64.b64encode(der).decode("ascii"),
                "public_key_digest": digest,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2028-01-01T00:00:00Z",
                "status": "active",
                "limitations": [
                    "Synthetic fixture key; not trusted for production use."
                ],
            }
        )
    trust = {
        "schema_version": SCHEMA_VERSION,
        "artifact_status": ARTIFACT_STATUS,
        "trust_domain_id": TRUST_DOMAIN,
        "trust_root_revision": 1,
        "permitted_signing_profiles": [
            {
                "id": "private-match-public-release-signing",
                "version": SCHEMA_VERSION,
            }
        ],
        "keys": keys,
        "limitations": [
            "Trust-root authenticity is an external verifier decision and is not established by a release bundle."
        ],
    }
    trust["trust_root_digest"] = domain_digest(TRUST_ROOT_DOMAIN, trust)
    return trust


def validate_trust_root(
    root: Path, trust: dict[str, Any], schemas: dict[str, dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    validate_named_schema(trust, "trust_root", schemas)
    if trust.get("trust_root_digest") != detached_digest(
        TRUST_ROOT_DOMAIN, trust, "trust_root_digest"
    ):
        raise PublicReleaseError("trust-root digest is invalid")
    if (
        trust.get("artifact_status") != ARTIFACT_STATUS
        or trust.get("trust_domain_id") != TRUST_DOMAIN
    ):
        raise PublicReleaseError("trust-root domain is unsupported")
    result: dict[str, dict[str, Any]] = {}
    for key in trust["keys"]:
        key_id = key["key_id"]
        if key_id in result:
            raise PublicReleaseError("trust root contains a duplicate key")
        der = _strict_base64(key["public_key"])
        if (
            file_digest(der) != key_id
            or key["public_key_digest"] != key_id
            or key["algorithm"] != ALGORITHM
            or key["public_key_format"] != "spki-der-base64"
        ):
            raise PublicReleaseError("trust-root key identity is invalid")
        parse_timestamp(key["valid_from"])
        parse_timestamp(key["valid_until"])
        result[key_id] = key
    release = result.get(RELEASE_KEY_ID)
    status = result.get(STATUS_KEY_ID)
    if (
        not release
        or release.get("usage") != "release-signing"
        or not status
        or status.get("usage") != "release-status-signing"
    ):
        raise PublicReleaseError("trust-root key usage separation is invalid")
    return result


def _status_entry(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result["status_entry_digest"] = domain_digest(STATUS_ENTRY_DOMAIN, result)
    return result


def build_status_set(
    *,
    release_state: str = "active",
    release_key_status: str = "active",
    release_key_reason: str = "fixture-key-active",
    replacement_release_id: str | None = None,
    replacement_bundle_digest: str | None = None,
    notice_digest: str | None = None,
    previous_status_set_digest: str | None = None,
    revision: int = 1,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or (
        CREATED_AT if revision == 1 else f"2026-08-{revision + 1:02d}T00:00:00Z"
    )
    key_entries = [
        _status_entry(
            {
                "entry_type": "key-status",
                "key_id": RELEASE_KEY_ID,
                "usage": "release-signing",
                "status": release_key_status,
                "effective_at": timestamp,
                "reason_code": release_key_reason,
                "replacement_key_id": None,
                "compromise_indicator": release_key_status == "revoked",
            }
        )
    ]
    release_entries = [
        _status_entry(
            {
                "entry_type": "release-status",
                "release_id": RELEASE_ID,
                "bundle_manifest_digest": "__MANIFEST_DIGEST__",
                "state": release_state,
                "effective_at": timestamp,
                "reason_code": f"fixture-release-{release_state}",
                "replacement_release_id": replacement_release_id,
                "replacement_bundle_digest": replacement_bundle_digest,
                "notice_digest": notice_digest,
            }
        )
    ]
    status_set = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "public-release-status-set",
        "artifact_status": ARTIFACT_STATUS,
        "trust_domain_id": TRUST_DOMAIN,
        "status_set_id": "PMA-PUBLIC-RELEASE-STATUS-FIXTURE-V0-1",
        "revision": revision,
        "generated_at": timestamp,
        "previous_status_set_digest": previous_status_set_digest,
        "signing_key_id": STATUS_KEY_ID,
        "key_statuses": key_entries,
        "release_statuses": release_entries,
    }
    return status_set


def finalize_status_set(
    status_set: dict[str, Any], manifest_digest: str
) -> dict[str, Any]:
    result = copy.deepcopy(status_set)
    for entry in result["release_statuses"]:
        entry["bundle_manifest_digest"] = manifest_digest
        entry["status_entry_digest"] = detached_digest(
            STATUS_ENTRY_DOMAIN, entry, "status_entry_digest"
        )
    entries = result["key_statuses"] + result["release_statuses"]
    result["entry_set_digest"] = domain_digest(STATUS_ENTRY_SET_DOMAIN, entries)
    result["status_set_digest"] = domain_digest(STATUS_SET_DOMAIN, result)
    return result


def status_revision_set_path(revision: int) -> str:
    return f"revisions/{revision:04d}/{STATUS_SET_FILENAME}"


def status_revision_envelope_path(revision: int) -> str:
    return f"revisions/{revision:04d}/{STATUS_ENVELOPE_FILENAME}"


def _fixture_subject() -> dict[str, Any]:
    return {
        "type": "build-artifact",
        "identifier": "private-match-synthetic-public-release-fixture",
        "version": "0.1.0",
        "digest": "sha256:" + "a6" * 32,
    }


def build_fixture_records() -> dict[str, dict[str, Any]]:
    subject = _fixture_subject()
    limitation_ids = ["PM-LIMITATION-6001", "PM-LIMITATION-6002"]
    claims = {
        "PM-CLAIM-6001": {
            "schema_version": SCHEMA_VERSION,
            "record_type": "claim",
            "id": "PM-CLAIM-6001",
            "statement": "The synthetic fixture bundle signature verifies under the supplied fixture trust root.",
            "subject": subject,
            "scope": "Mechanical verification of the catalogued test-only fixture bundle.",
            "status": "supported",
            "assumptions": [],
            "evidence": ["PM-EVIDENCE-6001"],
            "limitations": limitation_ids,
            "valid_from": VALID_FROM,
            "valid_until": VALID_UNTIL,
            "status_reason": None,
            "supersedes": None,
            "owner": "ITDO Inc.",
            "reviewers": ["synthetic-fixture-reviewer"],
        },
        "PM-CLAIM-6002": {
            "schema_version": SCHEMA_VERSION,
            "record_type": "claim",
            "id": "PM-CLAIM-6002",
            "statement": "The synthetic fixture bundle file digests and report linkage are complete under the Draft 0.1 profile.",
            "subject": subject,
            "scope": "Closed fixture bundle path, digest, and derived-report linkage.",
            "status": "supported",
            "assumptions": [],
            "evidence": ["PM-EVIDENCE-6001", "PM-EVIDENCE-6003"],
            "limitations": limitation_ids,
            "valid_from": VALID_FROM,
            "valid_until": VALID_UNTIL,
            "status_reason": None,
            "supersedes": None,
            "owner": "ITDO Inc.",
            "reviewers": ["synthetic-fixture-reviewer"],
        },
        "PM-CLAIM-6003": {
            "schema_version": SCHEMA_VERSION,
            "record_type": "claim",
            "id": "PM-CLAIM-6003",
            "statement": "The fixture manifest references the reviewed Protocol and conformance identifiers.",
            "subject": subject,
            "scope": "Identifier and digest binding for the public synthetic fixture only.",
            "status": "supported-with-assumptions",
            "assumptions": ["PM-ASSUMPTION-6001"],
            "evidence": ["PM-EVIDENCE-6002"],
            "limitations": limitation_ids,
            "valid_from": VALID_FROM,
            "valid_until": VALID_UNTIL,
            "status_reason": None,
            "supersedes": None,
            "owner": "ITDO Inc.",
            "reviewers": ["synthetic-fixture-reviewer"],
        },
        "PM-CLAIM-6004": {
            "schema_version": SCHEMA_VERSION,
            "record_type": "claim",
            "id": "PM-CLAIM-6004",
            "statement": "The catalogued fixture is test-only and is not a production Product release.",
            "subject": subject,
            "scope": "Fixture classification and publication boundary.",
            "status": "supported",
            "assumptions": [],
            "evidence": ["PM-EVIDENCE-6003"],
            "limitations": limitation_ids,
            "valid_from": VALID_FROM,
            "valid_until": VALID_UNTIL,
            "status_reason": None,
            "supersedes": None,
            "owner": "ITDO Inc.",
            "reviewers": ["synthetic-fixture-reviewer"],
        },
    }
    assumptions = {
        "PM-ASSUMPTION-6001": {
            "schema_version": SCHEMA_VERSION,
            "record_type": "assumption",
            "id": "PM-ASSUMPTION-6001",
            "statement": "The committed reviewed Protocol authority file is the intended authority for this synthetic fixture.",
            "scope": "Fixture Protocol/conformance metadata binding.",
            "status": "active",
            "rationale": "The fixture performs structural binding and does not independently authenticate the upstream authority.",
            "owner": "ITDO Inc.",
            "reviewed_at": CREATED_AT,
            "next_review_at": "2026-11-01T00:00:00Z",
            "sources": [
                "https://github.com/itdojp/private-match-protocol/commit/9bb59d3b5e1435885fdea60280d6602f937305c9"
            ],
        }
    }

    def evidence(
        evidence_id: str,
        evidence_type: str,
        status: str,
        output: str | None,
        configuration: dict[str, Any],
        summary: str,
        ran: bool,
        required: bool,
        reason: str | None,
    ) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "record_type": "evidence",
            "id": evidence_id,
            "type": evidence_type,
            "status": status,
            "lifecycle": "sanitized",
            "lifecycle_history": [
                {
                    "state": "collected",
                    "recorded_at": "2026-08-01T00:00:01Z",
                    "review_digest": None,
                },
                {
                    "state": "validated",
                    "recorded_at": "2026-08-01T00:00:02Z",
                    "review_digest": "sha256:" + "b1" * 32,
                },
                {
                    "state": "sanitized",
                    "recorded_at": "2026-08-01T00:00:03Z",
                    "review_digest": "sha256:" + "b2" * 32,
                },
            ],
            "subject": subject,
            "input_digests": ["sha256:" + "b3" * 32],
            "output_digest": output,
            "producer": {
                "type": "local-runner",
                "identity": "synthetic-public-release-fixture",
            },
            "tool": {
                "name": "private-match-public-release-fixture",
                "version": SCHEMA_VERSION,
                "source": "reviewed-public-fixture",
            },
            "started_at": "2026-08-01T00:00:00Z",
            "completed_at": "2026-08-01T00:00:01Z",
            "execution": {"ran": ran, "required": required, "reason": reason},
            "configuration": configuration,
            "model_check": None,
            "summary": summary,
            "private_source_metadata": None,
            "public_artifacts": [],
            "limitations": ["Synthetic fixture only; no Product result is asserted."],
        }

    evidence_items = {
        "PM-EVIDENCE-6001": evidence(
            "PM-EVIDENCE-6001",
            "test",
            "pass",
            "sha256:" + "c1" * 32,
            {"fixture_id": FIXTURE_ID, "contract": "bundle-digest-closure-v0.1"},
            "Synthetic digest-closure and signature fixture completed.",
            True,
            True,
            None,
        ),
        "PM-EVIDENCE-6002": evidence(
            "PM-EVIDENCE-6002",
            "conformance",
            "pass",
            "sha256:" + "c2" * 32,
            {
                "protocol": {"identifier": "private-match-core", "version": "0.1"},
                "conformance_suite": {
                    "identifier": "private-match-core",
                    "version": "0.1",
                },
                "vectors": 49,
            },
            "Synthetic fixture references the reviewed public conformance authority.",
            True,
            True,
            None,
        ),
        "PM-EVIDENCE-6003": evidence(
            "PM-EVIDENCE-6003",
            "provenance",
            "pass",
            "sha256:" + "c3" * 32,
            {"fixture_only": True, "signed": False, "publication_approval": False},
            "Synthetic unsigned provenance and fixture boundary were validated.",
            True,
            True,
            None,
        ),
        "PM-EVIDENCE-6004": evidence(
            "PM-EVIDENCE-6004",
            "security-scan",
            "unsupported",
            None,
            {"capability": "production-signing-key-security-assessment"},
            "Production key-security assessment is unavailable in fixture mode.",
            False,
            False,
            "production-signing-unsupported",
        ),
    }
    limitations = {
        "PM-LIMITATION-6001": {
            "schema_version": SCHEMA_VERSION,
            "record_type": "known-limitation",
            "id": "PM-LIMITATION-6001",
            "statement": "The fixture keys and trust root are synthetic and not production trust anchors.",
            "affected_claims": sorted(claims),
            "severity": "medium",
            "status": "accepted",
            "owner": "ITDO Inc.",
            "identified_at": CREATED_AT,
            "reviewed_at": CREATED_AT,
            "next_review_at": None,
            "mitigation": "Require a separate reviewed production key-custody and trust-root decision before any real release.",
            "references": ["docs/KEY_AND_REVOCATION_BOUNDARY.md"],
        },
        "PM-LIMITATION-6002": {
            "schema_version": SCHEMA_VERSION,
            "record_type": "known-limitation",
            "id": "PM-LIMITATION-6002",
            "statement": "No trusted timestamp establishes whether a signature predates a key compromise.",
            "affected_claims": sorted(claims),
            "severity": "medium",
            "status": "accepted",
            "owner": "ITDO Inc.",
            "identified_at": CREATED_AT,
            "reviewed_at": CREATED_AT,
            "next_review_at": None,
            "mitigation": "Treat compromise revocation conservatively for every signature under the revoked key.",
            "references": ["docs/KEY_AND_REVOCATION_BOUNDARY.md"],
        },
    }
    result: dict[str, dict[str, Any]] = {}
    result.update(claims)
    result.update(assumptions)
    result.update(evidence_items)
    result.update(limitations)
    return result


def _record_relative(record: dict[str, Any]) -> str:
    directories = {
        "claim": "claims",
        "assumption": "assumptions",
        "evidence": "evidence",
        "known-limitation": "limitations",
    }
    directory = directories[record["record_type"]]
    return f"records/{directory}/{record['id'].lower()}.json"


def validate_fixture_records(
    records: dict[str, dict[str, Any]], schemas: dict[str, dict[str, Any]]
) -> None:
    if len(records) != len(set(records)):
        raise PublicReleaseError("record IDs are not unique")
    subject = _fixture_subject()
    for record_id, record in records.items():
        if record.get("id") != record_id:
            raise PublicReleaseError("record identity is invalid")
        validate_named_schema(record, record["record_type"], schemas)
        if (
            record["record_type"] in {"claim", "evidence"}
            and record.get("subject") != subject
        ):
            raise PublicReleaseError("record subject is inconsistent")


def build_fixture_artifacts(root: Path) -> dict[str, dict[str, Any]]:
    artifact = {
        "schema_version": SCHEMA_VERSION,
        "artifact_status": ARTIFACT_STATUS,
        "artifact_id": "PMA-SYNTHETIC-RELEASE-ARTIFACT-V0-1",
        "subject": _fixture_subject(),
        "content": {
            "fixture": True,
            "production_data": False,
            "publication_approval": "not-applicable-test-only",
        },
        "limitations": ["Synthetic JSON artifact; not executable Product software."],
    }
    artifact_bytes = canonicalize(artifact)
    protocol = read_strict_json(
        resolve_regular_file(
            root, "config/private-match-protocol-authorities.v0.1.json"
        )
    )
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000006",
        "version": 1,
        "metadata": {
            "timestamp": CREATED_AT,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "private-match-public-release-fixture-generator",
                        "version": SCHEMA_VERSION,
                    }
                ]
            },
            "component": {
                "type": "file",
                "bom-ref": "fixture-release-artifact",
                "name": "fixture-release-artifact.json",
                "version": "0.1.0",
                "hashes": [
                    {
                        "alg": "SHA-256",
                        "content": file_digest(artifact_bytes).removeprefix("sha256:"),
                    }
                ],
            },
        },
        "components": [],
        "dependencies": [{"ref": "fixture-release-artifact", "dependsOn": []}],
        "properties": [
            {"name": "itdo:artifact-status", "value": ARTIFACT_STATUS},
            {"name": "itdo:source-revision-digest", "value": "sha256:" + "d1" * 32},
        ],
    }
    sbom_bytes = canonicalize(sbom)
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "fixture-release-artifact.json",
                "digest": {
                    "sha256": file_digest(artifact_bytes).removeprefix("sha256:")
                },
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://itdo.jp/build-types/private-match-public-release-fixture/v0.1",
                "externalParameters": {"artifact_status": ARTIFACT_STATUS},
                "internalParameters": {
                    "signed": False,
                    "hermetic": False,
                    "reproducible": False,
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/itdojp/private-match-protocol",
                        "digest": {"gitCommit": protocol["commit"]},
                    },
                    {
                        "uri": "fixture:sbom.cdx.json",
                        "digest": {
                            "sha256": file_digest(sbom_bytes).removeprefix("sha256:")
                        },
                    },
                ],
            },
            "runDetails": {
                "builder": {"id": "private-match-assurance/fixture-builder-v0.1"},
                "metadata": {
                    "invocationId": "PMA-PUBLIC-RELEASE-FIXTURE-BUILD-V0-1",
                    "startedOn": CREATED_AT,
                    "finishedOn": "2026-08-01T00:00:04Z",
                },
                "byproducts": [],
            },
        },
    }
    return {
        "artifacts/fixture-release-artifact.json": artifact,
        "artifacts/sbom.cdx.json": sbom,
        "artifacts/build-provenance.v0.1.json": provenance,
    }


def _set_digest(records: Iterable[dict[str, Any]]) -> str:
    ordered = sorted(records, key=lambda item: item["id"])
    return domain_digest(RECORD_SET_DOMAIN, ordered)


def _file_entries(values: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    entries = []
    for path, value in sorted(values.items()):
        data = canonicalize(value)
        entries.append(
            {
                "path": path,
                "file_digest": file_digest(data),
                "size": len(data),
                "role": "release-record"
                if path.startswith("records/")
                else "release-artifact",
            }
        )
    return entries


def _evaluate_claims(
    records: dict[str, dict[str, Any]], verification_time: str | None
) -> dict[str, Any]:
    """Evaluate immutable record state, optionally at one explicit verifier time."""

    verification = (
        parse_timestamp(verification_time) if verification_time is not None else None
    )
    claims = {
        identifier: value
        for identifier, value in records.items()
        if value.get("record_type") == "claim"
    }
    assumptions = {
        identifier: value
        for identifier, value in records.items()
        if value.get("record_type") == "assumption"
    }
    evidence = {
        identifier: value
        for identifier, value in records.items()
        if value.get("record_type") == "evidence"
    }
    limitations = {
        identifier: value
        for identifier, value in records.items()
        if value.get("record_type") == "known-limitation"
    }
    results = []
    counts = {value: 0 for value in CLAIM_RESULT_VALUES}
    for identifier in sorted(claims):
        claim = claims[identifier]
        evidence_refs = claim.get("evidence", [])
        assumption_refs = claim.get("assumptions", [])
        limitation_refs = claim.get("limitations", [])
        missing = (
            [item for item in evidence_refs if item not in evidence]
            + [item for item in assumption_refs if item not in assumptions]
            + [item for item in limitation_refs if item not in limitations]
        )
        statuses = [
            evidence[item]["status"] if item in evidence else "missing"
            for item in evidence_refs
        ]
        evidence_lifecycles = [
            evidence[item]["lifecycle"] if item in evidence else "missing"
            for item in evidence_refs
        ]
        assumption_statuses = [
            assumptions[item]["status"] if item in assumptions else "missing"
            for item in assumption_refs
        ]
        positive_claim = claim["status"] in {
            "supported",
            "supported-with-assumptions",
        }
        assumption_classification_invalid = (
            claim["status"] == "supported" and bool(assumption_refs)
        ) or (claim["status"] == "supported-with-assumptions" and not assumption_refs)
        subject_mismatch = any(
            evidence[item].get("subject") != claim.get("subject")
            for item in evidence_refs
            if item in evidence
        )
        valid_at_verification_time = None
        if verification is not None:
            valid_from = parse_timestamp(claim["valid_from"])
            valid_until = (
                parse_timestamp(claim["valid_until"])
                if claim["valid_until"] is not None
                else None
            )
            valid_at_verification_time = verification >= valid_from and (
                valid_until is None or verification <= valid_until
            )
        if assumption_classification_invalid:
            result = "invalid-reference"
            reason = "claim-assumption-classification-invalid"
        elif missing or subject_mismatch or (positive_claim and not evidence_refs):
            result = "invalid-reference"
            reason = "claim-reference-invalid"
        elif (
            claim["status"] in {"not-supported", "expired", "withdrawn"}
            or "fail" in statuses
            or (
                positive_claim
                and any(
                    lifecycle
                    not in CLAIM_EVALUATION_POLICY["supporting_evidence_lifecycles"]
                    for lifecycle in evidence_lifecycles
                )
            )
            or "invalidated" in assumption_statuses
        ):
            result = "not-supported"
            if positive_claim and any(
                lifecycle
                not in CLAIM_EVALUATION_POLICY["supporting_evidence_lifecycles"]
                for lifecycle in evidence_lifecycles
            ):
                reason = "evidence-lifecycle-not-supporting"
            elif "invalidated" in assumption_statuses:
                reason = "required-assumption-invalidated"
            else:
                reason = "claim-or-evidence-not-supported"
        elif valid_at_verification_time is False:
            result = "not-evaluated"
            reason = "claim-not-valid-at-verification-time"
        elif any(
            status in {"skip", "unsupported", "timeout", "tool-error"}
            for status in statuses
        ):
            result = "not-evaluated"
            reason = "required-evidence-not-evaluated"
        elif "expired" in assumption_statuses:
            result = "not-evaluated"
            reason = "required-assumption-expired"
        elif (
            claim["status"] == "supported-with-assumptions"
            and assumption_refs
            and all(status == "active" for status in assumption_statuses)
            and evidence_refs
            and all(status == "pass" for status in statuses)
            and all(
                lifecycle in CLAIM_EVALUATION_POLICY["supporting_evidence_lifecycles"]
                for lifecycle in evidence_lifecycles
            )
        ):
            result = "supported-with-assumptions"
            reason = "evidence-pass-assumptions-visible"
        elif (
            claim["status"] == "supported"
            and not assumption_refs
            and evidence_refs
            and statuses
            and all(status == "pass" for status in statuses)
            and all(
                lifecycle in CLAIM_EVALUATION_POLICY["supporting_evidence_lifecycles"]
                for lifecycle in evidence_lifecycles
            )
        ):
            result = "supported"
            reason = "required-evidence-pass"
        else:
            result = "not-evaluated"
            reason = "claim-status-not-evaluable"
        counts[result] += 1
        results.append(
            {
                "claim_id": identifier,
                "declared_status": claim["status"],
                "result": result,
                "reason_code": reason,
                "assumption_ids": assumption_refs,
                "assumption_statuses": assumption_statuses,
                "evidence_ids": evidence_refs,
                "limitation_ids": limitation_refs,
                "evidence_statuses": statuses,
                "evidence_lifecycles": evidence_lifecycles,
                "valid_from": claim["valid_from"],
                "valid_until": claim["valid_until"],
                **(
                    {
                        "valid_at_verification_time": valid_at_verification_time,
                    }
                    if verification is not None
                    else {}
                ),
            }
        )
    return {"results": results, "status_counts": counts}


def summarize_declared_claims(
    records: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Summarize immutable signed declarations without a current-time result."""

    return _evaluate_claims(records, None)


def evaluate_claims(
    records: dict[str, dict[str, Any]], verification_time: str
) -> dict[str, Any]:
    """Evaluate signed claims against record state and an explicit verifier time."""

    return _evaluate_claims(records, verification_time)


def _evidence_status_counts(records: dict[str, dict[str, Any]]) -> dict[str, int]:
    counts = {
        status: 0
        for status in ("pass", "fail", "skip", "unsupported", "timeout", "tool-error")
    }
    for record in records.values():
        if record.get("record_type") == "evidence":
            counts[record["status"]] += 1
    return counts


def build_report_model(
    root: Path,
    records: dict[str, dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    protocol = read_strict_json(
        resolve_regular_file(
            root, "config/private-match-protocol-authorities.v0.1.json"
        )
    )
    pin = read_strict_json(
        resolve_regular_file(root, "config/ae-framework-pin.v0.1.json")
    )
    export_profile = read_strict_json(
        resolve_regular_file(root, "profiles/public-evidence-export.v0.1.json")
    )
    assurance_profile = read_strict_json(
        resolve_regular_file(root, "profiles/private-match-ae-assurance.v0.1.json")
    )
    claim_evaluation = summarize_declared_claims(records)
    model = {
        "schema_version": SCHEMA_VERSION,
        "artifact_status": ARTIFACT_STATUS,
        "release": {
            "release_id": RELEASE_ID,
            "version": "0.1.0",
            "channel": "fixture",
            "bundle_revision": 1,
        },
        "signing": {
            "payload_type": RELEASE_PAYLOAD_TYPE,
            "algorithm": ALGORITHM,
            "key_id": RELEASE_KEY_ID,
            "trust_domain_id": TRUST_DOMAIN,
        },
        "protocol": {
            "identifier": protocol["protocol"]["identifier"],
            "version": protocol["protocol"]["version"],
            "semantic_digest": protocol["protocol"]["semantic_digest"],
            "commit": protocol["commit"],
        },
        "conformance": {
            "identifier": protocol["conformance_suite"]["identifier"],
            "version": protocol["conformance_suite"]["version"],
            "semantic_digest": protocol["conformance_suite"]["semantic_digest"],
            "complete_suite_tree_digest": protocol["conformance_suite"][
                "complete_suite_tree_digest"
            ],
        },
        "ae_framework": {
            "repository": pin["repository"],
            "commit": pin["commit"],
            "package": pin["package"],
            "pin_digest": pin["pin_digest"],
        },
        "profiles": {
            "export": {
                "id": export_profile["profile_id"],
                "version": export_profile["profile_version"],
                "digest": export_profile["profile_digest"],
            },
            "assurance": {
                "id": assurance_profile["profile_id"],
                "version": assurance_profile["profile_version"],
                "digest": assurance_profile["profile_digest"],
            },
        },
        "subject": _fixture_subject(),
        "source_revision_digest": "sha256:" + "d1" * 32,
        "release_artifact_digest": file_digest(
            canonicalize(artifacts["artifacts/fixture-release-artifact.json"])
        ),
        "sbom_digest": file_digest(canonicalize(artifacts["artifacts/sbom.cdx.json"])),
        "build_provenance_digest": file_digest(
            canonicalize(artifacts["artifacts/build-provenance.v0.1.json"])
        ),
        "record_counts": {
            "claims": sum(
                value["record_type"] == "claim" for value in records.values()
            ),
            "assumptions": sum(
                value["record_type"] == "assumption" for value in records.values()
            ),
            "evidence": sum(
                value["record_type"] == "evidence" for value in records.values()
            ),
            "limitations": sum(
                value["record_type"] == "known-limitation" for value in records.values()
            ),
        },
        "evidence_status_counts": _evidence_status_counts(records),
        "claims": claim_evaluation,
        "publication": {
            "final_publication_approval": "not-applicable-test-only",
            "automation_permitted": False,
            "production_signing": "unsupported",
            "product_release_signing": "unsupported",
            "github_release_creation": "absent",
            "ci_artifact_upload": "absent",
        },
        "limitations": RELEASE_LIMITATIONS,
    }
    return model


def build_release_manifest(
    root: Path,
    records: dict[str, dict[str, Any]],
    artifacts: dict[str, dict[str, Any]],
    report_model: dict[str, Any],
) -> dict[str, Any]:
    _, signing_profile, verification_profile = load_release_authority(root)
    protocol = read_strict_json(
        resolve_regular_file(
            root, "config/private-match-protocol-authorities.v0.1.json"
        )
    )
    pin = read_strict_json(
        resolve_regular_file(root, "config/ae-framework-pin.v0.1.json")
    )
    export_profile = read_strict_json(
        resolve_regular_file(root, "profiles/public-evidence-export.v0.1.json")
    )
    assurance_profile = read_strict_json(
        resolve_regular_file(root, "profiles/private-match-ae-assurance.v0.1.json")
    )
    content: dict[str, dict[str, Any]] = {}
    for record in records.values():
        content[_record_relative(record)] = record
    content.update(artifacts)
    entries = _file_entries(content)
    claim_records = [
        value for value in records.values() if value["record_type"] == "claim"
    ]
    assumption_records = [
        value for value in records.values() if value["record_type"] == "assumption"
    ]
    evidence_records = [
        value for value in records.values() if value["record_type"] == "evidence"
    ]
    limitation_records = [
        value
        for value in records.values()
        if value["record_type"] == "known-limitation"
    ]
    report_model_digest = domain_digest(REPORT_MODEL_DOMAIN, report_model)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "public-release-bundle-manifest",
        "artifact_status": ARTIFACT_STATUS,
        "bundle_id": BUNDLE_ID,
        "release": {
            "release_id": RELEASE_ID,
            "version": "0.1.0",
            "bundle_revision": 1,
            "channel": "fixture",
        },
        "created_at": CREATED_AT,
        "valid_from": VALID_FROM,
        "valid_until": VALID_UNTIL,
        "subject": _fixture_subject(),
        "source_revision_digest": "sha256:" + "d1" * 32,
        "release_artifact_digest": file_digest(
            canonicalize(artifacts["artifacts/fixture-release-artifact.json"])
        ),
        "protocol": {
            "repository": protocol["repository"],
            "commit": protocol["commit"],
            "identifier": protocol["protocol"]["identifier"],
            "version": protocol["protocol"]["version"],
            "semantic_digest": protocol["protocol"]["semantic_digest"],
        },
        "conformance": {
            "identifier": protocol["conformance_suite"]["identifier"],
            "version": protocol["conformance_suite"]["version"],
            "semantic_digest": protocol["conformance_suite"]["semantic_digest"],
            "complete_suite_tree_digest": protocol["conformance_suite"][
                "complete_suite_tree_digest"
            ],
        },
        "ae_framework": {
            "repository": pin["repository"],
            "commit": pin["commit"],
            "package": pin["package"],
            "pin_digest": pin["pin_digest"],
        },
        "export_profile": {
            "id": export_profile["profile_id"],
            "version": export_profile["profile_version"],
            "digest": export_profile["profile_digest"],
        },
        "assurance_profile": {
            "id": assurance_profile["profile_id"],
            "version": assurance_profile["profile_version"],
            "digest": assurance_profile["profile_digest"],
        },
        "record_sets": {
            "claim_set_digest": _set_digest(claim_records),
            "assumption_set_digest": _set_digest(assumption_records),
            "evidence_set_digest": _set_digest(evidence_records),
            "limitation_set_digest": _set_digest(limitation_records),
            "evidence_record_digests": [
                domain_digest("private-match-evidence-record/v0.1", value)
                for value in sorted(evidence_records, key=lambda item: item["id"])
            ],
            "evidence_output_digests": sorted(
                value["output_digest"]
                for value in evidence_records
                if value["output_digest"] is not None
            ),
        },
        "artifacts": {
            "release": {
                "path": "artifacts/fixture-release-artifact.json",
                "digest": file_digest(
                    canonicalize(artifacts["artifacts/fixture-release-artifact.json"])
                ),
            },
            "sbom": {
                "path": "artifacts/sbom.cdx.json",
                "digest": file_digest(
                    canonicalize(artifacts["artifacts/sbom.cdx.json"])
                ),
            },
            "build_provenance": {
                "path": "artifacts/build-provenance.v0.1.json",
                "digest": file_digest(
                    canonicalize(artifacts["artifacts/build-provenance.v0.1.json"])
                ),
            },
        },
        "reports": {
            "json": {
                "path": REPORT_JSON_PATH,
                "report_model_digest": report_model_digest,
            },
            "markdown": {
                "path": REPORT_MD_PATH,
                "report_model_digest": report_model_digest,
            },
        },
        "content_files": entries,
        "content_tree_digest": domain_digest(CONTENT_TREE_DOMAIN, entries),
        "signing": {
            "profile_id": signing_profile["profile_id"],
            "profile_version": signing_profile["profile_version"],
            "profile_digest": signing_profile["profile_digest"],
            "verification_profile_digest": verification_profile["profile_digest"],
            "payload_type": RELEASE_PAYLOAD_TYPE,
            "algorithm": ALGORITHM,
            "release_signing_key_id": RELEASE_KEY_ID,
            "trust_domain_id": TRUST_DOMAIN,
        },
        "supersedes": {"release_id": None, "bundle_manifest_digest": None},
        "corrects": {"release_id": None, "bundle_manifest_digest": None},
        "limitations": RELEASE_LIMITATIONS,
    }
    manifest["manifest_digest"] = detached_jcs_sha256(manifest, "manifest_digest")
    return manifest


def build_verification_report(
    manifest: dict[str, Any],
    report_model: dict[str, Any],
    status_set: dict[str, Any],
    *,
    status_chain: dict[str, Any],
    claim_evaluation: dict[str, Any],
    overall_status: str = "verified-fixture-with-limitations",
    key_status: str = "active",
    release_state: str = "active",
    signature_valid: bool = True,
    trust_valid: bool = True,
    structure_valid: bool = True,
    digest_valid: bool = True,
    report_linkage_valid: bool = True,
    verification_time: str = VERIFICATION_TIME,
) -> dict[str, Any]:
    report = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "public-release-verification-result",
        "artifact_status": ARTIFACT_STATUS,
        "verification_time": verification_time,
        "release": report_model["release"],
        "manifest_digest": manifest["manifest_digest"],
        "release_signature": {
            "envelope_valid": signature_valid,
            "payload_type_supported": signature_valid,
            "algorithm_supported": signature_valid,
            "signature_valid": signature_valid,
            "key_id": RELEASE_KEY_ID,
        },
        "trust": {
            "trust_domain_valid": trust_valid,
            "key_known": trust_valid,
            "key_usage_valid": trust_valid,
            "key_valid_at_verification_time": trust_valid and key_status == "active",
            "key_status": key_status,
            "key_revoked": key_status == "revoked",
        },
        "structure": {
            "schemas_valid": structure_valid,
            "canonical_json_valid": structure_valid,
            "bundle_exact_path_set_valid": structure_valid,
            "status_chain_exact_path_set_valid": structure_valid,
        },
        "digest_closure": {
            "manifest_digest_valid": digest_valid,
            "file_digests_valid": digest_valid,
            "tree_digest_valid": digest_valid,
            "record_set_digests_valid": digest_valid,
            "sbom_reference_valid": digest_valid,
            "provenance_reference_valid": digest_valid,
            "status_chain_digests_valid": digest_valid,
        },
        "report_linkage": {
            "static_json_report_valid": report_linkage_valid,
            "static_markdown_report_valid": report_linkage_valid,
            "static_report_content_matches_manifest": report_linkage_valid,
        },
        "release_lifecycle": {
            "state": release_state,
            "active": release_state == "active",
            "superseded": release_state == "superseded",
            "corrected": release_state == "corrected",
            "withdrawn": release_state == "withdrawn",
            "expired": release_state == "expired",
            "status_set_digest": status_set["status_set_digest"],
        },
        "status_chain": status_chain,
        "authorities": {
            "protocol": report_model["protocol"],
            "conformance": report_model["conformance"],
            "ae_framework": report_model["ae_framework"],
            "profiles": report_model["profiles"],
        },
        "subject": report_model["subject"],
        "source_revision_digest": report_model["source_revision_digest"],
        "release_artifact_digest": report_model["release_artifact_digest"],
        "sbom_digest": report_model["sbom_digest"],
        "build_provenance_digest": report_model["build_provenance_digest"],
        "record_counts": report_model["record_counts"],
        "evidence_status_counts": report_model["evidence_status_counts"],
        "claims": claim_evaluation,
        "publication": report_model["publication"],
        "overall": {
            "status": overall_status,
            "limitations": RELEASE_LIMITATIONS,
        },
        "statements": [
            "Signature verification proves origin and integrity only relative to the supplied trust input.",
            "Signature validity is not security certification or proof of Product correctness.",
            "Fixture verification is not Product release or publication approval.",
        ],
    }
    report["verification_result_digest"] = domain_digest(
        VERIFICATION_RESULT_DOMAIN, report
    )
    return report


def render_content_markdown(report: dict[str, Any]) -> bytes:
    """Render immutable release-content facts without current trust/lifecycle claims."""
    release = report["release"]
    lines = [
        "# Private Match synthetic release content",
        "",
        "> Immutable synthetic test-only content. This is not a verification result or Product release approval.",
        "",
        "## Release content",
        "",
        f"- Release ID: `{release['release_id']}`",
        f"- Version: `{release['version']}`",
        f"- Channel: `{release['channel']}`",
        f"- Bundle revision: `{release['bundle_revision']}`",
        f"- Source revision digest: `{report['source_revision_digest']}`",
        f"- Release artifact digest: `{report['release_artifact_digest']}`",
        f"- SBOM digest: `{report['sbom_digest']}`",
        f"- Build provenance digest: `{report['build_provenance_digest']}`",
        "",
        "## Declared authorities",
        "",
        f"- Protocol: `{report['protocol']['identifier']}` `{report['protocol']['version']}`",
        f"- Protocol digest: `{report['protocol']['semantic_digest']}`",
        f"- Conformance digest: `{report['conformance']['semantic_digest']}`",
        "",
        "## Evidence status counts",
        "",
    ]
    for status, count in report["evidence_status_counts"].items():
        lines.append(f"- `{status}`: {count}")
    lines.extend(["", "## Declared claim support", ""])
    for claim in report["claims"]["results"]:
        lines.append(
            f"- `{claim['claim_id']}`: `{claim['result']}` ({claim['reason_code']})"
        )
        lines.append(
            f"  - Signed validity: `{claim['valid_from']}` through `{claim['valid_until'] or 'unbounded'}`"
        )
        lines.append(
            "  - Assumptions: "
            + (
                ", ".join(
                    f"`{identifier}={status}`"
                    for identifier, status in zip(
                        claim["assumption_ids"],
                        claim["assumption_statuses"],
                        strict=True,
                    )
                )
                or "none"
            )
        )
        lines.append(
            "  - Evidence: "
            + ", ".join(
                f"`{identifier}={status}/{lifecycle}`"
                for identifier, status, lifecycle in zip(
                    claim["evidence_ids"],
                    claim["evidence_statuses"],
                    claim["evidence_lifecycles"],
                    strict=True,
                )
            )
        )
    lines.extend(["", "## Known limitations", ""])
    for limitation in report["limitations"]:
        lines.append(f"- {limitation}")
    lines.extend(
        [
            "",
            "Current signature validity, trust, key status, release lifecycle, verification time, and overall verification classification are intentionally absent.",
        ]
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def render_verification_markdown(report: dict[str, Any]) -> bytes:
    release = report["release"]
    lines = [
        "# Private Match public release verification",
        "",
        "> Synthetic test-only fixture. This is not a Product release or publication approval.",
        "",
        "## Release",
        "",
        f"- Release ID: `{release['release_id']}`",
        f"- Version: `{release['version']}`",
        f"- Channel: `{release['channel']}`",
        f"- Bundle revision: `{release['bundle_revision']}`",
        f"- Manifest digest: `{report['manifest_digest']}`",
        f"- Overall: `{report['overall']['status']}`",
        f"- Verification time: `{report['verification_time']}`",
        "",
        "## Signature and trust",
        "",
        f"- Algorithm: `{ALGORITHM}`",
        f"- Signing key ID: `{report['release_signature']['key_id']}`",
        f"- Signature valid: `{str(report['release_signature']['signature_valid']).lower()}`",
        f"- Trust domain valid: `{str(report['trust']['trust_domain_valid']).lower()}`",
        f"- Key status: `{report['trust']['key_status']}`",
        f"- Release lifecycle: `{report['release_lifecycle']['state']}`",
        f"- Selected status revision: `{report['status_chain']['latest_revision']}`",
        f"- Status-chain manifest digest: `{report['status_chain']['chain_manifest_digest']}`",
        "",
        "## Authorities and artifacts",
        "",
        f"- Protocol: `{report['authorities']['protocol']['identifier']}` `{report['authorities']['protocol']['version']}`",
        f"- Protocol digest: `{report['authorities']['protocol']['semantic_digest']}`",
        f"- Conformance digest: `{report['authorities']['conformance']['semantic_digest']}`",
        f"- Source revision digest: `{report['source_revision_digest']}`",
        f"- Release artifact digest: `{report['release_artifact_digest']}`",
        f"- SBOM digest: `{report['sbom_digest']}`",
        f"- Build provenance digest: `{report['build_provenance_digest']}`",
        "",
        "## Verification stages",
        "",
        f"- Structure valid: `{str(all(report['structure'].values())).lower()}`",
        f"- Digest closure valid: `{str(all(report['digest_closure'].values())).lower()}`",
        f"- Report linkage valid: `{str(all(report['report_linkage'].values())).lower()}`",
        "",
        "## Evidence status counts",
        "",
    ]
    for status, count in report["evidence_status_counts"].items():
        lines.append(f"- `{status}`: {count}")
    lines.extend(["", "## Claim support", ""])
    for claim in report["claims"]["results"]:
        lines.append(
            f"- `{claim['claim_id']}`: `{claim['result']}` ({claim['reason_code']})"
        )
        lines.append(
            "  - Valid at verification time: "
            f"`{str(claim['valid_at_verification_time']).lower()}` "
            f"(`{claim['valid_from']}` through `{claim['valid_until'] or 'unbounded'}`)"
        )
        lines.append(
            "  - Assumptions: "
            + (
                ", ".join(
                    f"`{identifier}={status}`"
                    for identifier, status in zip(
                        claim["assumption_ids"],
                        claim["assumption_statuses"],
                        strict=True,
                    )
                )
                or "none"
            )
        )
        lines.append(
            "  - Evidence: "
            + ", ".join(
                f"`{identifier}={status}/{lifecycle}`"
                for identifier, status, lifecycle in zip(
                    claim["evidence_ids"],
                    claim["evidence_statuses"],
                    claim["evidence_lifecycles"],
                    strict=True,
                )
            )
        )
    lines.extend(["", "## Known limitations", ""])
    for limitation in report["overall"]["limitations"]:
        lines.append(f"- {limitation}")
    lines.extend(["", "## Interpretation boundary", ""])
    for statement in report["statements"]:
        lines.append(f"- {statement}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _bundle_file_entry(root: Path, relative: str, role: str) -> dict[str, Any]:
    path = resolve_regular_file(root, relative, max_bytes=MAX_BUNDLE_FILE_BYTES)
    data = path.read_bytes()
    return {
        "path": relative,
        "file_digest": file_digest(data),
        "size": len(data),
        "role": role,
    }


def build_output_set_from_directory(bundle_root: Path) -> dict[str, Any]:
    role_map = {
        MANIFEST_PATH: "release-manifest",
        RELEASE_ENVELOPE_PATH: "release-signature",
        REPORT_JSON_PATH: "release-content-report-json",
        REPORT_MD_PATH: "release-content-report-markdown",
    }
    files = []
    for path in sorted(bundle_root.rglob("*")):
        if path.is_symlink() or (
            path.exists() and not path.is_file() and not path.is_dir()
        ):
            raise PublicReleaseError("bundle contains a non-regular path")
        if not path.is_file():
            continue
        relative = path.relative_to(bundle_root).as_posix()
        if relative == OUTPUT_SET_PATH:
            continue
        role = role_map.get(relative)
        if role is None:
            role = (
                "release-record"
                if relative.startswith("records/")
                else "release-artifact"
            )
        files.append(_bundle_file_entry(bundle_root, relative, role))
    exact_paths = sorted([entry["path"] for entry in files] + [OUTPUT_SET_PATH])
    output = {
        "schema_version": SCHEMA_VERSION,
        "artifact_status": ARTIFACT_STATUS,
        "bundle_id": BUNDLE_ID,
        "release_id": RELEASE_ID,
        "exact_paths": exact_paths,
        "files": files,
        "self": {"path": OUTPUT_SET_PATH, "digest_field": "output_set_digest"},
        "bundle_tree_digest": domain_digest(CONTENT_TREE_DOMAIN, files),
        "manifest_digest": read_strict_json(bundle_root / MANIFEST_PATH)[
            "manifest_digest"
        ],
        "release_signature_digest": file_digest(
            (bundle_root / RELEASE_ENVELOPE_PATH).read_bytes()
        ),
        "static_report_model_digest": domain_digest(
            REPORT_MODEL_DOMAIN, read_strict_json(bundle_root / REPORT_JSON_PATH)
        ),
    }
    output["output_set_digest"] = domain_digest(OUTPUT_SET_DOMAIN, output)
    return output


def _write_bundle_values(bundle_root: Path, values: dict[str, Any]) -> None:
    for relative, value in values.items():
        validate_relative_path(relative)
        path = bundle_root / relative
        if isinstance(value, bytes):
            data = value
        else:
            data = canonicalize(value)
        atomic_write_file(path, data)


def build_fixture_bundle_values(root: Path) -> dict[str, Any]:
    schemas = load_public_release_schemas(root)
    verify_rfc8032_vector(root)
    records = build_fixture_records()
    validate_fixture_records(records, schemas)
    artifacts = build_fixture_artifacts(root)
    report_model = build_report_model(root, records, artifacts)
    manifest = build_release_manifest(root, records, artifacts, report_model)
    validate_named_schema(manifest, "manifest", schemas)
    manifest_bytes = canonicalize(manifest)
    envelope = sign_fixture_dsse(
        root, RELEASE_PAYLOAD_TYPE, manifest_bytes, "release-signing"
    )
    validate_named_schema(envelope, "dsse", schemas)
    validate_named_schema(report_model, "content_report", schemas)
    values: dict[str, Any] = {
        MANIFEST_PATH: manifest,
        RELEASE_ENVELOPE_PATH: envelope,
        REPORT_JSON_PATH: report_model,
        REPORT_MD_PATH: render_content_markdown(report_model),
    }
    for record in records.values():
        values[_record_relative(record)] = record
    values.update(artifacts)
    return values


def generate_fixture_bundle(
    root: Path, output_root: Path, relative_output: str
) -> Path:
    output_root = resolve_trusted_directory(output_root)
    target = resolve_new_directory(output_root, relative_output)
    staging = target.with_name(target.name + ".partial")
    if os.path.lexists(staging):
        raise PublicReleaseError("partial bundle output already exists")
    try:
        staging.mkdir(mode=0o700)
        values = build_fixture_bundle_values(root)
        _write_bundle_values(staging, values)
        output_set = build_output_set_from_directory(staging)
        schemas = load_public_release_schemas(root)
        validate_named_schema(output_set, "output_set", schemas)
        atomic_write_file(staging / OUTPUT_SET_PATH, canonicalize(output_set))
        os.replace(staging, target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        raise
    return target


def build_status_chain_values(
    root: Path, manifest_digest: str, variant: str
) -> dict[str, Any]:
    """Build one independently distributed signed status chain."""
    if variant not in STATUS_CHAIN_VARIANTS:
        raise PublicReleaseError("status-chain fixture variant is not catalogued")
    policy = STATUS_CHAIN_VARIANTS[variant]
    sets: list[dict[str, Any]] = []
    first = finalize_status_set(
        build_status_set(revision=1, generated_at=CREATED_AT), manifest_digest
    )
    sets.append(first)
    if policy["latest_revision"] == 2:
        state = policy["release_state"]
        replacement = state in {"superseded", "corrected"}
        second = finalize_status_set(
            build_status_set(
                release_state=state,
                release_key_status=policy["key_status"],
                release_key_reason=(
                    "fixture-key-compromised"
                    if policy["key_status"] == "revoked"
                    else "fixture-key-active"
                ),
                replacement_release_id=(
                    "private-match-assurance-fixture-release-0.2.0"
                    if replacement
                    else None
                ),
                replacement_bundle_digest=(
                    "sha256:" + "9a" * 32 if replacement else None
                ),
                notice_digest=("sha256:" + "9b" * 32 if state == "withdrawn" else None),
                previous_status_set_digest=first["status_set_digest"],
                revision=2,
                generated_at="2026-08-03T00:00:00Z",
            ),
            manifest_digest,
        )
        sets.append(second)
    values: dict[str, Any] = {}
    revisions: list[dict[str, Any]] = []
    tree_files: list[dict[str, Any]] = []
    for status_set in sets:
        revision = status_set["revision"]
        set_path = status_revision_set_path(revision)
        envelope_path = status_revision_envelope_path(revision)
        set_bytes = canonicalize(status_set)
        envelope = sign_fixture_dsse(
            root, STATUS_PAYLOAD_TYPE, set_bytes, "release-status-signing"
        )
        envelope_bytes = canonicalize(envelope)
        values[set_path] = status_set
        values[envelope_path] = envelope
        revisions.append(
            {
                "revision": revision,
                "generated_at": status_set["generated_at"],
                "status_set_path": set_path,
                "status_set_digest": status_set["status_set_digest"],
                "status_set_file_digest": file_digest(set_bytes),
                "status_signature_path": envelope_path,
                "status_signature_digest": file_digest(envelope_bytes),
                "previous_status_set_digest": status_set["previous_status_set_digest"],
            }
        )
        tree_files.extend(
            [
                {
                    "path": set_path,
                    "file_digest": file_digest(set_bytes),
                    "size": len(set_bytes),
                    "role": "status-set",
                },
                {
                    "path": envelope_path,
                    "file_digest": file_digest(envelope_bytes),
                    "size": len(envelope_bytes),
                    "role": "status-signature",
                },
            ]
        )
    latest = sets[-1]
    chain_manifest = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "public-release-status-chain-manifest",
        "artifact_status": ARTIFACT_STATUS,
        "trust_domain_id": TRUST_DOMAIN,
        "status_signing_profile": {
            "id": "private-match-public-release-signing",
            "version": SCHEMA_VERSION,
            "algorithm": ALGORITHM,
            "payload_type": STATUS_PAYLOAD_TYPE,
        },
        "status_signing_key_id": STATUS_KEY_ID,
        "revisions": revisions,
        "latest_revision": latest["revision"],
        "latest_status_set_digest": latest["status_set_digest"],
        "generated_at": latest["generated_at"],
        "chain_tree_digest": domain_digest(
            STATUS_CHAIN_TREE_DOMAIN,
            sorted(tree_files, key=lambda item: item["path"]),
        ),
        "limitations": [
            "The verifier cannot prove that a supplied offline status chain is the globally latest distributed revision."
        ],
    }
    chain_manifest["chain_manifest_digest"] = detached_digest(
        STATUS_CHAIN_MANIFEST_DOMAIN, chain_manifest, "chain_manifest_digest"
    )
    values[STATUS_CHAIN_MANIFEST_PATH] = chain_manifest
    return values


def build_status_chain_output_set(chain_root: Path) -> dict[str, Any]:
    manifest = read_strict_json(chain_root / STATUS_CHAIN_MANIFEST_PATH)
    role_map = {STATUS_CHAIN_MANIFEST_PATH: "status-chain-manifest"}
    files = []
    for path in sorted(chain_root.rglob("*")):
        if path.is_symlink() or (
            path.exists() and not path.is_file() and not path.is_dir()
        ):
            raise PublicReleaseError("status chain contains a non-regular path")
        if not path.is_file():
            continue
        relative = path.relative_to(chain_root).as_posix()
        if relative == STATUS_CHAIN_OUTPUT_SET_PATH:
            continue
        role = role_map.get(
            relative,
            "status-signature"
            if relative.endswith(".dsse.v0.1.json")
            else "status-set",
        )
        files.append(_bundle_file_entry(chain_root, relative, role))
    exact_paths = sorted(
        [entry["path"] for entry in files] + [STATUS_CHAIN_OUTPUT_SET_PATH]
    )
    output = {
        "schema_version": SCHEMA_VERSION,
        "artifact_status": ARTIFACT_STATUS,
        "trust_domain_id": TRUST_DOMAIN,
        "exact_paths": exact_paths,
        "files": files,
        "self": {
            "path": STATUS_CHAIN_OUTPUT_SET_PATH,
            "digest_field": "output_set_digest",
        },
        "chain_tree_digest": manifest["chain_tree_digest"],
        "chain_manifest_digest": manifest["chain_manifest_digest"],
        "latest_revision": manifest["latest_revision"],
        "latest_status_set_digest": manifest["latest_status_set_digest"],
    }
    output["output_set_digest"] = domain_digest(STATUS_CHAIN_OUTPUT_SET_DOMAIN, output)
    return output


def generate_status_chain(
    root: Path,
    output_root: Path,
    relative_output: str,
    manifest_digest: str,
    variant: str,
) -> Path:
    output_root = resolve_trusted_directory(output_root)
    target = resolve_new_directory(output_root, relative_output)
    staging = target.with_name(target.name + ".partial")
    if os.path.lexists(staging):
        raise PublicReleaseError("partial status-chain output already exists")
    try:
        staging.mkdir(mode=0o700)
        _write_bundle_values(
            staging, build_status_chain_values(root, manifest_digest, variant)
        )
        output = build_status_chain_output_set(staging)
        validate_named_schema(
            output, "status_chain_output_set", load_public_release_schemas(root)
        )
        atomic_write_file(staging / STATUS_CHAIN_OUTPUT_SET_PATH, canonicalize(output))
        os.replace(staging, target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        raise
    return target


def _load_canonical_json_file(
    path: Path, *, schema_name: str | None = None, root: Path | None = None
) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = strict_loads(raw, max_bytes=MAX_BUNDLE_FILE_BYTES)
    except (OSError, ValueError) as error:
        raise PublicReleaseError("bundle JSON is invalid") from error
    if not isinstance(value, dict) or raw != canonicalize(value):
        raise PublicReleaseError("bundle JSON is not exact RFC 8785")
    if schema_name and root:
        validate_named_schema(value, schema_name, load_public_release_schemas(root))
    return value, raw


def _actual_bundle_paths(bundle_root: Path) -> list[str]:
    if bundle_root.is_symlink() or not bundle_root.is_dir():
        raise VerificationFailure("invalid-structure", 1, "bundle-root-invalid")
    paths: list[str] = []
    for path in bundle_root.rglob("*"):
        if path.is_symlink():
            raise VerificationFailure("invalid-structure", 1, "bundle-symlink")
        if path.is_dir():
            continue
        try:
            mode = path.stat().st_mode
        except OSError as error:
            raise VerificationFailure(
                "incomplete-bundle", 1, "bundle-path-unavailable"
            ) from error
        if not stat.S_ISREG(mode) or path.stat().st_size > MAX_BUNDLE_FILE_BYTES:
            raise VerificationFailure("invalid-structure", 1, "bundle-file-invalid")
        relative = path.relative_to(bundle_root).as_posix()
        validate_relative_path(relative)
        paths.append(relative)
    if len(paths) > MAX_BUNDLE_FILES:
        raise VerificationFailure("invalid-structure", 1, "bundle-file-count")
    return sorted(paths)


def validate_output_set(root: Path, bundle_root: Path) -> dict[str, Any]:
    actual_paths = _actual_bundle_paths(bundle_root)
    if OUTPUT_SET_PATH not in actual_paths:
        raise VerificationFailure("incomplete-bundle", 1, "output-set-missing")
    try:
        output, raw = _load_canonical_json_file(
            bundle_root / OUTPUT_SET_PATH, schema_name="output_set", root=root
        )
    except PublicReleaseError as error:
        raise VerificationFailure(
            "invalid-structure", 1, "output-set-invalid"
        ) from error
    if output.get("output_set_digest") != detached_digest(
        OUTPUT_SET_DOMAIN, output, "output_set_digest"
    ):
        raise VerificationFailure("invalid-structure", 1, "output-set-digest")
    if output.get("exact_paths") != actual_paths:
        raise VerificationFailure("incomplete-bundle", 1, "output-path-set")
    entries = output.get("files")
    if not isinstance(entries, list):
        raise VerificationFailure("invalid-structure", 1, "output-file-list")
    listed: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "file_digest",
            "size",
            "role",
        }:
            raise VerificationFailure("invalid-structure", 1, "output-file-entry")
        relative = entry["path"]
        if relative in listed or relative == OUTPUT_SET_PATH:
            raise VerificationFailure("invalid-structure", 1, "output-file-duplicate")
        listed.add(relative)
        try:
            path = resolve_regular_file(
                bundle_root, relative, max_bytes=MAX_BUNDLE_FILE_BYTES
            )
            data = path.read_bytes()
        except Exception as error:
            raise VerificationFailure(
                "incomplete-bundle", 1, "output-file-missing"
            ) from error
        if entry["file_digest"] != file_digest(data) or entry["size"] != len(data):
            raise VerificationFailure("incomplete-bundle", 1, "output-file-digest")
    if sorted(listed | {OUTPUT_SET_PATH}) != actual_paths:
        raise VerificationFailure("incomplete-bundle", 1, "output-file-closure")
    if output.get("bundle_tree_digest") != domain_digest(CONTENT_TREE_DOMAIN, entries):
        raise VerificationFailure("invalid-structure", 1, "output-tree-digest")
    if raw != canonicalize(output):
        raise VerificationFailure("invalid-structure", 1, "output-set-bytes")
    try:
        expected = build_output_set_from_directory(bundle_root)
    except Exception as error:
        raise VerificationFailure(
            "invalid-structure", 1, "output-set-reconstruction"
        ) from error
    if output != expected:
        raise VerificationFailure("invalid-structure", 1, "output-set-reconstruction")
    return output


def _load_bundle_records(
    root: Path, bundle_root: Path, manifest: dict[str, Any]
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    schemas = load_public_release_schemas(root)
    records: dict[str, dict[str, Any]] = {}
    artifacts: dict[str, dict[str, Any]] = {}
    entries = manifest.get("content_files")
    if not isinstance(entries, list):
        raise VerificationFailure("invalid-structure", 1, "content-manifest-invalid")
    expected_tree = domain_digest(CONTENT_TREE_DOMAIN, entries)
    if manifest.get("content_tree_digest") != expected_tree:
        raise VerificationFailure("invalid-structure", 1, "content-tree-digest")
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "file_digest",
            "size",
            "role",
        }:
            raise VerificationFailure("invalid-structure", 1, "content-entry-invalid")
        relative = entry["path"]
        if relative in seen:
            raise VerificationFailure("invalid-structure", 1, "content-path-duplicate")
        seen.add(relative)
        try:
            path = resolve_regular_file(
                bundle_root, relative, max_bytes=MAX_BUNDLE_FILE_BYTES
            )
            raw = path.read_bytes()
            value = strict_loads(raw, max_bytes=MAX_BUNDLE_FILE_BYTES)
        except Exception as error:
            raise VerificationFailure(
                "incomplete-bundle", 1, "content-file-unavailable"
            ) from error
        if raw != canonicalize(value):
            raise VerificationFailure(
                "invalid-structure", 1, "content-json-noncanonical"
            )
        if entry["file_digest"] != file_digest(raw) or entry["size"] != len(raw):
            raise VerificationFailure("incomplete-bundle", 1, "content-file-digest")
        if not isinstance(value, dict):
            raise VerificationFailure("invalid-structure", 1, "content-file-shape")
        if relative.startswith("records/"):
            record_id = value.get("id")
            record_type = value.get("record_type")
            if (
                not isinstance(record_id, str)
                or record_id in records
                or record_type not in A1_SCHEMAS
            ):
                raise VerificationFailure("invalid-structure", 1, "record-identity")
            try:
                validate_named_schema(value, record_type, schemas)
            except PublicReleaseError as error:
                raise VerificationFailure(
                    "invalid-structure", 1, "record-schema"
                ) from error
            if _record_relative(value) != relative:
                raise VerificationFailure("invalid-structure", 1, "record-path")
            records[record_id] = value
        elif relative.startswith("artifacts/"):
            artifacts[relative] = value
        else:
            raise VerificationFailure("invalid-structure", 1, "content-path-role")
    required_artifacts = {
        "artifacts/fixture-release-artifact.json",
        "artifacts/sbom.cdx.json",
        "artifacts/build-provenance.v0.1.json",
    }
    if set(artifacts) != required_artifacts:
        raise VerificationFailure("incomplete-bundle", 1, "artifact-path-set")
    try:
        validate_fixture_records(records, schemas)
    except PublicReleaseError as error:
        raise VerificationFailure("invalid-structure", 1, "record-semantics") from error
    try:
        expected_artifacts = build_fixture_artifacts(root)
    except PublicReleaseError as error:
        raise VerificationFailure(
            "invalid-structure", 1, "fixture-artifact-authority"
        ) from error
    if artifacts != expected_artifacts:
        raise VerificationFailure(
            "invalid-structure", 1, "fixture-artifact-reconstruction"
        )
    return records, artifacts


def validate_status_set(
    root: Path,
    status_set: dict[str, Any],
    manifest_digest: str,
    trust_keys: dict[str, dict[str, Any]],
    verification_time: str,
) -> tuple[str, str]:
    schemas = load_public_release_schemas(root)
    try:
        validate_named_schema(status_set, "status_set", schemas)
    except PublicReleaseError as error:
        raise VerificationFailure(
            "invalid-structure", 1, "status-set-schema"
        ) from error
    if status_set.get("status_set_digest") != detached_digest(
        STATUS_SET_DOMAIN, status_set, "status_set_digest"
    ):
        raise VerificationFailure("invalid-structure", 1, "status-set-digest")
    if (
        status_set.get("artifact_status") != ARTIFACT_STATUS
        or status_set.get("trust_domain_id") != TRUST_DOMAIN
        or status_set.get("status_set_id") != "PMA-PUBLIC-RELEASE-STATUS-FIXTURE-V0-1"
        or status_set.get("signing_key_id") != STATUS_KEY_ID
        or not isinstance(status_set.get("revision"), int)
        or status_set.get("revision", 0) < 1
    ):
        raise VerificationFailure("invalid-structure", 1, "status-set-authority")
    if (
        status_set.get("revision") == 1
        and status_set.get("previous_status_set_digest") is not None
    ) or (
        status_set.get("revision", 0) > 1
        and status_set.get("previous_status_set_digest") is None
    ):
        raise VerificationFailure("invalid-structure", 1, "status-set-chain")
    entries = status_set["key_statuses"] + status_set["release_statuses"]
    if status_set.get("entry_set_digest") != domain_digest(
        STATUS_ENTRY_SET_DOMAIN, entries
    ):
        raise VerificationFailure("invalid-structure", 1, "status-entry-set")
    for entry in entries:
        try:
            validate_named_schema(entry, "status_entry", schemas)
        except PublicReleaseError as error:
            raise VerificationFailure(
                "invalid-structure", 1, "status-entry-schema"
            ) from error
        if entry.get("status_entry_digest") != detached_digest(
            STATUS_ENTRY_DOMAIN, entry, "status_entry_digest"
        ):
            raise VerificationFailure("invalid-structure", 1, "status-entry-digest")
        if parse_timestamp(entry["effective_at"]) > parse_timestamp(verification_time):
            raise VerificationFailure("invalid-structure", 1, "status-entry-future")
    if status_set.get("signing_key_id") != STATUS_KEY_ID:
        raise VerificationFailure("untrusted-key", 3, "status-key-identity")
    status_signer = trust_keys.get(STATUS_KEY_ID)
    if not status_signer or status_signer.get("usage") != "release-status-signing":
        raise VerificationFailure("untrusted-key", 3, "status-key-usage")
    verification = parse_timestamp(verification_time)
    if (
        not (
            parse_timestamp(status_signer["valid_from"])
            <= verification
            <= parse_timestamp(status_signer["valid_until"])
        )
        or status_signer.get("status") != "active"
    ):
        raise VerificationFailure("untrusted-key", 3, "status-key-validity")
    key_entries = {entry["key_id"]: entry for entry in status_set["key_statuses"]}
    if len(key_entries) != len(status_set["key_statuses"]):
        raise VerificationFailure("invalid-structure", 1, "status-key-duplicate")
    if set(key_entries) != {RELEASE_KEY_ID}:
        raise VerificationFailure("untrusted-key", 3, "status-key-set")
    release_key_entry = key_entries.get(RELEASE_KEY_ID)
    if not release_key_entry or release_key_entry.get("usage") != "release-signing":
        raise VerificationFailure("untrusted-key", 3, "status-key-separation")
    if release_key_entry.get("status") == "revoked":
        if release_key_entry.get("compromise_indicator") is not True:
            raise VerificationFailure("invalid-structure", 1, "revocation-policy")
    elif release_key_entry.get("compromise_indicator") is not False:
        raise VerificationFailure("invalid-structure", 1, "revocation-policy")
    release_entries = [
        entry
        for entry in status_set["release_statuses"]
        if entry.get("release_id") == RELEASE_ID
        and entry.get("bundle_manifest_digest") == manifest_digest
    ]
    if len(release_entries) != 1 or len(status_set["release_statuses"]) != 1:
        raise VerificationFailure("invalid-structure", 1, "release-status-binding")
    release_entry = release_entries[0]
    state = release_entry["state"]
    if state in {"superseded", "corrected"} and (
        release_entry.get("replacement_release_id") is None
        or release_entry.get("replacement_bundle_digest") is None
    ):
        raise VerificationFailure("invalid-structure", 1, "replacement-binding")
    if state in {"superseded", "corrected"} and (
        release_entry.get("replacement_release_id") == RELEASE_ID
        or release_entry.get("replacement_bundle_digest") == manifest_digest
    ):
        raise VerificationFailure("invalid-structure", 1, "replacement-cycle")
    if state == "withdrawn" and release_entry.get("notice_digest") is None:
        raise VerificationFailure("invalid-structure", 1, "withdrawal-notice")
    if state in {"active", "expired"} and any(
        release_entry.get(field) is not None
        for field in (
            "replacement_release_id",
            "replacement_bundle_digest",
            "notice_digest",
        )
    ):
        raise VerificationFailure("invalid-structure", 1, "release-status-fields")
    if (
        state in {"superseded", "corrected"}
        and release_entry.get("notice_digest") is not None
    ):
        raise VerificationFailure("invalid-structure", 1, "release-status-fields")
    if state == "withdrawn" and (
        release_entry.get("replacement_release_id") is not None
        or release_entry.get("replacement_bundle_digest") is not None
    ):
        raise VerificationFailure("invalid-structure", 1, "release-status-fields")
    return release_key_entry["status"], state


def validate_status_chain(
    root: Path,
    chain_root: Path,
    manifest_digest: str,
    trust_keys: dict[str, dict[str, Any]],
    verification_time: str,
) -> tuple[dict[str, Any], str, str, dict[str, Any]]:
    """Validate every revision and return only the fully chained latest state."""
    try:
        chain_root = resolve_trusted_directory(chain_root)
        actual_paths = _actual_bundle_paths(chain_root)
    except Exception as error:
        raise VerificationFailure(
            "invalid-structure", 1, "status-chain-root-invalid"
        ) from error
    if STATUS_CHAIN_OUTPUT_SET_PATH not in actual_paths:
        raise VerificationFailure(
            "incomplete-bundle", 1, "status-chain-output-set-missing"
        )
    try:
        output, _ = _load_canonical_json_file(
            chain_root / STATUS_CHAIN_OUTPUT_SET_PATH,
            schema_name="status_chain_output_set",
            root=root,
        )
        chain_manifest, _ = _load_canonical_json_file(
            chain_root / STATUS_CHAIN_MANIFEST_PATH,
            schema_name="status_chain_manifest",
            root=root,
        )
    except PublicReleaseError as error:
        raise VerificationFailure(
            "invalid-structure", 1, "status-chain-structure"
        ) from error
    if output.get("output_set_digest") != detached_digest(
        STATUS_CHAIN_OUTPUT_SET_DOMAIN, output, "output_set_digest"
    ):
        raise VerificationFailure(
            "invalid-structure", 1, "status-chain-output-set-digest"
        )
    if chain_manifest.get("chain_manifest_digest") != detached_digest(
        STATUS_CHAIN_MANIFEST_DOMAIN,
        chain_manifest,
        "chain_manifest_digest",
    ):
        raise VerificationFailure(
            "invalid-structure", 1, "status-chain-manifest-digest"
        )
    if (
        chain_manifest.get("trust_domain_id") != TRUST_DOMAIN
        or chain_manifest.get("status_signing_key_id") != STATUS_KEY_ID
        or chain_manifest.get("status_signing_profile")
        != {
            "id": "private-match-public-release-signing",
            "version": SCHEMA_VERSION,
            "algorithm": ALGORITHM,
            "payload_type": STATUS_PAYLOAD_TYPE,
        }
        or chain_manifest.get("limitations")
        != [
            "The verifier cannot prove that a supplied offline status chain is the globally latest distributed revision."
        ]
    ):
        raise VerificationFailure("invalid-structure", 1, "status-chain-authority")
    status_signer = trust_keys.get(STATUS_KEY_ID)
    verification = parse_timestamp(verification_time)
    if (
        not status_signer
        or status_signer.get("usage") != "release-status-signing"
        or status_signer.get("status") != "active"
        or not (
            parse_timestamp(status_signer["valid_from"])
            <= verification
            <= parse_timestamp(status_signer["valid_until"])
        )
    ):
        raise VerificationFailure("untrusted-key", 3, "status-key-untrusted")
    entries = output.get("files")
    if not isinstance(entries, list):
        raise VerificationFailure("invalid-structure", 1, "status-chain-file-list")
    listed: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "file_digest",
            "size",
            "role",
        }:
            raise VerificationFailure("invalid-structure", 1, "status-chain-file-entry")
        relative = entry["path"]
        if relative in listed or relative == STATUS_CHAIN_OUTPUT_SET_PATH:
            raise VerificationFailure(
                "invalid-structure", 1, "status-chain-file-duplicate"
            )
        listed.add(relative)
        try:
            data = resolve_regular_file(
                chain_root, relative, max_bytes=MAX_BUNDLE_FILE_BYTES
            ).read_bytes()
        except Exception as error:
            raise VerificationFailure(
                "incomplete-bundle", 1, "status-chain-file-missing"
            ) from error
        if entry["file_digest"] != file_digest(data) or entry["size"] != len(data):
            raise VerificationFailure(
                "incomplete-bundle", 1, "status-chain-file-digest"
            )
    if (
        output.get("exact_paths") != actual_paths
        or sorted(listed | {STATUS_CHAIN_OUTPUT_SET_PATH}) != actual_paths
    ):
        raise VerificationFailure("incomplete-bundle", 1, "status-chain-path-closure")
    try:
        expected_output = build_status_chain_output_set(chain_root)
    except Exception as error:
        raise VerificationFailure(
            "invalid-structure", 1, "status-chain-output-reconstruction"
        ) from error
    if output != expected_output:
        raise VerificationFailure(
            "invalid-structure", 1, "status-chain-output-reconstruction"
        )
    revisions = chain_manifest.get("revisions")
    if not isinstance(revisions, list) or not revisions:
        raise VerificationFailure("invalid-structure", 1, "status-chain-revisions")
    expected_paths = {STATUS_CHAIN_MANIFEST_PATH, STATUS_CHAIN_OUTPUT_SET_PATH}
    previous_digest: str | None = None
    previous_time: dt.datetime | None = None
    latest: dict[str, Any] | None = None
    latest_key_status = "active"
    latest_release_state = "active"
    compromised_seen = False
    nonactive_release_seen = False
    tree_files: list[dict[str, Any]] = []
    for expected_revision, revision_entry in enumerate(revisions, start=1):
        if revision_entry.get("revision") != expected_revision:
            raise VerificationFailure(
                "invalid-structure", 1, "status-chain-revision-sequence"
            )
        set_path = status_revision_set_path(expected_revision)
        envelope_path = status_revision_envelope_path(expected_revision)
        expected_paths.update({set_path, envelope_path})
        if (
            revision_entry.get("status_set_path") != set_path
            or revision_entry.get("status_signature_path") != envelope_path
            or revision_entry.get("previous_status_set_digest") != previous_digest
        ):
            raise VerificationFailure(
                "invalid-structure", 1, "status-chain-revision-binding"
            )
        try:
            status_set, status_raw = _load_canonical_json_file(
                chain_root / set_path, schema_name="status_set", root=root
            )
            envelope, envelope_raw = _load_canonical_json_file(
                chain_root / envelope_path, schema_name="dsse", root=root
            )
        except PublicReleaseError as error:
            raise VerificationFailure(
                "invalid-structure", 1, "status-chain-revision-input"
            ) from error
        generated = parse_timestamp(status_set["generated_at"])
        if (
            status_set.get("revision") != expected_revision
            or status_set.get("previous_status_set_digest") != previous_digest
            or revision_entry.get("generated_at") != status_set.get("generated_at")
            or (previous_time is not None and generated <= previous_time)
        ):
            raise VerificationFailure(
                "invalid-structure", 1, "status-chain-revision-order"
            )
        if (
            revision_entry.get("status_set_digest")
            != status_set.get("status_set_digest")
            or revision_entry.get("status_set_file_digest") != file_digest(status_raw)
            or revision_entry.get("status_signature_digest")
            != file_digest(envelope_raw)
        ):
            raise VerificationFailure(
                "invalid-structure", 1, "status-chain-revision-digest"
            )
        if (
            envelope.get("payloadType") != STATUS_PAYLOAD_TYPE
            or envelope.get("signingProfile")
            != {
                "id": "private-match-public-release-signing",
                "version": SCHEMA_VERSION,
                "algorithm": ALGORITHM,
            }
            or not isinstance(envelope.get("signatures"), list)
            or len(envelope["signatures"]) != 1
            or envelope["signatures"][0].get("keyid") != STATUS_KEY_ID
        ):
            algorithm = envelope.get("signingProfile", {}).get("algorithm")
            if algorithm != ALGORITHM:
                raise VerificationFailure(
                    "unsupported-algorithm", 2, "status-algorithm-unsupported"
                )
            raise VerificationFailure("untrusted-key", 3, "status-key-identity")
        try:
            payload = verify_dsse_signature(
                root, envelope, STATUS_PAYLOAD_TYPE, status_signer
            )
        except PublicReleaseError as error:
            raise VerificationFailure(
                "invalid-signature", 1, "status-signature-invalid"
            ) from error
        if payload != status_raw:
            raise VerificationFailure("invalid-signature", 1, "status-payload-bytes")
        latest_key_status, latest_release_state = validate_status_set(
            root,
            status_set,
            manifest_digest,
            trust_keys,
            verification_time,
        )
        if compromised_seen and latest_key_status != "revoked":
            raise VerificationFailure(
                "invalid-structure", 1, "status-chain-key-state-rollback"
            )
        if nonactive_release_seen and latest_release_state == "active":
            raise VerificationFailure(
                "invalid-structure", 1, "status-chain-release-state-rollback"
            )
        compromised_seen = compromised_seen or latest_key_status == "revoked"
        nonactive_release_seen = (
            nonactive_release_seen or latest_release_state != "active"
        )
        tree_files.extend(
            [
                {
                    "path": set_path,
                    "file_digest": file_digest(status_raw),
                    "size": len(status_raw),
                    "role": "status-set",
                },
                {
                    "path": envelope_path,
                    "file_digest": file_digest(envelope_raw),
                    "size": len(envelope_raw),
                    "role": "status-signature",
                },
            ]
        )
        previous_digest = status_set["status_set_digest"]
        previous_time = generated
        latest = status_set
    if set(actual_paths) != expected_paths:
        raise VerificationFailure(
            "incomplete-bundle", 1, "status-chain-revision-path-set"
        )
    if latest is None or (
        chain_manifest.get("latest_revision") != latest["revision"]
        or chain_manifest.get("latest_status_set_digest") != latest["status_set_digest"]
        or chain_manifest.get("generated_at") != latest["generated_at"]
        or chain_manifest.get("chain_tree_digest")
        != domain_digest(
            STATUS_CHAIN_TREE_DOMAIN,
            sorted(tree_files, key=lambda item: item["path"]),
        )
        or output.get("chain_manifest_digest")
        != chain_manifest["chain_manifest_digest"]
        or output.get("chain_tree_digest") != chain_manifest["chain_tree_digest"]
        or output.get("latest_revision") != latest["revision"]
        or output.get("latest_status_set_digest") != latest["status_set_digest"]
    ):
        raise VerificationFailure("invalid-structure", 1, "status-chain-latest-binding")
    return (
        latest,
        latest_key_status,
        latest_release_state,
        {
            "chain_manifest_digest": chain_manifest["chain_manifest_digest"],
            "chain_output_set_digest": output["output_set_digest"],
            "latest_revision": latest["revision"],
            "latest_status_set_digest": latest["status_set_digest"],
        },
    )


def _verification_error_report(
    verification_time: str, failure: VerificationFailure
) -> dict[str, Any]:
    value = {
        "schema_version": SCHEMA_VERSION,
        "record_type": "public-release-verification-result",
        "artifact_status": ARTIFACT_STATUS,
        "verification_time": verification_time,
        "overall": {
            "status": failure.status,
            "reason_code": failure.reason_code,
            "limitations": RELEASE_LIMITATIONS,
        },
    }
    value["verification_result_digest"] = domain_digest(
        VERIFICATION_RESULT_DOMAIN, value
    )
    return value


def verify_public_release_bundle(
    root: Path,
    bundle_root: Path,
    trust_root_path: Path,
    status_chain_root: Path,
    verification_time: str,
) -> tuple[dict[str, Any], int]:
    """Verify immutable content against one caller-selected external status chain."""
    parse_timestamp(verification_time)
    try:
        try:
            bundle_root = resolve_trusted_directory(bundle_root)
            trust_root_path = resolve_external_regular_file(trust_root_path)
            status_chain_root = resolve_trusted_directory(status_chain_root)
        except Exception as error:
            raise VerificationFailure(
                "invalid-structure", 1, "verification-input-path"
            ) from error
        output = validate_output_set(root, bundle_root)
        schemas = load_public_release_schemas(root)
        try:
            trust, _ = _load_canonical_json_file(trust_root_path)
            trust_keys = validate_trust_root(root, trust, schemas)
        except PublicReleaseError as error:
            raise VerificationFailure(
                "untrusted-key", 3, "trust-root-invalid"
            ) from error

        try:
            manifest, manifest_raw = _load_canonical_json_file(
                bundle_root / MANIFEST_PATH
            )
            release_envelope, _ = _load_canonical_json_file(
                bundle_root / RELEASE_ENVELOPE_PATH, schema_name="dsse", root=root
            )
        except PublicReleaseError as error:
            raise VerificationFailure(
                "invalid-structure", 1, "release-envelope-structure"
            ) from error
        algorithm = release_envelope.get("signingProfile", {}).get("algorithm")
        if (
            algorithm != ALGORITHM
            or manifest.get("signing", {}).get("algorithm") != ALGORITHM
        ):
            raise VerificationFailure(
                "unsupported-algorithm", 2, "release-algorithm-unsupported"
            )
        if (
            release_envelope.get("payloadType") != RELEASE_PAYLOAD_TYPE
            or release_envelope.get("signingProfile", {}).get("id")
            != "private-match-public-release-signing"
            or release_envelope.get("signingProfile", {}).get("version")
            != SCHEMA_VERSION
        ):
            raise VerificationFailure(
                "unsupported-algorithm", 2, "release-profile-unsupported"
            )
        if (
            not isinstance(release_envelope.get("signatures"), list)
            or len(release_envelope["signatures"]) != 1
        ):
            raise VerificationFailure("invalid-signature", 1, "release-signature-count")
        release_key = trust_keys.get(RELEASE_KEY_ID)
        if not release_key or release_key.get("usage") != "release-signing":
            raise VerificationFailure("untrusted-key", 3, "release-key-untrusted")
        verification = parse_timestamp(verification_time)
        if (
            not (
                parse_timestamp(release_key["valid_from"])
                <= verification
                <= parse_timestamp(release_key["valid_until"])
            )
            or release_key.get("status") != "active"
        ):
            raise VerificationFailure("untrusted-key", 3, "release-key-validity")
        try:
            payload = verify_dsse_signature(
                root, release_envelope, RELEASE_PAYLOAD_TYPE, release_key
            )
        except PublicReleaseError as error:
            if "unsupported" in str(error):
                raise VerificationFailure(
                    "unsupported-algorithm", 2, "release-profile-unsupported"
                ) from error
            if "trusted" in str(error):
                raise VerificationFailure(
                    "untrusted-key", 3, "release-key-untrusted"
                ) from error
            raise VerificationFailure(
                "invalid-signature", 1, "release-signature-invalid"
            ) from error
        if payload != manifest_raw:
            raise VerificationFailure("invalid-signature", 1, "release-payload-bytes")
        try:
            validate_named_schema(manifest, "manifest", schemas)
        except PublicReleaseError as error:
            raise VerificationFailure(
                "invalid-structure", 1, "manifest-schema"
            ) from error
        if manifest.get("manifest_digest") != detached_jcs_sha256(
            manifest, "manifest_digest"
        ):
            raise VerificationFailure("invalid-structure", 1, "manifest-digest")
        content_paths = [
            entry.get("path")
            for entry in manifest.get("content_files", [])
            if isinstance(entry, dict)
        ]
        expected_bundle_paths = sorted(
            content_paths
            + [
                MANIFEST_PATH,
                RELEASE_ENVELOPE_PATH,
                REPORT_JSON_PATH,
                REPORT_MD_PATH,
                OUTPUT_SET_PATH,
            ]
        )
        if output.get("exact_paths") != expected_bundle_paths:
            raise VerificationFailure("incomplete-bundle", 1, "manifest-path-closure")

        records, artifacts = _load_bundle_records(root, bundle_root, manifest)
        report_model = build_report_model(root, records, artifacts)
        expected_manifest = build_release_manifest(
            root, records, artifacts, report_model
        )
        if manifest != expected_manifest:
            raise VerificationFailure("invalid-structure", 1, "manifest-reconstruction")
        try:
            static_report, static_report_raw = _load_canonical_json_file(
                bundle_root / REPORT_JSON_PATH,
                schema_name="content_report",
                root=root,
            )
            static_markdown = resolve_regular_file(
                bundle_root, REPORT_MD_PATH, max_bytes=MAX_BUNDLE_FILE_BYTES
            ).read_bytes()
        except (OSError, PublicReleaseError) as error:
            raise VerificationFailure(
                "invalid-report-linkage", 1, "static-report-unavailable"
            ) from error
        report_model_digest = domain_digest(REPORT_MODEL_DOMAIN, report_model)
        if (
            static_report != report_model
            or static_report_raw != canonicalize(report_model)
            or static_markdown != render_content_markdown(report_model)
            or manifest["reports"]["json"]["report_model_digest"] != report_model_digest
            or manifest["reports"]["markdown"]["report_model_digest"]
            != report_model_digest
            or output.get("static_report_model_digest") != report_model_digest
            or output.get("manifest_digest") != manifest["manifest_digest"]
            or output.get("release_signature_digest")
            != file_digest((bundle_root / RELEASE_ENVELOPE_PATH).read_bytes())
        ):
            raise VerificationFailure(
                "invalid-report-linkage", 1, "static-report-linkage-invalid"
            )

        status_set, key_status, release_state, status_chain = validate_status_chain(
            root,
            status_chain_root,
            manifest["manifest_digest"],
            trust_keys,
            verification_time,
        )
        claim_evaluation = evaluate_claims(records, verification_time)
        overall_status = "verified-fixture-with-limitations"
        exit_code = 0
        if key_status == "revoked":
            overall_status, exit_code = "revoked-key", 3
        elif key_status != "active":
            overall_status, exit_code = "untrusted-key", 3
        elif verification < parse_timestamp(manifest["valid_from"]):
            overall_status, exit_code = "expired-release", 4
        elif verification > parse_timestamp(manifest["valid_until"]):
            overall_status, exit_code = "expired-release", 4
        elif release_state in {
            "withdrawn",
            "superseded",
            "corrected",
            "expired",
        }:
            overall_status, exit_code = f"{release_state}-release", 4
        elif release_state != "active":
            raise VerificationFailure("invalid-structure", 1, "release-status-unknown")
        elif any(
            result["result"] in {"not-supported", "invalid-reference"}
            for result in claim_evaluation["results"]
        ):
            overall_status, exit_code = "claims-not-supported", 5
        elif any(
            result["result"] == "not-evaluated"
            for result in claim_evaluation["results"]
        ):
            overall_status, exit_code = "not-evaluated", 5

        runtime_report = build_verification_report(
            manifest,
            report_model,
            status_set,
            status_chain=status_chain,
            overall_status=overall_status,
            key_status=key_status,
            release_state=release_state,
            verification_time=verification_time,
            claim_evaluation=claim_evaluation,
        )
        validate_named_schema(runtime_report, "verification_result", schemas)
        return runtime_report, exit_code
    except VerificationFailure as failure:
        return _verification_error_report(verification_time, failure), failure.exit_code


def generate_fixture_suite(root: Path, output_root: Path, relative_output: str) -> Path:
    """Generate one immutable bundle, six external chains, and dynamic results."""
    output_root = resolve_trusted_directory(output_root)
    target = resolve_new_directory(output_root, relative_output)
    staging = target.with_name(target.name + ".partial")
    if os.path.lexists(staging):
        raise PublicReleaseError("partial public release suite already exists")
    try:
        staging.mkdir(mode=0o700)
        bundle = generate_fixture_bundle(root, staging, "bundle")
        manifest = read_strict_json(bundle / MANIFEST_PATH)
        (staging / "status-chains").mkdir(mode=0o700)
        for variant, policy in STATUS_CHAIN_VARIANTS.items():
            chain = generate_status_chain(
                root,
                staging / "status-chains",
                variant,
                manifest["manifest_digest"],
                variant,
            )
            result, code = verify_public_release_bundle(
                root,
                bundle,
                root / TRUST_ROOT_PATH,
                chain,
                VERIFICATION_TIME,
            )
            if (
                result["overall"]["status"] != policy["expected_overall"]
                or code != policy["expected_exit_code"]
            ):
                raise PublicReleaseError("generated lifecycle fixture is invalid")
            result_root = staging / "verification-results" / variant
            result_root.mkdir(parents=True)
            atomic_write_file(
                result_root / VERIFICATION_RESULT_JSON_FILENAME,
                canonicalize(result),
            )
            atomic_write_file(
                result_root / VERIFICATION_RESULT_MD_FILENAME,
                render_verification_markdown(result),
            )
        os.replace(staging, target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        raise
    return target


NEGATIVE_FIXTURE_CASES = [
    ("manifest-byte-mutation", "invalid-signature", 1),
    ("dsse-payload-type-mutation", "unsupported-algorithm", 2),
    ("signature-mutation", "invalid-signature", 1),
    ("unknown-key", "untrusted-key", 3),
    ("unknown-algorithm", "unsupported-algorithm", 2),
    ("revoked-release-key", "revoked-key", 3),
    ("expired-key", "untrusted-key", 3),
    ("expired-release", "expired-release", 4),
    ("withdrawn-release", "withdrawn-release", 4),
    ("superseded-release", "superseded-release", 4),
    ("corrected-release", "corrected-release", 4),
    ("missing-artifact", "incomplete-bundle", 1),
    ("extra-artifact", "incomplete-bundle", 1),
    ("report-linkage-mismatch", "invalid-report-linkage", 1),
    ("missing-evidence-reference", "claims-not-supported", 5),
    ("evidence-fail", "claims-not-supported", 5),
    ("evidence-unsupported", "not-evaluated", 5),
    ("evidence-superseded", "claims-not-supported", 5),
    ("evidence-withdrawn", "claims-not-supported", 5),
    ("claim-not-yet-valid", "not-evaluated", 5),
    ("claim-expired-at-verification-time", "not-evaluated", 5),
    ("assumption-invalidated", "claims-not-supported", 5),
    ("assumption-expired", "not-evaluated", 5),
    ("claim-supported-with-assumption", "invalid-structure", 1),
    ("claim-supported-without-required-assumption", "invalid-structure", 1),
    ("malformed-trust-root", "untrusted-key", 3),
    ("invalid-status-signature", "invalid-signature", 1),
    ("embedded-untrusted-key", "untrusted-key", 3),
    ("status-chain-revision-2-without-1", "incomplete-bundle", 1),
    ("status-chain-duplicate-revision", "invalid-structure", 1),
    ("status-chain-revision-gap", "invalid-structure", 1),
    ("status-chain-revision-rollback", "invalid-structure", 1),
    ("status-chain-wrong-previous-digest", "invalid-structure", 1),
    ("status-chain-forked-previous-digest", "invalid-structure", 1),
    ("status-chain-nonincreasing-generated-at", "invalid-structure", 1),
    ("status-chain-wrong-status-key", "untrusted-key", 3),
    ("status-chain-release-key-signature", "untrusted-key", 3),
    ("status-chain-unknown-algorithm", "unsupported-algorithm", 2),
    ("status-chain-wrong-trust-domain", "invalid-structure", 1),
    ("status-chain-invalid-intermediate-signature", "invalid-signature", 1),
    ("status-chain-valid-latest-after-invalid-earlier", "invalid-signature", 1),
    ("status-chain-extra-unlisted-revision", "incomplete-bundle", 1),
    ("status-chain-missing-listed-revision", "incomplete-bundle", 1),
    ("status-chain-changed-status-bytes", "incomplete-bundle", 1),
    ("status-chain-changed-envelope-bytes", "incomplete-bundle", 1),
    ("status-chain-manifest-digest-mismatch", "invalid-structure", 1),
    ("status-chain-tree-digest-mismatch", "invalid-structure", 1),
    ("status-chain-output-set-mismatch", "invalid-structure", 1),
    ("status-chain-latest-revision-mismatch", "invalid-structure", 1),
    ("status-chain-different-release-manifest", "invalid-structure", 1),
    ("status-key-self-authority", "untrusted-key", 3),
    ("status-chain-active-after-revoked", "invalid-structure", 1),
]


def build_fixture_catalog(
    root: Path, bundle_root: Path | None = None
) -> dict[str, Any]:
    bundle = bundle_root or root / EXPECTED_BUNDLE_PATH
    expected_root = bundle.parent
    trust = read_strict_json(resolve_regular_file(root, TRUST_ROOT_PATH))
    manifest = read_strict_json(bundle / MANIFEST_PATH)
    output_set = read_strict_json(bundle / OUTPUT_SET_PATH)
    catalog = {
        "schema_version": SCHEMA_VERSION,
        "artifact_status": ARTIFACT_STATUS,
        "release_bundle": {
            "fixture_id": FIXTURE_ID,
            "bundle_path": bundle.relative_to(root).as_posix()
            if bundle.is_relative_to(root)
            else EXPECTED_BUNDLE_PATH,
            "manifest_digest": manifest["manifest_digest"],
            "release_signature_digest": file_digest(
                (bundle / RELEASE_ENVELOPE_PATH).read_bytes()
            ),
            "static_report_model_digest": output_set["static_report_model_digest"],
            "output_set_digest": output_set["output_set_digest"],
            "file_count": len(output_set["exact_paths"]),
        },
        "trust_root": {
            "path": TRUST_ROOT_PATH,
            "digest": trust["trust_root_digest"],
            "release_key_id": RELEASE_KEY_ID,
            "status_key_id": STATUS_KEY_ID,
        },
        "status_chains": [],
        "negative_cases": [
            {
                "case_id": identifier,
                "expected_overall": overall,
                "expected_exit_code": code,
            }
            for identifier, overall, code in NEGATIVE_FIXTURE_CASES
        ],
    }
    for variant, policy in STATUS_CHAIN_VARIANTS.items():
        chain_root = expected_root / "status-chains" / variant
        chain_manifest = read_strict_json(chain_root / STATUS_CHAIN_MANIFEST_PATH)
        chain_output = read_strict_json(chain_root / STATUS_CHAIN_OUTPUT_SET_PATH)
        result_root = expected_root / "verification-results" / variant
        result_json = result_root / VERIFICATION_RESULT_JSON_FILENAME
        result_markdown = result_root / VERIFICATION_RESULT_MD_FILENAME
        result = read_strict_json(result_json)
        catalog["status_chains"].append(
            {
                "fixture_id": f"PUBLIC-RELEASE-STATUS-{variant.upper()}-V0-1",
                "chain_root": (
                    chain_root.relative_to(root).as_posix()
                    if chain_root.is_relative_to(root)
                    else f"{EXPECTED_STATUS_CHAINS_PATH}/{variant}"
                ),
                "latest_revision": chain_manifest["latest_revision"],
                "latest_status_set_digest": chain_manifest["latest_status_set_digest"],
                "chain_manifest_digest": chain_manifest["chain_manifest_digest"],
                "chain_output_set_digest": chain_output["output_set_digest"],
                "expected_overall": policy["expected_overall"],
                "expected_exit_code": policy["expected_exit_code"],
                "verification_time": VERIFICATION_TIME,
                "verification_json_path": (
                    result_json.relative_to(root).as_posix()
                    if result_json.is_relative_to(root)
                    else f"{EXPECTED_VERIFICATION_RESULTS_PATH}/{variant}/{VERIFICATION_RESULT_JSON_FILENAME}"
                ),
                "verification_json_digest": file_digest(result_json.read_bytes()),
                "verification_result_digest": result["verification_result_digest"],
                "verification_markdown_path": (
                    result_markdown.relative_to(root).as_posix()
                    if result_markdown.is_relative_to(root)
                    else f"{EXPECTED_VERIFICATION_RESULTS_PATH}/{variant}/{VERIFICATION_RESULT_MD_FILENAME}"
                ),
                "verification_markdown_digest": file_digest(
                    result_markdown.read_bytes()
                ),
            }
        )
    catalog["catalog_digest"] = domain_digest(FIXTURE_CATALOG_DOMAIN, catalog)
    return catalog


def validate_fixture_catalog(root: Path) -> dict[str, Any]:
    schemas = load_public_release_schemas(root)
    catalog = read_strict_json(resolve_regular_file(root, FIXTURE_CATALOG_PATH))
    if not isinstance(catalog, dict):
        raise PublicReleaseError("fixture catalog is invalid")
    validate_named_schema(catalog, "fixture_catalog", schemas)
    if catalog.get("catalog_digest") != detached_digest(
        FIXTURE_CATALOG_DOMAIN, catalog, "catalog_digest"
    ):
        raise PublicReleaseError("fixture catalog digest is invalid")
    if len(catalog["status_chains"]) != len(STATUS_CHAIN_VARIANTS) or len(
        catalog["negative_cases"]
    ) != len(NEGATIVE_FIXTURE_CASES):
        raise PublicReleaseError("fixture catalog coverage is incomplete")
    expected = build_fixture_catalog(root)
    if catalog != expected:
        raise PublicReleaseError("fixture catalog does not match expected fixtures")
    for entry in catalog["status_chains"]:
        result, code = verify_public_release_bundle(
            root,
            root / catalog["release_bundle"]["bundle_path"],
            root / catalog["trust_root"]["path"],
            root / entry["chain_root"],
            entry["verification_time"],
        )
        if (
            code != entry["expected_exit_code"]
            or result["overall"]["status"] != entry["expected_overall"]
            or canonicalize(result)
            != (root / entry["verification_json_path"]).read_bytes()
            or render_verification_markdown(result)
            != (root / entry["verification_markdown_path"]).read_bytes()
        ):
            raise PublicReleaseError("fixture catalog verifier result is stale")
    return catalog
