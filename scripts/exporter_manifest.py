#!/usr/bin/env python3
"""Build and verify the closed Evidence exporter implementation manifest."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

try:
    from canonical_json import canonicalize, domain_digest, file_digest
except ImportError:  # pragma: no cover - package import during unit tests
    from scripts.canonical_json import canonicalize, domain_digest, file_digest


VERSION = "0.1"
IMPLEMENTATION_DOMAIN = "private-match-evidence-exporter-implementation/v0.1"
MANIFEST_PATH = Path("manifests/evidence-exporter-implementation.v0.1.json")
SOURCE_PATHS = (
    "scripts/canonical_json.py",
    "scripts/export_public_evidence.py",
    "scripts/exporter_manifest.py",
    "scripts/validate_assurance.py",
)
SCHEMA_PATHS = (
    "schema/evidence-export-candidate.v0.1.schema.json",
    "schema/evidence-export-fixture-catalog.v0.1.schema.json",
    "schema/evidence-export-profile.v0.1.schema.json",
    "schema/evidence-exporter-implementation.v0.1.schema.json",
    "schema/public-evidence-export.v0.1.schema.json",
)
EVIDENCE_SCHEMA_PATH = "schema/evidence-item.schema.json"
LOCK_PATHS = ("requirements-build.txt", "requirements-dev.txt")


class ImplementationManifestError(ValueError):
    """Bounded implementation-manifest failure without file contents."""


def implementation_digest(manifest: dict[str, Any]) -> str:
    material = copy.deepcopy(manifest)
    material.pop("implementation_digest", None)
    return domain_digest(IMPLEMENTATION_DOMAIN, material)


def canonical_manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return canonicalize(manifest) + b"\n"


def manifest_file_digest(manifest: dict[str, Any]) -> str:
    return file_digest(canonical_manifest_bytes(manifest))


def _safe_file(root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise ImplementationManifestError(
            "implementation path is not repository-relative"
        )
    root = root.resolve()
    path = root.joinpath(candidate)
    current = root
    for part in candidate.parts:
        current = current / part
        if current.is_symlink():
            raise ImplementationManifestError("implementation path uses a symlink")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as error:
        raise ImplementationManifestError(
            "implementation file is missing or outside root"
        ) from error
    if not resolved.is_file():
        raise ImplementationManifestError("implementation entry is not a regular file")
    return resolved


def _entry(root: Path, relative: str) -> dict[str, str]:
    return {
        "path": relative,
        "digest": file_digest(_safe_file(root, relative).read_bytes()),
    }


def build_implementation_manifest(
    root: Path, expected_profile_digest: str
) -> dict[str, Any]:
    """Build a deterministic manifest from the reviewed, behavior-affecting set."""

    manifest: dict[str, Any] = {
        "schema_version": VERSION,
        "artifact_status": "draft",
        "exporter": {
            "identity": "private-match-assurance/evidence-exporter",
            "version": VERSION,
        },
        "source_files": [_entry(root, path) for path in sorted(SOURCE_PATHS)],
        "schema_files": [_entry(root, path) for path in sorted(SCHEMA_PATHS)],
        "evidence_schema_reference": _entry(root, EVIDENCE_SCHEMA_PATH),
        "dependency_lock_files": [_entry(root, path) for path in sorted(LOCK_PATHS)],
        "runtime_profile": {
            "python": "CPython 3.12",
            "platform": "Ubuntu 24.04 x86_64",
            "canonicalization": "RFC 8785",
            "canonicalization_implementation": "rfc8785-python 0.1.4",
        },
        "expected_export_profile_digest": expected_profile_digest,
    }
    manifest["implementation_digest"] = implementation_digest(manifest)
    return manifest


def _entry_map(entries: Any, label: str) -> dict[str, str]:
    if not isinstance(entries, list):
        raise ImplementationManifestError(f"{label} must be an array")
    result: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "digest"}:
            raise ImplementationManifestError(f"{label} contains an invalid entry")
        path = entry.get("path")
        digest = entry.get("digest")
        if not isinstance(path, str) or not isinstance(digest, str):
            raise ImplementationManifestError(f"{label} contains an invalid entry")
        if path in result:
            raise ImplementationManifestError(f"{label} contains a duplicate path")
        result[path] = digest
    return result


def verify_implementation_manifest(
    manifest: Any,
    root: Path,
    expected_profile_digest: str,
    *,
    verify_files: bool = True,
) -> None:
    """Fail closed unless the manifest and, optionally, repository files match."""

    if not isinstance(manifest, dict):
        raise ImplementationManifestError("implementation manifest must be an object")
    if manifest.get("expected_export_profile_digest") != expected_profile_digest:
        raise ImplementationManifestError(
            "implementation profile digest does not match"
        )
    if manifest.get("implementation_digest") != implementation_digest(manifest):
        raise ImplementationManifestError("implementation digest does not match")

    source = _entry_map(manifest.get("source_files"), "source_files")
    schemas = _entry_map(manifest.get("schema_files"), "schema_files")
    locks = _entry_map(manifest.get("dependency_lock_files"), "dependency_lock_files")
    evidence = manifest.get("evidence_schema_reference")
    if not isinstance(evidence, dict) or set(evidence) != {"path", "digest"}:
        raise ImplementationManifestError("evidence schema reference is invalid")
    if set(source) != set(SOURCE_PATHS):
        raise ImplementationManifestError("source file set does not match")
    if set(schemas) != set(SCHEMA_PATHS):
        raise ImplementationManifestError("schema file set does not match")
    if set(locks) != set(LOCK_PATHS):
        raise ImplementationManifestError("dependency lock set does not match")
    if evidence.get("path") != EVIDENCE_SCHEMA_PATH:
        raise ImplementationManifestError("Evidence Schema path does not match")

    if not verify_files:
        return
    for path, digest in {
        **source,
        **schemas,
        **locks,
        evidence["path"]: evidence["digest"],
    }.items():
        if file_digest(_safe_file(root, path).read_bytes()) != digest:
            raise ImplementationManifestError(
                "implementation file digest does not match"
            )
