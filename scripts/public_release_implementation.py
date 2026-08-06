#!/usr/bin/env python3
"""Generate and validate the closed public release verifier implementation manifest."""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    from ae_assurance_common import (
        atomic_write_file,
        read_strict_json,
        resolve_regular_file,
    )
    from canonical_json import canonicalize, domain_digest, file_digest
    from public_release import (
        FIXTURE_CATALOG_PATH,
        IMPLEMENTATION_DOMAIN,
        IMPLEMENTATION_MANIFEST_PATH,
        STANDARDS_PATH,
        SIGNING_PROFILE_PATH,
        TRUST_ROOT_PATH,
        VERIFICATION_PROFILE_PATH,
        PublicReleaseError,
        detached_digest,
        load_public_release_schemas,
        validate_named_schema,
    )
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import (
        atomic_write_file,
        read_strict_json,
        resolve_regular_file,
    )
    from scripts.canonical_json import canonicalize, domain_digest, file_digest
    from scripts.public_release import (
        FIXTURE_CATALOG_PATH,
        IMPLEMENTATION_DOMAIN,
        IMPLEMENTATION_MANIFEST_PATH,
        STANDARDS_PATH,
        SIGNING_PROFILE_PATH,
        TRUST_ROOT_PATH,
        VERIFICATION_PROFILE_PATH,
        PublicReleaseError,
        detached_digest,
        load_public_release_schemas,
        validate_named_schema,
    )


IMPLEMENTATION_PATHS = (
    ".github/workflows/assurance-schema.yml",
    "REUSE.toml",
    "docs/SIGNED_PUBLIC_RELEASE.md",
    "docs/OFFLINE_PUBLIC_VERIFICATION.md",
    "docs/KEY_AND_REVOCATION_BOUNDARY.md",
    "docs/decisions/ADR-0004-SIGNED-PUBLIC-RELEASE.md",
    "package.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "requirements-build.txt",
    "requirements-dev.txt",
    STANDARDS_PATH,
    SIGNING_PROFILE_PATH,
    VERIFICATION_PROFILE_PATH,
    "schema/claim.schema.json",
    "schema/public-release-signing-standards.v0.1.schema.json",
    "schema/public-release-signing-profile.v0.1.schema.json",
    "schema/public-release-verification-profile.v0.1.schema.json",
    "schema/public-release-trust-root.v0.1.schema.json",
    "schema/public-release-status-entry.v0.1.schema.json",
    "schema/public-release-status-set.v0.1.schema.json",
    "schema/public-release-status-chain-manifest.v0.1.schema.json",
    "schema/public-release-status-chain-output-set.v0.1.schema.json",
    "schema/public-release-dsse-envelope.v0.1.schema.json",
    "schema/public-release-bundle-manifest.v0.1.schema.json",
    "schema/public-release-output-set.v0.1.schema.json",
    "schema/public-release-content-report.v0.1.schema.json",
    "schema/public-release-verification-result.v0.1.schema.json",
    "schema/public-release-fixture-catalog.v0.1.schema.json",
    "schema/public-release-verifier-implementation.v0.1.schema.json",
    "scripts/canonical_json.py",
    "scripts/ae_assurance_common.py",
    "scripts/public_release.py",
    "scripts/public_release_crypto.mjs",
    "scripts/generate_public_release_fixture.py",
    "scripts/sign_public_release_fixture.py",
    "scripts/verify_public_release_bundle.py",
    "scripts/public_release_implementation.py",
    "scripts/validate_public_release.py",
    "tests/test_public_release.py",
    FIXTURE_CATALOG_PATH,
    TRUST_ROOT_PATH,
    "tests/fixtures/public-release/keys/release-public.pem",
    "tests/fixtures/public-release/keys/status-public.pem",
    "tests/fixtures/public-release/keys/README.md",
)


def _role(path: str) -> str:
    if path.startswith(".github/workflows/"):
        return "workflow"
    if path.startswith("schema/"):
        return "schema"
    if path.startswith("scripts/"):
        return "source"
    if path.startswith("docs/"):
        return "narrative"
    if path.startswith("tests/"):
        return "fixture-or-test"
    if path.startswith("profiles/"):
        return "profile"
    if path.startswith("config/"):
        return "standards-authority"
    if path == "REUSE.toml":
        return "license-metadata"
    return "dependency-lock"


def build_manifest(root: Path) -> dict:
    paths = list(IMPLEMENTATION_PATHS)
    catalog = read_strict_json(root / FIXTURE_CATALOG_PATH)
    fixture_roots = [catalog["release_bundle"]["bundle_path"]]
    fixture_roots.extend(entry["chain_root"] for entry in catalog["status_chains"])
    for relative_root in fixture_roots:
        directory = root / relative_root
        paths.extend(
            path.relative_to(root).as_posix()
            for path in sorted(directory.rglob("*"))
            if path.is_file()
        )
    for entry in catalog["status_chains"]:
        paths.extend(
            [entry["verification_json_path"], entry["verification_markdown_path"]]
        )
    if len(paths) != len(set(paths)):
        raise PublicReleaseError("implementation path set contains a duplicate")
    files = []
    for relative in sorted(paths):
        path = resolve_regular_file(root, relative, max_bytes=8 * 1024 * 1024)
        files.append(
            {
                "path": relative,
                "digest": file_digest(path.read_bytes()),
                "role": _role(relative),
            }
        )
    standards = read_strict_json(root / STANDARDS_PATH)
    signing = read_strict_json(root / SIGNING_PROFILE_PATH)
    verification = read_strict_json(root / VERIFICATION_PROFILE_PATH)
    trust = read_strict_json(root / TRUST_ROOT_PATH)
    manifest = {
        "schema_version": "0.1",
        "artifact_status": "test-only",
        "implementation_id": "private-match-public-release-verifier",
        "implementation_version": "0.1",
        "runtimes": {"python": "3.12", "node": "22.22.2", "pnpm": "10.34.5"},
        "files": files,
        "exact_path_count": len(files),
        "bindings": {
            "standards_digest": standards["standards_digest"],
            "signing_profile_digest": signing["profile_digest"],
            "verification_profile_digest": verification["profile_digest"],
            "trust_root_digest": trust["trust_root_digest"],
            "fixture_catalog_digest": catalog["catalog_digest"],
            "package_digest": file_digest((root / "package.json").read_bytes()),
            "pnpm_lock_digest": file_digest((root / "pnpm-lock.yaml").read_bytes()),
            "pnpm_workspace_digest": file_digest(
                (root / "pnpm-workspace.yaml").read_bytes()
            ),
            "python_build_lock_digest": file_digest(
                (root / "requirements-build.txt").read_bytes()
            ),
            "python_dev_lock_digest": file_digest(
                (root / "requirements-dev.txt").read_bytes()
            ),
        },
    }
    manifest["implementation_digest"] = domain_digest(IMPLEMENTATION_DOMAIN, manifest)
    return manifest


def validate_manifest(root: Path, manifest: dict) -> None:
    schemas = load_public_release_schemas(root)
    validate_named_schema(manifest, "implementation", schemas)
    if manifest.get("implementation_digest") != detached_digest(
        IMPLEMENTATION_DOMAIN, manifest, "implementation_digest"
    ):
        raise PublicReleaseError("implementation digest is invalid")
    expected = build_manifest(root)
    if manifest != expected:
        raise PublicReleaseError("implementation manifest is stale")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.generate == args.check:
        parser.error("select exactly one of --generate or --check")
    root = Path(__file__).resolve().parents[1]
    try:
        expected = build_manifest(root)
        path = root / IMPLEMENTATION_MANIFEST_PATH
        if args.generate:
            atomic_write_file(path, canonicalize(expected))
            print(expected["implementation_digest"])
            return 0
        current = read_strict_json(path)
        validate_manifest(root, current)
        if path.read_bytes() != canonicalize(current):
            raise PublicReleaseError("implementation manifest bytes are not canonical")
        print(current["implementation_digest"])
        return 0
    except (OSError, PublicReleaseError):
        parser.exit(1, "public release implementation manifest validation failed\n")


if __name__ == "__main__":
    raise SystemExit(main())
