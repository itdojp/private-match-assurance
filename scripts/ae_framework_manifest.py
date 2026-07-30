#!/usr/bin/env python3
"""Build and verify the exact reviewed ae-framework vendored source manifest."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
import re
from typing import Any

try:
    from ae_assurance_common import (
        AssuranceIntegrationError,
        canonical_json_bytes,
        path_entry,
        read_strict_json,
        resolve_regular_file,
    )
    from canonical_json import domain_digest, file_digest
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import (
        AssuranceIntegrationError,
        canonical_json_bytes,
        path_entry,
        read_strict_json,
        resolve_regular_file,
    )
    from scripts.canonical_json import domain_digest, file_digest


SOURCE_COMMIT = "bba9b6846608359b87ed5393cb208e321f3ba8af"
REPOSITORY = "itdojp/ae-framework"
PACKAGE_NAME = "ae-framework"
PACKAGE_VERSION = "1.0.0"
PACKAGE_JSON_DIGEST = (
    "sha256:c8dddb23b4c883d84ec94d98cc501258a6784d0e6f4d5521aeaab8abf533be2c"
)
LICENSE = "Apache-2.0"
MANIFEST_PATH = Path("vendor/ae-framework/source-manifest.v0.1.json")
SOURCE_TREE_DOMAIN = "private-match-ae-framework-vendored-source-tree/v0.1"
MANIFEST_DOMAIN = "private-match-ae-framework-source-manifest/v0.1"
VENDORED_PATHS = (
    "vendor/ae-framework/schema/artifact-metadata.schema.json",
    "vendor/ae-framework/schema/assurance-profile.schema.json",
    "vendor/ae-framework/schema/assurance-summary.schema.json",
    "vendor/ae-framework/schema/formal-execution-evidence-v1.schema.json",
    "vendor/ae-framework/schema/formal-summary-v1.schema.json",
    "vendor/ae-framework/schema/formal-summary-v2.schema.json",
    "vendor/ae-framework/scripts/assurance/aggregate-lanes.mjs",
    "vendor/ae-framework/scripts/ci/lib/artifact-metadata.mjs",
    "vendor/ae-framework/scripts/formal/execution-evidence.mjs",
)
ROLES = {
    "vendor/ae-framework/scripts/assurance/aggregate-lanes.mjs": "native-assurance-entrypoint",
    "vendor/ae-framework/scripts/ci/lib/artifact-metadata.mjs": "runtime-source-dependency",
    "vendor/ae-framework/scripts/formal/execution-evidence.mjs": "runtime-source-dependency",
    "vendor/ae-framework/schema/assurance-profile.schema.json": "native-input-schema",
    "vendor/ae-framework/schema/assurance-summary.schema.json": "native-output-schema",
    "vendor/ae-framework/schema/artifact-metadata.schema.json": "runtime-schema-dependency",
    "vendor/ae-framework/schema/formal-execution-evidence-v1.schema.json": "runtime-schema-dependency",
    "vendor/ae-framework/schema/formal-summary-v1.schema.json": "runtime-schema-dependency",
    "vendor/ae-framework/schema/formal-summary-v2.schema.json": "runtime-schema-dependency",
}
DEPENDENCIES = (
    {"name": "ajv", "version": "8.20.0", "license": "MIT"},
    {"name": "ajv-formats", "version": "2.1.1", "license": "MIT"},
    {"name": "yaml", "version": "2.8.3", "license": "ISC"},
)


def original_path(path: str) -> str:
    return path.removeprefix("vendor/ae-framework/")


def source_tree_digest(files: list[dict[str, str]]) -> str:
    material = [
        {"original_path": entry["original_path"], "digest": entry["digest"]}
        for entry in files
    ]
    return domain_digest(SOURCE_TREE_DOMAIN, material)


def manifest_digest(manifest: dict[str, Any]) -> str:
    material = copy.deepcopy(manifest)
    material.pop("manifest_digest", None)
    return domain_digest(MANIFEST_DOMAIN, material)


def build_source_manifest(root: Path) -> dict[str, Any]:
    files = []
    for path in VENDORED_PATHS:
        entry = path_entry(root, path)
        entry.update(
            {
                "original_path": original_path(path),
                "role": ROLES[path],
                "license": LICENSE,
            }
        )
        files.append(entry)
    manifest: dict[str, Any] = {
        "schema_version": "0.1",
        "artifact_status": "draft",
        "repository": REPOSITORY,
        "source_commit": SOURCE_COMMIT,
        "reviewed_package": {
            "name": PACKAGE_NAME,
            "version": PACKAGE_VERSION,
            "package_json_digest": PACKAGE_JSON_DIGEST,
        },
        "entrypoint": "vendor/ae-framework/scripts/assurance/aggregate-lanes.mjs",
        "files": files,
        "runtime_dependencies": list(DEPENDENCIES),
        "source_tree_digest": source_tree_digest(files),
        "license": LICENSE,
        "limitations": [
            "This is the minimum reviewed Assurance command closure, not the complete ae-framework repository.",
            "Native output is validated and reduced to a path-free deterministic projection before packaging.",
        ],
    }
    manifest["manifest_digest"] = manifest_digest(manifest)
    return manifest


def verify_source_manifest(manifest: Any, root: Path) -> None:
    if not isinstance(manifest, dict):
        raise AssuranceIntegrationError("source manifest must be an object")
    if manifest != build_source_manifest(root):
        raise AssuranceIntegrationError(
            "source manifest does not match the reviewed closure"
        )
    raw_entries = manifest.get("files")
    if not isinstance(raw_entries, list):
        raise AssuranceIntegrationError("source manifest files must be an array")
    entries: dict[str, str] = {}
    for entry in raw_entries:
        if not isinstance(entry, dict):
            raise AssuranceIntegrationError("source manifest entry is invalid")
        path = entry.get("path")
        digest = entry.get("digest")
        if not isinstance(path, str) or not isinstance(digest, str) or path in entries:
            raise AssuranceIntegrationError("source manifest entry is invalid")
        entries[path] = digest
    if set(entries) != set(VENDORED_PATHS):
        raise AssuranceIntegrationError("source manifest file set does not match")
    for path, digest in entries.items():
        actual = file_digest(
            resolve_regular_file(root, path, max_bytes=16_777_216).read_bytes()
        )
        if actual != digest:
            raise AssuranceIntegrationError("vendored source digest does not match")
    vendor_root = root / "vendor/ae-framework"
    actual_paths: set[str] = set()
    for path in vendor_root.rglob("*"):
        if path.is_symlink():
            raise AssuranceIntegrationError("vendored source tree contains a symlink")
        if path.is_file():
            actual_paths.add(path.relative_to(root).as_posix())
    if actual_paths != {*VENDORED_PATHS, MANIFEST_PATH.as_posix()}:
        raise AssuranceIntegrationError("vendored source tree path set does not match")
    entrypoint = resolve_regular_file(
        root,
        "vendor/ae-framework/scripts/assurance/aggregate-lanes.mjs",
        max_bytes=16_777_216,
    ).read_text(encoding="utf-8")
    local_imports = set(re.findall(r"from\s+['\"](\.\.?/[^'\"]+)['\"]", entrypoint))
    if local_imports != {
        "../ci/lib/artifact-metadata.mjs",
        "../formal/execution-evidence.mjs",
    }:
        raise AssuranceIntegrationError("vendored import closure does not match")
    runtime_schemas = {
        value
        for value in re.findall(r"'([^']+\.schema\.json)'", entrypoint)
        if "/" not in value
    }
    if runtime_schemas != {
        "artifact-metadata.schema.json",
        "formal-execution-evidence-v1.schema.json",
        "formal-summary-v1.schema.json",
        "formal-summary-v2.schema.json",
    }:
        raise AssuranceIntegrationError(
            "vendored runtime Schema closure does not match"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    expected = build_source_manifest(root)
    target = root / MANIFEST_PATH
    if args.write:
        target.write_bytes(canonical_json_bytes(expected))
        return 0
    actual = read_strict_json(target)
    verify_source_manifest(actual, root)
    if target.read_bytes() != canonical_json_bytes(expected):
        raise AssuranceIntegrationError("source manifest serialization is stale")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
