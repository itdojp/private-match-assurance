#!/usr/bin/env python3
"""Closed ae Assurance runner implementation inventory and digest."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
from typing import Any

try:
    from ae_assurance_common import (
        AssuranceIntegrationError,
        canonical_json_bytes,
        exact_entry_map,
        path_entry,
        read_strict_json,
        resolve_regular_file,
    )
    from ae_assurance_policy import (
        FIXTURE_CATALOG_PATH,
        PIN_PATH,
        PROFILE_PATH,
        TOOL_INVENTORY_PATH,
        load_authority,
        verify_fixture_catalog,
    )
    from ae_framework_manifest import MANIFEST_PATH as AE_SOURCE_MANIFEST_PATH
    from canonical_json import domain_digest, file_digest
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import (
        AssuranceIntegrationError,
        canonical_json_bytes,
        exact_entry_map,
        path_entry,
        read_strict_json,
        resolve_regular_file,
    )
    from scripts.ae_assurance_policy import (
        FIXTURE_CATALOG_PATH,
        PIN_PATH,
        PROFILE_PATH,
        TOOL_INVENTORY_PATH,
        load_authority,
        verify_fixture_catalog,
    )
    from scripts.ae_framework_manifest import MANIFEST_PATH as AE_SOURCE_MANIFEST_PATH
    from scripts.canonical_json import domain_digest, file_digest


MANIFEST_PATH = Path("manifests/ae-assurance-runner-implementation.v0.1.json")
IMPLEMENTATION_DOMAIN = "private-match-ae-assurance-runner-implementation/v0.1"
ADAPTER_SOURCE_DOMAIN = "private-match-ae-assurance-adapter-source/v0.1"
RENDERER_SOURCE_DOMAIN = "private-match-ae-assurance-markdown-renderer-source/v0.1"

SOURCE_PATHS = (
    "scripts/ae_assurance_common.py",
    "scripts/ae_assurance_implementation.py",
    "scripts/ae_assurance_policy.py",
    "scripts/ae_assurance_output_set.py",
    "scripts/ae_framework_adapter.py",
    "scripts/ae_framework_manifest.py",
    "scripts/generate_ae_assurance_fixtures.py",
    "scripts/render_ae_assurance_report.py",
    "scripts/run_ae_assurance.py",
    "scripts/validate_ae_assurance.py",
    "scripts/canonical_json.py",
)
SCHEMA_PATHS = (
    "schema/ae-assurance-fixture-catalog.v0.1.schema.json",
    "schema/ae-assurance-output-set.v0.1.schema.json",
    "schema/ae-assurance-runner-implementation.v0.1.schema.json",
    "schema/ae-assurance-tool-inventory.v0.1.schema.json",
    "schema/ae-assurance-tool-binding.v0.1.schema.json",
    "schema/ae-framework-integration-profile.v0.1.schema.json",
    "schema/ae-framework-pin.v0.1.schema.json",
    "schema/ae-framework-source-manifest.v0.1.schema.json",
    "schema/assurance-automated-judgment.v0.1.schema.json",
    "schema/assurance-human-approval.v0.1.schema.json",
    "schema/assurance-producer-gate-judgment.v0.1.schema.json",
    "schema/ae-native-judgment.v0.1.schema.json",
    "schema/evidence-item.schema.json",
    "schema/private-match-assurance-package.v0.1.schema.json",
    "schema/private-match-producer-package.v0.1.schema.json",
)
PROFILE_PATHS = (
    PROFILE_PATH,
    "profiles/private-match-ae-native-profile.v0.1.json",
)
AUTHORITY_PATHS = (PIN_PATH, AE_SOURCE_MANIFEST_PATH.as_posix())
TOOL_PATHS = (TOOL_INVENTORY_PATH,)
LOCK_PATHS = (
    "package.json",
    "pnpm-lock.yaml",
    "requirements-build.txt",
    "requirements-dev.txt",
)


def _entries(root: Path, paths: tuple[str, ...]) -> list[dict[str, str]]:
    return [path_entry(root, path) for path in sorted(paths)]


def adapter_source_digest(root: Path) -> str:
    """Digest behavior-affecting code/contracts without fixture-output cycles."""

    paths = sorted(
        {
            *SOURCE_PATHS,
            *SCHEMA_PATHS,
            *PROFILE_PATHS,
            *AUTHORITY_PATHS,
            *TOOL_PATHS,
            *LOCK_PATHS,
        }
    )
    material = [path_entry(root, path) for path in paths]
    return domain_digest(ADAPTER_SOURCE_DOMAIN, material)


def renderer_source_digest(root: Path) -> str:
    """Bind the exact renderer bytes separately from the broader adapter."""

    return domain_digest(
        RENDERER_SOURCE_DOMAIN,
        [path_entry(root, "scripts/render_ae_assurance_report.py")],
    )


def implementation_digest(manifest: dict[str, Any]) -> str:
    material = copy.deepcopy(manifest)
    material.pop("implementation_digest", None)
    return domain_digest(IMPLEMENTATION_DOMAIN, material)


def build_manifest(root: Path) -> dict[str, Any]:
    pin, inventory, profile = load_authority(root)
    catalog_path = resolve_regular_file(root, FIXTURE_CATALOG_PATH)
    catalog = read_strict_json(catalog_path)
    if not isinstance(catalog, dict):
        raise AssuranceIntegrationError("fixture catalog must be an object")
    verify_fixture_catalog(catalog)
    fixture_paths = [FIXTURE_CATALOG_PATH]
    for fixture in catalog["fixtures"]:
        fixture_paths.extend(
            [
                f"tests/fixtures/ae-framework/{fixture['input_path']}",
                f"tests/fixtures/ae-framework/{fixture['expected_json_path']}",
                f"tests/fixtures/ae-framework/{fixture['expected_markdown_path']}",
                f"tests/fixtures/ae-framework/{fixture['expected_output_set_path']}",
            ]
        )
    source_manifest = read_strict_json(
        resolve_regular_file(root, AE_SOURCE_MANIFEST_PATH.as_posix())
    )
    manifest: dict[str, Any] = {
        "schema_version": "0.1",
        "artifact_status": "draft",
        "runner": {
            "id": "private-match-assurance/ae-framework-adapter",
            "version": "0.1",
        },
        "source_files": _entries(root, SOURCE_PATHS),
        "schema_files": _entries(root, SCHEMA_PATHS),
        "profile_files": _entries(root, PROFILE_PATHS),
        "authority_files": _entries(root, AUTHORITY_PATHS),
        "tool_inventory_files": _entries(root, TOOL_PATHS),
        "fixture_trust_files": _entries(root, tuple(sorted(set(fixture_paths)))),
        "dependency_lock_files": _entries(root, LOCK_PATHS),
        "tested_runtime": {
            "python": "3.12",
            "node": "22.22.2",
            "operating_system": "Ubuntu 24.04",
            "architecture": "x86_64",
        },
        "bindings": {
            "profile_digest": profile["profile_digest"],
            "ae_framework_pin_digest": pin["pin_digest"],
            "ae_framework_source_tree_digest": source_manifest["source_tree_digest"],
            "tool_inventory_digest": inventory["inventory_digest"],
            "fixture_catalog_digest": catalog["catalog_digest"],
        },
        "adapter_source_digest": adapter_source_digest(root),
    }
    manifest["implementation_digest"] = implementation_digest(manifest)
    return manifest


def verify_manifest(manifest: Any, root: Path) -> None:
    if not isinstance(manifest, dict) or manifest != build_manifest(root):
        raise AssuranceIntegrationError("runner implementation manifest is stale")
    all_paths: list[str] = []
    for field in (
        "source_files",
        "schema_files",
        "profile_files",
        "authority_files",
        "tool_inventory_files",
        "fixture_trust_files",
        "dependency_lock_files",
    ):
        entries = exact_entry_map(manifest[field], field)
        all_paths.extend(entries)
        for path, digest in entries.items():
            if (
                file_digest(
                    resolve_regular_file(root, path, max_bytes=16_777_216).read_bytes()
                )
                != digest
            ):
                raise AssuranceIntegrationError(
                    "runner implementation file digest does not match"
                )
    if len(all_paths) != len(set(all_paths)):
        raise AssuranceIntegrationError("runner implementation paths overlap")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    target = root / MANIFEST_PATH
    if args.write:
        target.write_bytes(canonical_json_bytes(build_manifest(root)))
        return 0
    manifest = read_strict_json(target)
    verify_manifest(manifest, root)
    if target.read_bytes() != canonical_json_bytes(build_manifest(root)):
        raise AssuranceIntegrationError("runner implementation serialization is stale")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
