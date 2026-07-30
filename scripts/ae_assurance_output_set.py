#!/usr/bin/env python3
"""Build and validate the exact ae Assurance JSON/Markdown output set."""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from ae_assurance_common import (
        AssuranceIntegrationError,
        build_schema_registry,
        canonical_json_bytes,
        read_strict_json,
        validate_schema_instance,
    )
    from ae_assurance_implementation import (
        adapter_source_digest,
        renderer_source_digest,
    )
    from ae_assurance_policy import (
        OUTPUT_SET_DOMAIN,
        load_authority,
        load_schemas,
    )
    from canonical_json import domain_digest, file_digest
    from render_ae_assurance_report import render_markdown
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import (
        AssuranceIntegrationError,
        build_schema_registry,
        canonical_json_bytes,
        read_strict_json,
        validate_schema_instance,
    )
    from scripts.ae_assurance_implementation import (
        adapter_source_digest,
        renderer_source_digest,
    )
    from scripts.ae_assurance_policy import (
        OUTPUT_SET_DOMAIN,
        load_authority,
        load_schemas,
    )
    from scripts.canonical_json import domain_digest, file_digest
    from scripts.render_ae_assurance_report import render_markdown


JSON_NAME = "private-match-assurance-package.v0.1.json"
MARKDOWN_NAME = "private-match-assurance-package.v0.1.md"
OUTPUT_SET_NAME = "private-match-assurance-output-set.v0.1.json"
EXACT_OUTPUT_NAMES = frozenset({JSON_NAME, MARKDOWN_NAME, OUTPUT_SET_NAME})


def build_output_set(
    root: Path,
    package: dict[str, Any],
    json_bytes: bytes,
    markdown_bytes: bytes,
) -> dict[str, Any]:
    """Bind exact report bytes without creating a package self-reference cycle."""

    pin, _inventory, profile = load_authority(root)
    manifest: dict[str, Any] = {
        "schema_version": "0.1",
        "artifact_status": package["artifact_status"],
        "execution_mode": package["execution_mode"],
        "package_digest": package["package_digest"],
        "json_report": {"path": JSON_NAME, "file_digest": file_digest(json_bytes)},
        "markdown_report": {
            "path": MARKDOWN_NAME,
            "file_digest": file_digest(markdown_bytes),
        },
        "renderer": {
            "id": "private-match-assurance/markdown-renderer",
            "version": "0.1",
            "implementation_digest": renderer_source_digest(root),
        },
        "adapter_implementation_digest": adapter_source_digest(root),
        "integration_profile_digest": profile["profile_digest"],
        "ae_framework_pin_digest": pin["pin_digest"],
    }
    manifest["output_set_digest"] = domain_digest(OUTPUT_SET_DOMAIN, manifest)
    schemas = load_schemas(root)
    validate_schema_instance(
        manifest,
        schemas["output_set"],
        registry=build_schema_registry(schemas.values()),
    )
    return manifest


def validate_output_directory(root: Path, output_directory: Path) -> dict[str, Any]:
    """Validate one exact, symlink-free three-file output directory."""

    if (
        any(item.is_symlink() for item in (output_directory, *output_directory.parents))
        or not output_directory.is_dir()
    ):
        raise AssuranceIntegrationError("output set directory is unavailable")
    entries = list(output_directory.iterdir())
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise AssuranceIntegrationError("output set contains a non-regular file")
    if {entry.name for entry in entries} != EXACT_OUTPUT_NAMES:
        raise AssuranceIntegrationError("output set path set does not match")

    package_path = output_directory / JSON_NAME
    markdown_path = output_directory / MARKDOWN_NAME
    manifest_path = output_directory / OUTPUT_SET_NAME
    package = read_strict_json(package_path, max_bytes=2_097_152)
    manifest = read_strict_json(manifest_path, max_bytes=1_048_576)
    if not isinstance(package, dict) or not isinstance(manifest, dict):
        raise AssuranceIntegrationError("output set artifact is invalid")
    try:
        from validate_ae_assurance import validate_package
    except ImportError:  # pragma: no cover
        from scripts.validate_ae_assurance import validate_package

    validate_package(root, package)
    json_bytes = package_path.read_bytes()
    markdown_bytes = markdown_path.read_bytes()
    if json_bytes != canonical_json_bytes(package):
        raise AssuranceIntegrationError("output JSON bytes are not canonical")
    if markdown_bytes != render_markdown(package).encode("utf-8"):
        raise AssuranceIntegrationError(
            "output Markdown does not match the JSON authority"
        )
    expected = build_output_set(root, package, json_bytes, markdown_bytes)
    if manifest != expected or manifest_path.read_bytes() != canonical_json_bytes(
        expected
    ):
        raise AssuranceIntegrationError(
            "output set manifest does not match exact bytes"
        )
    return manifest
