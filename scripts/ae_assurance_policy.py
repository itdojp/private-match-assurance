#!/usr/bin/env python3
"""Closed policy and authority validation for the ae Assurance integration."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

try:
    from ae_assurance_common import (
        AssuranceIntegrationError,
        PRODUCER_TYPES,
        STATUS_VALUES,
        build_schema_registry,
        load_schema,
        read_strict_json,
        resolve_regular_file,
        validate_schema_instance,
    )
    from ae_framework_manifest import (
        SOURCE_COMMIT,
        MANIFEST_PATH as SOURCE_MANIFEST_PATH,
        verify_source_manifest,
    )
    from canonical_json import domain_digest, file_digest
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import (
        AssuranceIntegrationError,
        PRODUCER_TYPES,
        STATUS_VALUES,
        build_schema_registry,
        load_schema,
        read_strict_json,
        resolve_regular_file,
        validate_schema_instance,
    )
    from scripts.ae_framework_manifest import (
        SOURCE_COMMIT,
        MANIFEST_PATH as SOURCE_MANIFEST_PATH,
        verify_source_manifest,
    )
    from scripts.canonical_json import domain_digest, file_digest


PIN_PATH = "config/ae-framework-pin.v0.1.json"
PROFILE_PATH = "profiles/private-match-ae-assurance.v0.1.json"
NATIVE_PROFILE_PATH = "profiles/private-match-ae-native-profile.v0.1.json"
TOOL_INVENTORY_PATH = "config/ae-assurance-tools.v0.1.json"
FIXTURE_CATALOG_PATH = "tests/fixtures/ae-framework/fixture-catalog.v0.1.json"

PIN_DOMAIN = "private-match-ae-framework-pin/v0.1"
PROFILE_DOMAIN = "private-match-ae-assurance-profile/v0.1"
TOOL_INVENTORY_DOMAIN = "private-match-ae-assurance-tool-inventory/v0.1"
PRODUCER_PACKAGE_DOMAIN = "private-match-ae-producer-package/v0.1"
FIXTURE_CATALOG_DOMAIN = "private-match-ae-assurance-fixture-catalog/v0.1"
ASSURANCE_CONTENT_DOMAIN = "private-match-ae-assurance-content/v0.1"
ASSURANCE_PACKAGE_DOMAIN = "private-match-ae-assurance-package/v0.1"
JSON_REPORT_DOMAIN = "private-match-ae-assurance-json-report/v0.1"
MARKDOWN_REPORT_DOMAIN = "private-match-ae-assurance-markdown-report/v0.1"
NATIVE_PROJECTION_DOMAIN = "private-match-ae-native-summary-projection/v0.1"
EVIDENCE_RECORD_DOMAIN = "private-match-ae-evidence-record/v0.1"

SCHEMA_PATHS = {
    "pin": "schema/ae-framework-pin.v0.1.schema.json",
    "source_manifest": "schema/ae-framework-source-manifest.v0.1.schema.json",
    "profile": "schema/ae-framework-integration-profile.v0.1.schema.json",
    "tools": "schema/ae-assurance-tool-inventory.v0.1.schema.json",
    "producer": "schema/private-match-producer-package.v0.1.schema.json",
    "automated": "schema/assurance-automated-judgment.v0.1.schema.json",
    "approval": "schema/assurance-human-approval.v0.1.schema.json",
    "package": "schema/private-match-assurance-package.v0.1.schema.json",
    "catalog": "schema/ae-assurance-fixture-catalog.v0.1.schema.json",
    "implementation": "schema/ae-assurance-runner-implementation.v0.1.schema.json",
    "evidence": "schema/evidence-item.schema.json",
}


def without_field(value: dict[str, Any], field: str) -> dict[str, Any]:
    material = copy.deepcopy(value)
    material.pop(field, None)
    return material


def artifact_digest(domain: str, value: dict[str, Any], field: str) -> str:
    return domain_digest(domain, without_field(value, field))


def load_schemas(root: Path) -> dict[str, dict[str, Any]]:
    return {name: load_schema(root, path) for name, path in SCHEMA_PATHS.items()}


def _load_validate(
    root: Path,
    relative: str,
    schema: dict[str, Any],
    *,
    schemas: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    value = read_strict_json(resolve_regular_file(root, relative))
    if not isinstance(value, dict):
        raise AssuranceIntegrationError("artifact must be an object")
    validate_schema_instance(
        value, schema, registry=build_schema_registry(schemas.values())
    )
    return value


def load_authority(root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Load and cross-check pin, tool inventory, and integration profile."""

    schemas = load_schemas(root)
    source_manifest = _load_validate(
        root,
        SOURCE_MANIFEST_PATH.as_posix(),
        schemas["source_manifest"],
        schemas=schemas,
    )
    verify_source_manifest(source_manifest, root)
    pin = _load_validate(root, PIN_PATH, schemas["pin"], schemas=schemas)
    inventory = _load_validate(
        root, TOOL_INVENTORY_PATH, schemas["tools"], schemas=schemas
    )
    profile = _load_validate(root, PROFILE_PATH, schemas["profile"], schemas=schemas)

    if pin["pin_digest"] != artifact_digest(PIN_DOMAIN, pin, "pin_digest"):
        raise AssuranceIntegrationError("ae-framework pin digest does not match")
    if inventory["inventory_digest"] != artifact_digest(
        TOOL_INVENTORY_DOMAIN, inventory, "inventory_digest"
    ):
        raise AssuranceIntegrationError("tool inventory digest does not match")
    if profile["profile_digest"] != artifact_digest(
        PROFILE_DOMAIN, profile, "profile_digest"
    ):
        raise AssuranceIntegrationError("integration profile digest does not match")

    source_binding = pin["source_manifest"]
    source_bytes = resolve_regular_file(
        root, SOURCE_MANIFEST_PATH.as_posix()
    ).read_bytes()
    if (
        pin["commit"] != SOURCE_COMMIT
        or source_binding["file_digest"] != file_digest(source_bytes)
        or source_binding["source_tree_digest"] != source_manifest["source_tree_digest"]
        or source_binding["manifest_digest"] != source_manifest["manifest_digest"]
    ):
        raise AssuranceIntegrationError("ae-framework source binding does not match")
    package_contract = read_strict_json(resolve_regular_file(root, "package.json"))
    if not isinstance(package_contract, dict) or package_contract != {
        "name": "private-match-assurance-tools",
        "version": "0.0.0",
        "private": True,
        "license": "Apache-2.0",
        "engines": {"node": "22.22.2"},
        "packageManager": "pnpm@10.34.5",
        "dependencies": {
            "ajv": "8.20.0",
            "ajv-formats": "2.1.1",
            "yaml": "2.8.3",
        },
    }:
        raise AssuranceIntegrationError("Node dependency contract does not match")
    if profile["ae_framework_authority"] != {
        "pin_path": PIN_PATH,
        "pin_digest": pin["pin_digest"],
    }:
        raise AssuranceIntegrationError("profile ae-framework binding does not match")

    tool_by_id: dict[str, dict[str, Any]] = {}
    mappings: dict[tuple[str, str], dict[str, Any]] = {}
    for tool in inventory["tools"]:
        tool_id = tool["tool_id"]
        if tool_id in tool_by_id:
            raise AssuranceIntegrationError("tool inventory contains duplicate IDs")
        if (
            tool["requirement"] == "required"
            and tool["absence_behavior"]
            not in {"unsupported-blocked", "tool-error-blocked"}
        ) or (
            tool["requirement"] == "optional"
            and tool["absence_behavior"] not in {"skip-visible", "unsupported-visible"}
        ):
            raise AssuranceIntegrationError(
                "tool absence behavior does not match its requirement"
            )
        tool_by_id[tool_id] = tool
        local_statuses: set[str] = set()
        for mapping in tool["status_mappings"]:
            raw = mapping["raw_producer_status"]
            if (
                mapping["normalized_evidence_status"] != raw
                or mapping["tool_id"] != tool_id
                or mapping["producer_type"] != tool["producer_type"]
                or raw in local_statuses
            ):
                raise AssuranceIntegrationError("tool status mapping is not exact")
            local_statuses.add(raw)
            mappings[(tool_id, raw)] = mapping
        if local_statuses != set(STATUS_VALUES):
            raise AssuranceIntegrationError("tool status mapping is incomplete")

    expected_types = {tool["producer_type"] for tool in inventory["tools"]}
    if expected_types != set(PRODUCER_TYPES):
        raise AssuranceIntegrationError("producer type inventory is incomplete")
    if profile["accepted_producer_types"] != list(PRODUCER_TYPES):
        raise AssuranceIntegrationError("accepted producer types are not closed")
    if profile["producer_status_mapping"] != [
        mappings[(tool["tool_id"], status)]
        for tool in inventory["tools"]
        for status in STATUS_VALUES
    ]:
        raise AssuranceIntegrationError(
            "profile status mappings do not match inventory"
        )
    required = [
        tool["tool_id"]
        for tool in inventory["tools"]
        if tool["requirement"] == "required"
    ]
    optional = [
        tool["tool_id"]
        for tool in inventory["tools"]
        if tool["requirement"] == "optional"
    ]
    if (
        profile["required_check_ids"] != required
        or profile["optional_check_ids"] != optional
    ):
        raise AssuranceIntegrationError(
            "profile tool requirements do not match inventory"
        )
    return pin, inventory, profile


def verify_producer_package(value: dict[str, Any]) -> None:
    if value.get("package_digest") != artifact_digest(
        PRODUCER_PACKAGE_DOMAIN, value, "package_digest"
    ):
        raise AssuranceIntegrationError("producer package digest does not match")
    ids: set[str] = set()
    tools: set[str] = set()
    for record in value["records"]:
        if record["evidence_id"] in ids or record["tool_id"] in tools:
            raise AssuranceIntegrationError(
                "producer package contains duplicate records"
            )
        ids.add(record["evidence_id"])
        tools.add(record["tool_id"])


def verify_fixture_catalog(value: dict[str, Any]) -> None:
    if value.get("catalog_digest") != artifact_digest(
        FIXTURE_CATALOG_DOMAIN, value, "catalog_digest"
    ):
        raise AssuranceIntegrationError("fixture catalog digest does not match")
    ids: set[str] = set()
    paths: set[str] = set()
    for fixture in value["fixtures"]:
        if fixture["fixture_id"] in ids or fixture["input_path"] in paths:
            raise AssuranceIntegrationError(
                "fixture catalog contains duplicate bindings"
            )
        ids.add(fixture["fixture_id"])
        paths.add(fixture["input_path"])
