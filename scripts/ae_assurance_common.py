#!/usr/bin/env python3
"""Shared strict I/O, digest, Schema, and path helpers for ae Assurance."""

from __future__ import annotations

import copy
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
from typing import Any, Iterable

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

try:
    from canonical_json import canonicalize, domain_digest, file_digest, strict_loads
except ImportError:  # pragma: no cover - package import during unit tests
    from scripts.canonical_json import (
        canonicalize,
        domain_digest,
        file_digest,
        strict_loads,
    )


MAX_INPUT_BYTES = 1_048_576
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
STATUS_VALUES = ("pass", "fail", "skip", "unsupported", "timeout", "tool-error")
PRODUCER_TYPES = ("ci", "formal-tool", "test-runner", "security-tool", "human-review")


class AssuranceIntegrationError(ValueError):
    """A value-free, bounded integration-contract failure."""


def canonical_json_bytes(value: Any) -> bytes:
    return canonicalize(value) + b"\n"


def detached_digest(domain: str, value: dict[str, Any], field: str) -> str:
    material = copy.deepcopy(value)
    material.pop(field, None)
    return domain_digest(domain, material)


def validate_relative_path(value: str) -> PurePosixPath:
    """Validate one closed POSIX-relative path without normalizing it."""

    if not isinstance(value, str) or not value:
        raise AssuranceIntegrationError("path is not a non-empty relative path")
    if "\\" in value or PureWindowsPath(value).is_absolute():
        raise AssuranceIntegrationError("path is not a portable relative path")
    path = PurePosixPath(value)
    parts = value.split("/")
    if path.is_absolute() or any(part in {"", ".", ".."} for part in parts):
        raise AssuranceIntegrationError("path contains a forbidden segment")
    return path


def _resolve_root(root: Path, *, must_exist: bool = True) -> Path:
    try:
        probe = root if root.exists() else root.parent
        if any(item.is_symlink() for item in (probe, *probe.parents)):
            raise AssuranceIntegrationError("path root must not be a symlink")
        return root.resolve(strict=must_exist)
    except OSError as error:
        raise AssuranceIntegrationError("path root is unavailable") from error


def resolve_regular_file(
    root: Path,
    relative: str,
    *,
    max_bytes: int = MAX_INPUT_BYTES,
) -> Path:
    """Resolve a bounded regular file below a root without following symlinks."""

    root_resolved = _resolve_root(root)
    portable = validate_relative_path(relative)
    current = root_resolved
    for part in portable.parts:
        current = current / part
        if current.is_symlink():
            raise AssuranceIntegrationError("path must not contain a symlink")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(root_resolved)
        mode = resolved.stat().st_mode
    except (OSError, ValueError) as error:
        raise AssuranceIntegrationError("input file is unavailable") from error
    if not stat.S_ISREG(mode):
        raise AssuranceIntegrationError("input is not a regular file")
    if resolved.stat().st_size > max_bytes:
        raise AssuranceIntegrationError("input exceeds the configured size limit")
    return resolved


def read_strict_json(path: Path, *, max_bytes: int = MAX_INPUT_BYTES) -> Any:
    try:
        return strict_loads(path.read_bytes(), max_bytes=max_bytes)
    except (OSError, UnicodeError, ValueError) as error:
        raise AssuranceIntegrationError("input is not strict JSON") from error


def load_schema(root: Path, relative: str) -> dict[str, Any]:
    schema = read_strict_json(resolve_regular_file(root, relative))
    if not isinstance(schema, dict):
        raise AssuranceIntegrationError("Schema is not an object")
    try:
        Draft202012Validator.check_schema(schema)
    except Exception as error:
        raise AssuranceIntegrationError("Schema is invalid") from error
    return schema


def build_schema_registry(schemas: Iterable[dict[str, Any]]) -> Registry:
    registry = Registry()
    try:
        for schema in schemas:
            schema_id = schema.get("$id")
            if isinstance(schema_id, str):
                registry = registry.with_resource(
                    schema_id, Resource.from_contents(schema)
                )
    except Exception as error:
        raise AssuranceIntegrationError("Schema registry is invalid") from error
    return registry


def validate_schema_instance(
    value: Any,
    schema: dict[str, Any],
    *,
    registry: Registry | None = None,
) -> None:
    validator = Draft202012Validator(
        schema,
        registry=registry or Registry(),
        format_checker=FormatChecker(),
    )
    if next(iter(validator.iter_errors(value)), None) is not None:
        raise AssuranceIntegrationError("artifact does not match its Schema")


def atomic_write_file(path: Path, data: bytes) -> None:
    """Write one file with same-directory replacement and an fsync boundary."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.parent.is_symlink():
        raise AssuranceIntegrationError("output path must not use a symlink")
    partial = path.with_name(path.name + ".partial")
    if partial.exists() or partial.is_symlink():
        raise AssuranceIntegrationError("partial output path already exists")
    try:
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(partial, path)
    except Exception:
        try:
            partial.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def path_entry(root: Path, relative: str) -> dict[str, str]:
    path = resolve_regular_file(root, relative, max_bytes=16 * MAX_INPUT_BYTES)
    return {"path": relative, "digest": file_digest(path.read_bytes())}


def exact_entry_map(entries: Any, label: str) -> dict[str, str]:
    if not isinstance(entries, list):
        raise AssuranceIntegrationError(f"{label} must be an array")
    result: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "digest"}:
            raise AssuranceIntegrationError(f"{label} contains an invalid entry")
        path = entry.get("path")
        digest = entry.get("digest")
        if not isinstance(path, str) or not isinstance(digest, str):
            raise AssuranceIntegrationError(f"{label} contains an invalid entry")
        validate_relative_path(path)
        if path in result:
            raise AssuranceIntegrationError(f"{label} contains a duplicate path")
        result[path] = digest
    return result
