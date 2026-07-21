#!/usr/bin/env python3
"""Strict JSON parsing and RFC 8785 serialization for evidence export."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

import rfc8785


MAX_SAFE_INTEGER = (1 << 53) - 1


class CanonicalJSONError(ValueError):
    """A bounded canonical JSON contract failure."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError("duplicate JSON member name")
        result[key] = value
    return result


def _parse_int(token: str) -> int:
    if token.startswith("-0"):
        raise CanonicalJSONError("negative zero is forbidden")
    value = int(token)
    if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
        raise CanonicalJSONError("integer exceeds the I-JSON safe domain")
    return value


def _parse_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise CanonicalJSONError("non-finite number is forbidden")
    if value == 0 and token.startswith("-"):
        raise CanonicalJSONError("negative zero is forbidden")
    return value


def _reject_constant(_token: str) -> None:
    raise CanonicalJSONError("NaN and Infinity are forbidden")


def _validate_value(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise CanonicalJSONError(f"{path}: invalid Unicode scalar value") from error
        return
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalJSONError(f"{path}: integer exceeds the I-JSON safe domain")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalJSONError(f"{path}: non-finite number is forbidden")
        if value == 0 and math.copysign(1, value) < 0:
            raise CanonicalJSONError(f"{path}: negative zero is forbidden")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError(f"{path}: object keys must be strings")
            _validate_value(key, f"{path}.<key>")
            _validate_value(item, f"{path}.{key}")
        return
    raise CanonicalJSONError(f"{path}: unsupported JSON value type")


def strict_loads(raw: bytes | str, *, max_bytes: int) -> Any:
    """Parse one UTF-8 JSON value with duplicate and I-JSON checks."""

    if isinstance(raw, bytes):
        if len(raw) > max_bytes:
            raise CanonicalJSONError("input exceeds the configured size limit")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise CanonicalJSONError("input is not valid UTF-8") from error
    else:
        text = raw
        try:
            encoded = text.encode("utf-8", errors="strict")
        except UnicodeEncodeError as error:
            raise CanonicalJSONError("input contains invalid Unicode") from error
        if len(encoded) > max_bytes:
            raise CanonicalJSONError("input exceeds the configured size limit")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_int=_parse_int,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except CanonicalJSONError:
        raise
    except (json.JSONDecodeError, UnicodeError, ValueError) as error:
        raise CanonicalJSONError("invalid JSON input") from error
    _validate_value(value)
    return value


def canonicalize(value: Any) -> bytes:
    """Return exact RFC 8785 bytes after the stricter export value checks."""

    _validate_value(value)
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, UnicodeError, ValueError) as error:
        raise CanonicalJSONError("RFC 8785 canonicalization failed") from error


def domain_digest(domain: str, value: Any) -> str:
    """Digest a canonical value with an unambiguous ASCII domain prefix."""

    digest = hashlib.sha256(domain.encode("ascii") + b"\x00" + canonicalize(value))
    return "sha256:" + digest.hexdigest()


def file_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
