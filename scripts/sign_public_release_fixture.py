#!/usr/bin/env python3
"""Catalog-bound fixture signer; no production signing interface exists."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

try:
    from ae_assurance_common import resolve_regular_file
    from canonical_json import canonicalize, strict_loads
    from public_release import (
        EXPECTED_BUNDLE_PATH,
        MANIFEST_PATH,
        RELEASE_PAYLOAD_TYPE,
        STATUS_PAYLOAD_TYPE,
        STATUS_SET_PATH,
        PublicReleaseError,
        atomic_write_new_output,
        sign_fixture_dsse,
        validate_fixture_catalog,
    )
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import resolve_regular_file
    from scripts.canonical_json import canonicalize, strict_loads
    from scripts.public_release import (
        EXPECTED_BUNDLE_PATH,
        MANIFEST_PATH,
        RELEASE_PAYLOAD_TYPE,
        STATUS_PAYLOAD_TYPE,
        STATUS_SET_PATH,
        PublicReleaseError,
        atomic_write_new_output,
        sign_fixture_dsse,
        validate_fixture_catalog,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--usage", required=True, choices=["release-signing", "release-status-signing"]
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    expected = (
        f"{EXPECTED_BUNDLE_PATH}/{MANIFEST_PATH}"
        if args.usage == "release-signing"
        else f"{EXPECTED_BUNDLE_PATH}/{STATUS_SET_PATH}"
    )
    if args.input != expected or os.path.lexists(args.output):
        parser.error("fixture signer accepts only the catalogued fixture input")
    try:
        validate_fixture_catalog(root)
        source = resolve_regular_file(root, args.input)
        value = strict_loads(source.read_bytes(), max_bytes=4 * 1024 * 1024)
        payload = canonicalize(value)
        if source.read_bytes() != payload:
            raise PublicReleaseError("fixture signing input is not canonical")
        payload_type = (
            RELEASE_PAYLOAD_TYPE
            if args.usage == "release-signing"
            else STATUS_PAYLOAD_TYPE
        )
        envelope = sign_fixture_dsse(root, payload_type, payload, args.usage)
        atomic_write_new_output(args.output, canonicalize(envelope))
        return 0
    except PublicReleaseError:
        args.output.unlink(missing_ok=True)
        args.output.with_name(args.output.name + ".partial").unlink(missing_ok=True)
        parser.exit(1, "fixture signing failed\n")


if __name__ == "__main__":
    raise SystemExit(main())
