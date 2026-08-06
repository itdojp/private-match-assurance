#!/usr/bin/env python3
"""Catalog-bound fixture signer; no production signing interface exists."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

try:
    from ae_assurance_common import read_strict_json, resolve_regular_file
    from canonical_json import canonicalize, strict_loads
    from public_release import (
        EXPECTED_BUNDLE_PATH,
        MANIFEST_PATH,
        RELEASE_PAYLOAD_TYPE,
        STATUS_PAYLOAD_TYPE,
        STATUS_CHAIN_MANIFEST_PATH,
        PublicReleaseError,
        atomic_write_new_output,
        sign_fixture_dsse,
        validate_fixture_catalog,
    )
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import read_strict_json, resolve_regular_file
    from scripts.canonical_json import canonicalize, strict_loads
    from scripts.public_release import (
        EXPECTED_BUNDLE_PATH,
        MANIFEST_PATH,
        RELEASE_PAYLOAD_TYPE,
        STATUS_PAYLOAD_TYPE,
        STATUS_CHAIN_MANIFEST_PATH,
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
    catalog = validate_fixture_catalog(root)
    permitted = {f"{EXPECTED_BUNDLE_PATH}/{MANIFEST_PATH}"}
    if args.usage == "release-status-signing":
        permitted = set()
        for entry in catalog["status_chains"]:
            chain = read_strict_json(
                root / entry["chain_root"] / STATUS_CHAIN_MANIFEST_PATH
            )
            permitted.update(
                f"{entry['chain_root']}/{revision['status_set_path']}"
                for revision in chain["revisions"]
            )
    if args.input not in permitted or os.path.lexists(args.output):
        parser.error("fixture signer accepts only the catalogued fixture input")
    try:
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
