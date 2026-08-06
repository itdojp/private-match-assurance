#!/usr/bin/env python3
"""Validate all committed Issue #6 public release authorities and fixture output."""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    from public_release import (
        EXPECTED_BUNDLE_PATH,
        EXPECTED_STATUS_CHAINS_PATH,
        TRUST_ROOT_PATH,
        VERIFICATION_TIME,
        PublicReleaseError,
        load_release_authority,
        validate_fixture_catalog,
        validate_fixture_private_key_boundary,
        verify_public_release_bundle,
        verify_rfc8032_vector,
    )
    from public_release_implementation import validate_manifest
    from ae_assurance_common import read_strict_json
except ImportError:  # pragma: no cover
    from scripts.public_release import (
        EXPECTED_BUNDLE_PATH,
        EXPECTED_STATUS_CHAINS_PATH,
        TRUST_ROOT_PATH,
        VERIFICATION_TIME,
        PublicReleaseError,
        load_release_authority,
        validate_fixture_catalog,
        validate_fixture_private_key_boundary,
        verify_public_release_bundle,
        verify_rfc8032_vector,
    )
    from scripts.public_release_implementation import validate_manifest
    from scripts.ae_assurance_common import read_strict_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        load_release_authority(root)
        validate_fixture_private_key_boundary(root)
        verify_rfc8032_vector(root)
        validate_fixture_catalog(root)
        implementation = read_strict_json(
            root / "manifests/public-release-verifier-implementation.v0.1.json"
        )
        validate_manifest(root, implementation)
        bundle = root / EXPECTED_BUNDLE_PATH
        result, code = verify_public_release_bundle(
            root,
            bundle,
            root / TRUST_ROOT_PATH,
            root / EXPECTED_STATUS_CHAINS_PATH / "active",
            VERIFICATION_TIME,
        )
        if (
            code != 0
            or result["overall"]["status"] != "verified-fixture-with-limitations"
        ):
            raise PublicReleaseError("committed fixture verification failed")
        print(
            "public release authorities and fixture verified: "
            + result["verification_result_digest"]
        )
        return 0
    except (OSError, PublicReleaseError):
        parser.exit(1, "public release validation failed\n")


if __name__ == "__main__":
    raise SystemExit(main())
