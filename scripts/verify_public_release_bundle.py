#!/usr/bin/env python3
"""Deterministic, offline public release bundle verifier CLI."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

try:
    from canonical_json import canonicalize
    from public_release import (
        atomic_write_new_output,
        render_verification_markdown,
        verify_public_release_bundle,
    )
except ImportError:  # pragma: no cover
    from scripts.canonical_json import canonicalize
    from scripts.public_release import (
        atomic_write_new_output,
        render_verification_markdown,
        verify_public_release_bundle,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-root", required=True, type=Path)
    parser.add_argument("--trust-root", required=True, type=Path)
    parser.add_argument("--status-set", required=True, type=Path)
    parser.add_argument("--status-signature", required=True, type=Path)
    parser.add_argument("--verification-time", required=True)
    parser.add_argument("--output-json", required=True, type=Path)
    parser.add_argument("--output-md", required=True, type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    if os.path.lexists(args.output_json) or os.path.lexists(args.output_md):
        parser.error("output target already exists")
    created: list[Path] = []
    try:
        result, exit_code = verify_public_release_bundle(
            root,
            args.bundle_root,
            args.trust_root,
            args.status_set,
            args.status_signature,
            args.verification_time,
        )
        created.append(atomic_write_new_output(args.output_json, canonicalize(result)))
        markdown = (
            render_verification_markdown(result)
            if exit_code == 0
            else (
                "# Private Match public release verification\n\n"
                f"- Overall: `{result['overall']['status']}`\n"
                f"- Reason: `{result['overall']['reason_code']}`\n"
            ).encode("utf-8")
        )
        created.append(atomic_write_new_output(args.output_md, markdown))
        return exit_code
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
            path.with_name(path.name + ".partial").unlink(missing_ok=True)
        parser.exit(1, "public release verification failed\n")


if __name__ == "__main__":
    raise SystemExit(main())
