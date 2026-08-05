#!/usr/bin/env python3
"""Generate or check the complete synthetic signed public release fixture."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil

try:
    from public_release import (
        EXPECTED_BUNDLE_PATH,
        PublicReleaseError,
        generate_fixture_bundle,
        public_release_process_scratch,
    )
except ImportError:  # pragma: no cover
    from scripts.public_release import (
        EXPECTED_BUNDLE_PATH,
        PublicReleaseError,
        generate_fixture_bundle,
        public_release_process_scratch,
    )


def _tree(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--output")
    args = parser.parse_args()
    if sum(bool(value) for value in (args.check, args.write, args.output)) != 1:
        parser.error("select exactly one of --check, --write, or --output")
    root = Path(__file__).resolve().parents[1]
    try:
        if args.output:
            if args.output_root is None:
                parser.error("--output requires --output-root")
            target = generate_fixture_bundle(root, args.output_root, args.output)
            print(target.name)
            return 0
        with public_release_process_scratch(root) as temporary_root:
            generated = generate_fixture_bundle(root, temporary_root, "bundle")
            expected = root / EXPECTED_BUNDLE_PATH
            if args.check:
                if not expected.is_dir() or _tree(generated) != _tree(expected):
                    raise PublicReleaseError(
                        "committed public release fixture is stale"
                    )
                print(f"public release fixture checked: {len(_tree(expected))} files")
                return 0
            if expected.is_symlink():
                raise PublicReleaseError("expected fixture path must not be a symlink")
            if expected.exists():
                shutil.rmtree(expected)
            expected.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(generated, expected)
            print(f"public release fixture written: {len(_tree(expected))} files")
            return 0
    except PublicReleaseError as error:
        parser.exit(1, f"public release fixture failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
