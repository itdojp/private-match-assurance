#!/usr/bin/env python3
"""Run the exact-pinned ae-framework integration on one explicit package."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys

try:
    from ae_assurance_common import (
        AssuranceIntegrationError,
        canonical_json_bytes,
        read_strict_json,
        resolve_regular_file,
        resolve_new_directory,
        resolve_trusted_directory,
        validate_relative_path,
    )
    from ae_assurance_policy import (
        FIXTURE_CATALOG_PATH,
        PROFILE_PATH,
        verify_fixture_catalog,
    )
    from ae_framework_adapter import build_assurance_package
    from ae_assurance_output_set import (
        JSON_NAME,
        MARKDOWN_NAME,
        OUTPUT_SET_NAME,
        build_output_set,
        validate_output_directory,
    )
    from canonical_json import file_digest
    from render_ae_assurance_report import render_markdown
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import (
        AssuranceIntegrationError,
        canonical_json_bytes,
        read_strict_json,
        resolve_regular_file,
        resolve_new_directory,
        resolve_trusted_directory,
        validate_relative_path,
    )
    from scripts.ae_assurance_policy import (
        FIXTURE_CATALOG_PATH,
        PROFILE_PATH,
        verify_fixture_catalog,
    )
    from scripts.ae_framework_adapter import build_assurance_package
    from scripts.ae_assurance_output_set import (
        JSON_NAME,
        MARKDOWN_NAME,
        OUTPUT_SET_NAME,
        build_output_set,
        validate_output_directory,
    )
    from scripts.canonical_json import file_digest
    from scripts.render_ae_assurance_report import render_markdown


def _root_path(value: str, label: str) -> Path:
    path = Path(value)
    try:
        if any(item.is_symlink() for item in (path, *path.parents)):
            raise AssuranceIntegrationError(f"{label} must not be a symlink")
        resolved = resolve_trusted_directory(path)
    except OSError as error:
        raise AssuranceIntegrationError(f"{label} is unavailable") from error
    return resolved


def _fixture_entry(root: Path, input_root: Path, relative: str) -> dict:
    catalog = read_strict_json(resolve_regular_file(root, FIXTURE_CATALOG_PATH))
    if not isinstance(catalog, dict):
        raise AssuranceIntegrationError("fixture catalog is invalid")
    verify_fixture_catalog(catalog)
    fixture_root = (root / "tests/fixtures/ae-framework").resolve()
    if input_root != fixture_root:
        raise AssuranceIntegrationError(
            "fixture input root does not match the catalog root"
        )
    matches = [item for item in catalog["fixtures"] if item["input_path"] == relative]
    if len(matches) != 1:
        raise AssuranceIntegrationError("input is not a catalogued fixture")
    return matches[0]


def run_one(
    *,
    root: Path,
    profile_path: str,
    input_root: Path,
    relative_input: str,
    output_root: Path,
    relative_output: str,
    mode: str,
) -> tuple[bytes, bytes, bytes]:
    if profile_path != PROFILE_PATH:
        raise AssuranceIntegrationError(
            "integration profile path is not the reviewed profile"
        )
    validate_relative_path(relative_input)
    input_path = resolve_regular_file(input_root, relative_input)
    raw = input_path.read_bytes()
    producer = read_strict_json(input_path)
    if not isinstance(producer, dict) or producer.get("mode") != mode:
        raise AssuranceIntegrationError(
            "trusted mode does not match the producer package"
        )
    if mode == "fixture-test":
        fixture = _fixture_entry(root, input_root, relative_input)
        if fixture["input_digest"] != file_digest(raw):
            raise AssuranceIntegrationError("fixture input digest does not match")

    final_output = resolve_new_directory(output_root, relative_output)
    parent = final_output.parent
    staging = parent / f".{final_output.name}.partial-{os.getpid()}"
    if staging.exists() or staging.is_symlink():
        raise AssuranceIntegrationError("staging output root already exists")
    staging.mkdir(mode=0o700)
    try:
        package = build_assurance_package(root, producer, staging)
        try:
            from validate_ae_assurance import validate_package
        except ImportError:  # pragma: no cover
            from scripts.validate_ae_assurance import validate_package

        validate_package(root, package)
        json_bytes = canonical_json_bytes(package)
        markdown_bytes = render_markdown(package).encode("utf-8")
        output_set = build_output_set(root, package, json_bytes, markdown_bytes)
        output_set_bytes = canonical_json_bytes(output_set)
        json_path = staging / JSON_NAME
        md_path = staging / MARKDOWN_NAME
        output_set_path = staging / OUTPUT_SET_NAME
        json_path.write_bytes(json_bytes)
        md_path.write_bytes(markdown_bytes)
        output_set_path.write_bytes(output_set_bytes)
        for extra in list(staging.iterdir()):
            if extra.name not in {JSON_NAME, MARKDOWN_NAME, OUTPUT_SET_NAME}:
                if extra.is_dir() and not extra.is_symlink():
                    shutil.rmtree(extra)
                else:
                    extra.unlink()
        validate_output_directory(root, staging)
        for path in (json_path, md_path, output_set_path):
            with path.open("rb") as handle:
                os.fsync(handle.fileno())
        dir_fd = os.open(staging, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        os.rename(staging, final_output)
        return json_bytes, markdown_bytes, output_set_bytes
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--input-root", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--mode", required=True, choices=("fixture-test", "private-candidate")
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    try:
        input_root = _root_path(args.input_root, "input root")
        output_root = _root_path(args.output_root, "output root")
        run_one(
            root=root,
            profile_path=args.profile,
            input_root=input_root,
            relative_input=args.input,
            output_root=output_root,
            relative_output=args.output,
            mode=args.mode,
        )
    except Exception:
        print("ae Assurance execution failed: contract violation", file=sys.stderr)
        return 2
    print("ae Assurance execution completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
