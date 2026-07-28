#!/usr/bin/env python3
"""Generate and byte-check the closed synthetic ae Assurance fixture catalog."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil

try:
    from ae_assurance_common import (
        STATUS_VALUES,
        canonical_json_bytes,
        read_strict_json,
        resolve_regular_file,
    )
    from ae_assurance_policy import (
        FIXTURE_CATALOG_DOMAIN,
        FIXTURE_CATALOG_PATH,
        PRODUCER_PACKAGE_DOMAIN,
        PROFILE_PATH,
        TOOL_INVENTORY_PATH,
        artifact_digest,
        verify_fixture_catalog,
    )
    from canonical_json import domain_digest, file_digest
    from run_ae_assurance import JSON_NAME, MARKDOWN_NAME, run_one
except ImportError:  # pragma: no cover
    from scripts.ae_assurance_common import (
        STATUS_VALUES,
        canonical_json_bytes,
        read_strict_json,
        resolve_regular_file,
    )
    from scripts.ae_assurance_policy import (
        FIXTURE_CATALOG_DOMAIN,
        FIXTURE_CATALOG_PATH,
        PRODUCER_PACKAGE_DOMAIN,
        PROFILE_PATH,
        TOOL_INVENTORY_PATH,
        artifact_digest,
        verify_fixture_catalog,
    )
    from scripts.canonical_json import domain_digest, file_digest
    from scripts.run_ae_assurance import JSON_NAME, MARKDOWN_NAME, run_one


FIXTURE_ROOT = Path("tests/fixtures/ae-framework")
FIXTURES = (
    (
        "PMAE-FIXTURE-SUCCESS-V0-1",
        "success",
        {
            "PMAE-CI-PIPELINE-V0-1": "pass",
            "PMAE-CONFORMANCE-RUNNER-V0-1": "pass",
            "PMAE-FORMAL-TOOL-V0-1": "skip",
            "PMAE-SECURITY-TOOL-V0-1": "unsupported",
            "PMAE-HUMAN-REVIEW-V0-1": "skip",
        },
    ),
    (
        "PMAE-FIXTURE-REQUIRED-FAIL-V0-1",
        "required-fail",
        {
            "PMAE-CI-PIPELINE-V0-1": "pass",
            "PMAE-CONFORMANCE-RUNNER-V0-1": "fail",
            "PMAE-FORMAL-TOOL-V0-1": "skip",
            "PMAE-SECURITY-TOOL-V0-1": "unsupported",
            "PMAE-HUMAN-REVIEW-V0-1": "skip",
        },
    ),
    (
        "PMAE-FIXTURE-REQUIRED-MISSING-V0-1",
        "required-missing-tool",
        {
            "PMAE-CI-PIPELINE-V0-1": "unsupported",
            "PMAE-CONFORMANCE-RUNNER-V0-1": "pass",
            "PMAE-FORMAL-TOOL-V0-1": "skip",
            "PMAE-SECURITY-TOOL-V0-1": "unsupported",
            "PMAE-HUMAN-REVIEW-V0-1": "skip",
        },
    ),
    (
        "PMAE-FIXTURE-REQUIRED-TIMEOUT-V0-1",
        "required-timeout",
        {
            "PMAE-CI-PIPELINE-V0-1": "pass",
            "PMAE-CONFORMANCE-RUNNER-V0-1": "timeout",
            "PMAE-FORMAL-TOOL-V0-1": "skip",
            "PMAE-SECURITY-TOOL-V0-1": "unsupported",
            "PMAE-HUMAN-REVIEW-V0-1": "skip",
        },
    ),
    (
        "PMAE-FIXTURE-REQUIRED-TOOL-ERROR-V0-1",
        "required-tool-error",
        {
            "PMAE-CI-PIPELINE-V0-1": "pass",
            "PMAE-CONFORMANCE-RUNNER-V0-1": "tool-error",
            "PMAE-FORMAL-TOOL-V0-1": "skip",
            "PMAE-SECURITY-TOOL-V0-1": "unsupported",
            "PMAE-HUMAN-REVIEW-V0-1": "skip",
        },
    ),
    (
        "PMAE-FIXTURE-OPTIONAL-UNAVAILABLE-V0-1",
        "optional-unavailable",
        {
            "PMAE-CI-PIPELINE-V0-1": "pass",
            "PMAE-CONFORMANCE-RUNNER-V0-1": "pass",
            "PMAE-FORMAL-TOOL-V0-1": "unsupported",
            "PMAE-SECURITY-TOOL-V0-1": "skip",
            "PMAE-HUMAN-REVIEW-V0-1": "unsupported",
        },
    ),
)


def _synthetic_digest(label: str) -> str:
    return domain_digest("private-match-ae-synthetic-fixture/v0.1", {"label": label})


def _build_input(
    inventory: dict, fixture_id: str, slug: str, statuses: dict[str, str]
) -> dict:
    records = []
    for index, tool in enumerate(inventory["tools"], start=1):
        status = statuses[tool["tool_id"]]
        mapping = next(
            item
            for item in tool["status_mappings"]
            if item["raw_producer_status"] == status
        )
        output = (
            _synthetic_digest(f"{slug}:{tool['tool_id']}:output")
            if status in {"pass", "fail"}
            else None
        )
        records.append(
            {
                "evidence_id": f"PM-EVIDENCE-{index:04d}",
                "producer_type": tool["producer_type"],
                "producer_id": f"synthetic-{tool['producer_type']}-producer",
                "producer_version": "0.1",
                "tool_id": tool["tool_id"],
                "tool_version": tool["version"],
                "tool_implementation_digest": tool["implementation_digest"],
                "source_revision_digest": _synthetic_digest(f"{slug}:source"),
                "protocol_suite_digest": _synthetic_digest(f"{slug}:suite"),
                "protocol_case_digest": _synthetic_digest(
                    f"{slug}:{tool['tool_id']}:case"
                ),
                "protocol_input_digest": _synthetic_digest(
                    f"{slug}:{tool['tool_id']}:input"
                ),
                "product_implementation_digest": _synthetic_digest(
                    f"{slug}:product-implementation"
                ),
                "product_artifact_digest": _synthetic_digest(
                    f"{slug}:{tool['tool_id']}:artifact"
                ),
                "product_output_digest": output,
                "status": status,
                "limitations": [
                    mapping["required_limitation"],
                    "Public synthetic fixture only; no private Product execution is represented.",
                ],
                "test_only": True,
                "retention_classification": "synthetic-public-fixture",
                "public_export_eligibility": False,
                "started_at": "2030-01-01T00:00:00Z",
                "completed_at": "2030-01-01T00:00:01Z",
                "summary": f"Synthetic {tool['producer_type']} status record.",
            }
        )
    package = {
        "schema_version": "0.1",
        "package_id": fixture_id.replace("PMAE-FIXTURE-", "PMAE-PRODUCER-"),
        "artifact_status": "test-only",
        "mode": "fixture-test",
        "created_at": "2030-01-01T00:01:00Z",
        "source_revision_digest": _synthetic_digest(f"{slug}:source"),
        "records": records,
        "limitations": [
            "All identifiers and digests are public synthetic fixture values.",
            "The package is not eligible for public export or live approval.",
        ],
    }
    package["package_digest"] = artifact_digest(
        PRODUCER_PACKAGE_DOMAIN, package, "package_digest"
    )
    return package


def _counts(statuses: dict[str, str]) -> dict[str, int]:
    result = {status: 0 for status in STATUS_VALUES}
    for status in statuses.values():
        result[status] += 1
    return result


def write_fixtures(root: Path) -> None:
    fixture_root = root / FIXTURE_ROOT
    (fixture_root / "input").mkdir(parents=True, exist_ok=True)
    (fixture_root / "expected").mkdir(parents=True, exist_ok=True)
    inventory = read_strict_json(resolve_regular_file(root, TOOL_INVENTORY_PATH))
    entries = []
    for fixture_id, slug, statuses in FIXTURES:
        input_relative = f"input/{slug}.json"
        input_path = fixture_root / input_relative
        input_path.write_bytes(
            canonical_json_bytes(_build_input(inventory, fixture_id, slug, statuses))
        )
        entries.append(
            {
                "fixture_id": fixture_id,
                "mode": "fixture-test",
                "input_path": input_relative,
                "input_digest": file_digest(input_path.read_bytes()),
                "expected_json_path": f"expected/{slug}.json",
                "expected_json_digest": "sha256:" + "0" * 64,
                "expected_markdown_path": f"expected/{slug}.md",
                "expected_markdown_digest": "sha256:" + "0" * 64,
                "expected_status_counts": _counts(statuses),
                "expected_automated_judgment": "satisfied"
                if all(
                    statuses[tool] == "pass"
                    for tool in (
                        "PMAE-CI-PIPELINE-V0-1",
                        "PMAE-CONFORMANCE-RUNNER-V0-1",
                    )
                )
                else "blocked",
                "expected_human_approval_state": "not-applicable-test-only",
                "artifact_status": "test-only",
            }
        )
    catalog = {
        "schema_version": "0.1",
        "artifact_status": "test-only",
        "fixtures": entries,
    }
    catalog["catalog_digest"] = artifact_digest(
        FIXTURE_CATALOG_DOMAIN, catalog, "catalog_digest"
    )
    (root / FIXTURE_CATALOG_PATH).write_bytes(canonical_json_bytes(catalog))
    temp_root = root / ".codex-local/tmp/ae-fixture-generation"
    shutil.rmtree(temp_root, ignore_errors=True)
    temp_root.mkdir(parents=True)
    for entry in entries:
        slug = Path(entry["input_path"]).stem
        output = temp_root / slug
        run_one(
            root=root,
            profile_path=PROFILE_PATH,
            input_root=fixture_root.resolve(),
            relative_input=entry["input_path"],
            output_root=output,
            mode="fixture-test",
        )
        json_target = fixture_root / entry["expected_json_path"]
        md_target = fixture_root / entry["expected_markdown_path"]
        shutil.copyfile(output / JSON_NAME, json_target)
        shutil.copyfile(output / MARKDOWN_NAME, md_target)
        entry["expected_json_digest"] = file_digest(json_target.read_bytes())
        entry["expected_markdown_digest"] = file_digest(md_target.read_bytes())
    shutil.rmtree(temp_root)
    catalog["catalog_digest"] = artifact_digest(
        FIXTURE_CATALOG_DOMAIN, catalog, "catalog_digest"
    )
    (root / FIXTURE_CATALOG_PATH).write_bytes(canonical_json_bytes(catalog))


def check_fixtures(root: Path) -> None:
    catalog = read_strict_json(resolve_regular_file(root, FIXTURE_CATALOG_PATH))
    verify_fixture_catalog(catalog)
    fixture_root = (root / FIXTURE_ROOT).resolve()
    temp_root = root / ".codex-local/tmp/ae-fixture-check"
    shutil.rmtree(temp_root, ignore_errors=True)
    temp_root.mkdir(parents=True)
    try:
        for entry in catalog["fixtures"]:
            outputs = []
            for iteration in (1, 2):
                output = temp_root / f"{entry['fixture_id']}-{iteration}"
                run_one(
                    root=root,
                    profile_path=PROFILE_PATH,
                    input_root=fixture_root,
                    relative_input=entry["input_path"],
                    output_root=output,
                    mode="fixture-test",
                )
                outputs.append((output / JSON_NAME, output / MARKDOWN_NAME))
            expected_json = resolve_regular_file(
                fixture_root, entry["expected_json_path"]
            ).read_bytes()
            expected_md = resolve_regular_file(
                fixture_root, entry["expected_markdown_path"]
            ).read_bytes()
            if (
                outputs[0][0].read_bytes() != outputs[1][0].read_bytes()
                or outputs[0][1].read_bytes() != outputs[1][1].read_bytes()
            ):
                raise ValueError("fixture execution is not byte-identical")
            if (
                outputs[0][0].read_bytes() != expected_json
                or outputs[0][1].read_bytes() != expected_md
            ):
                raise ValueError("fixture expected output is stale")
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--write", action="store_true")
    action.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if args.write:
        write_fixtures(root)
    else:
        check_fixtures(root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
