from __future__ import annotations

import json
import unittest
from pathlib import Path

from scripts.validate_assurance import (
    load_schemas,
    validate_cross_references,
    validate_record,
)

ROOT = Path(__file__).resolve().parents[1]


class AssuranceSchemaTests(unittest.TestCase):
    def test_all_schemas_are_valid(self) -> None:
        validators = load_schemas(ROOT)
        self.assertEqual(
            set(validators),
            {
                "claim",
                "assumption",
                "evidence",
                "evidence-manifest",
                "known-limitation",
                "assurance-notice",
            },
        )

    def test_minimum_and_complete_fixture_catalogs_validate(self) -> None:
        validators = load_schemas(ROOT)
        for fixture_name in ("minimum.json", "complete.json"):
            catalog = json.loads(
                (ROOT / "tests" / "fixtures" / "valid" / fixture_name).read_text(encoding="utf-8")
            )
            for name, record in catalog.items():
                findings = validate_record(record, f"{fixture_name}:{name}", validators)
                self.assertEqual(findings, [], [(item.code, item.message) for item in findings])

    def test_complete_fixture_cross_references_resolve(self) -> None:
        catalog = json.loads(
            (ROOT / "tests" / "fixtures" / "valid" / "complete.json").read_text(encoding="utf-8")
        )
        records = list(catalog.values())
        paths = {record["id"]: f"complete.json:{name}" for name, record in catalog.items()}
        self.assertEqual(validate_cross_references(records, paths), [])

    def test_invalid_fixtures_fail_for_expected_code(self) -> None:
        validators = load_schemas(ROOT)
        cases = json.loads(
            (ROOT / "tests" / "fixtures" / "invalid" / "cases.json").read_text(encoding="utf-8")
        )
        for case in cases:
            findings = validate_record(case["record"], case["name"], validators)
            self.assertTrue(findings, case["name"])
            self.assertTrue(
                any(item.code == case["expected_code"] for item in findings),
                (case["name"], [(item.code, item.message) for item in findings]),
            )

    def test_duplicate_and_missing_references_fail(self) -> None:
        catalog = json.loads(
            (ROOT / "tests" / "fixtures" / "valid" / "complete.json").read_text(encoding="utf-8")
        )
        claim = dict(catalog["claim"])
        duplicate = dict(catalog["claim"])
        manifest = dict(catalog["evidence-manifest"])
        manifest["evidence"] = ["PM-EVIDENCE-9999"]
        records = [claim, duplicate, manifest]
        paths = {"PM-CLAIM-0001": "claim.json", "PM-MANIFEST-0001": "manifest.json"}
        findings = validate_cross_references(records, paths)
        self.assertTrue(any(item.code == "duplicate-id" for item in findings))
        self.assertTrue(any(item.code == "missing-reference" for item in findings))


if __name__ == "__main__":
    unittest.main()
