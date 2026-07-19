from __future__ import annotations

import copy
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
                (ROOT / "tests" / "fixtures" / "valid" / fixture_name).read_text(
                    encoding="utf-8"
                )
            )
            for name, record in catalog.items():
                findings = validate_record(record, f"{fixture_name}:{name}", validators)
                self.assertEqual(
                    findings, [], [(item.code, item.message) for item in findings]
                )

    def test_complete_fixture_cross_references_resolve(self) -> None:
        catalog = json.loads(
            (ROOT / "tests" / "fixtures" / "valid" / "complete.json").read_text(
                encoding="utf-8"
            )
        )
        records = list(catalog.values())
        paths = {
            record["id"]: f"complete.json:{name}" for name, record in catalog.items()
        }
        self.assertEqual(validate_cross_references(records, paths), [])

    def test_invalid_fixtures_fail_for_expected_code(self) -> None:
        validators = load_schemas(ROOT)
        cases = json.loads(
            (ROOT / "tests" / "fixtures" / "invalid" / "cases.json").read_text(
                encoding="utf-8"
            )
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
            (ROOT / "tests" / "fixtures" / "valid" / "complete.json").read_text(
                encoding="utf-8"
            )
        )
        claim = {**catalog["claim"], "_path": "claim-first.json"}
        duplicate = {**catalog["claim"], "_path": "claim-second.json"}
        manifest = {**catalog["evidence-manifest"], "_path": "manifest.json"}
        manifest["evidence"] = ["PM-EVIDENCE-9999"]
        findings = validate_cross_references([claim, duplicate, manifest], {})
        duplicate_findings = [item for item in findings if item.code == "duplicate-id"]
        self.assertEqual(len(duplicate_findings), 1)
        self.assertEqual(duplicate_findings[0].path, "claim-second.json")
        self.assertIn("claim-first.json", duplicate_findings[0].message)
        self.assertTrue(any(item.code == "missing-reference" for item in findings))

    def test_schema_invalid_reference_field_does_not_abort_cross_reference_validation(
        self,
    ) -> None:
        catalog = json.loads(
            (ROOT / "tests" / "fixtures" / "valid" / "complete.json").read_text(
                encoding="utf-8"
            )
        )
        for invalid_value in (None, [{}]):
            with self.subTest(invalid_value=invalid_value):
                claim = copy.deepcopy(catalog["claim"])
                claim["assumptions"] = []
                claim["evidence"] = invalid_value
                claim["limitations"] = []

                findings = validate_cross_references(
                    [claim], {claim["id"]: "claim.json"}
                )

                self.assertEqual(findings, [])

    def test_active_claim_cannot_use_withdrawn_or_superseded_evidence(self) -> None:
        catalog = json.loads(
            (ROOT / "tests" / "fixtures" / "valid" / "complete.json").read_text(
                encoding="utf-8"
            )
        )
        validators = load_schemas(ROOT)
        for lifecycle in ("withdrawn", "superseded"):
            with self.subTest(lifecycle=lifecycle):
                claim = copy.deepcopy(catalog["claim"])
                evidence = copy.deepcopy(catalog["evidence"])
                if lifecycle == "superseded":
                    evidence["lifecycle_history"].append(
                        {
                            "state": "published",
                            "recorded_at": "2026-07-18T00:04:00Z",
                            "review_digest": "sha256:" + "3" * 64,
                        }
                    )
                evidence["lifecycle"] = lifecycle
                evidence["lifecycle_history"].append(
                    {
                        "state": lifecycle,
                        "recorded_at": "2026-07-18T00:05:00Z",
                        "review_digest": "sha256:" + "4" * 64,
                    }
                )
                self.assertEqual(evidence["status"], "pass")
                self.assertEqual(
                    validate_record(evidence, "evidence.json", validators), []
                )
                findings = validate_cross_references(
                    [claim, evidence],
                    {claim["id"]: "claim.json", evidence["id"]: "evidence.json"},
                )
                self.assertTrue(
                    any(item.code == "inactive-evidence-reference" for item in findings)
                )

    def test_manifest_output_digest_set_must_match_referenced_evidence(self) -> None:
        catalog = json.loads(
            (ROOT / "tests" / "fixtures" / "valid" / "complete.json").read_text(
                encoding="utf-8"
            )
        )
        records = list(catalog.values())
        manifest = next(
            record for record in records if record["record_type"] == "evidence-manifest"
        )
        manifest["digests"]["evidence_output_digests"] = []
        paths = {record["id"]: f"{name}.json" for name, record in catalog.items()}

        findings = validate_cross_references(records, paths)

        self.assertTrue(
            any(item.code == "evidence-output-digest-set" for item in findings)
        )

    def test_model_check_results_must_stay_within_configured_state_bound(self) -> None:
        catalog = json.loads(
            (ROOT / "tests" / "fixtures" / "valid" / "complete.json").read_text(
                encoding="utf-8"
            )
        )
        record = catalog["model-check-evidence"]
        record["model_check"]["state_space_bounds"]["max_states"] = 100
        record["model_check"]["explored_state_space"]["generated_states"] = 101

        findings = validate_record(record, "model-check.json", load_schemas(ROOT))

        self.assertTrue(
            any(item.code == "model-check-state-bound" for item in findings)
        )


if __name__ == "__main__":
    unittest.main()
