from __future__ import annotations

import copy
import io
import socket
import struct
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from scripts.canonical_json import (
    CanonicalJSONError,
    canonicalize,
    strict_loads,
)
from scripts.export_public_evidence import (
    ExportError,
    _load_profile,
    bundle_digest,
    export_candidate,
    main,
    run_export,
    source_evidence_digest,
    validate_public_bundle,
)
from scripts.validate_assurance import (
    load_export_schemas,
    load_schemas,
    validate_export_bundle,
    validate_record,
)


ROOT = Path(__file__).resolve().parents[1]
INPUT_ROOT = ROOT / "tests" / "fixtures" / "export" / "input"
EXPECTED_ROOT = ROOT / "tests" / "fixtures" / "export" / "expected"
INVALID_ROOT = ROOT / "tests" / "fixtures" / "export" / "invalid"
PROFILE_PATH = ROOT / "profiles" / "public-evidence-export.v0.1.json"
STATUS_FIXTURES = {
    "pass": "safe-pass.json",
    "fail": "status-fail.json",
    "skip": "status-skip.json",
    "unsupported": "status-unsupported.json",
    "timeout": "status-timeout.json",
    "tool-error": "status-tool-error.json",
}


def load_json(path: Path) -> dict:
    value = strict_loads(path.read_bytes(), max_bytes=1_048_576)
    assert isinstance(value, dict)
    return value


def rebound(candidate: dict) -> dict:
    candidate["source_binding"]["source_evidence_record_digest"] = (
        source_evidence_digest(candidate["evidence_record"])
    )
    return candidate


class EvidenceExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        (ROOT / ".codex-local" / "tmp").mkdir(parents=True, exist_ok=True)
        cls.profile = _load_profile(PROFILE_PATH)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            dir=ROOT / ".codex-local" / "tmp", prefix="export-test-"
        )
        self.temp_root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def export_file(self, fixture: str) -> tuple[Path, dict]:
        relative_output = self.temp_root.relative_to(ROOT) / fixture.removesuffix(
            ".json"
        )
        return run_export(
            root=ROOT,
            staging_root=Path("tests/fixtures/export/input"),
            input_name=Path(fixture),
            profile_name=Path("profiles/public-evidence-export.v0.1.json"),
            output_dir=relative_output,
        )

    def assertRejected(self, candidate: dict, code: str) -> ExportError:
        with self.assertRaises(ExportError) as caught:
            export_candidate(candidate, self.profile, ROOT)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def test_valid_fixture_outputs_match_committed_bytes(self) -> None:
        for fixture in sorted(path.name for path in INPUT_ROOT.glob("*.json")):
            with self.subTest(fixture=fixture):
                output, bundle = self.export_file(fixture)
                self.assertEqual(
                    output.read_bytes(), (EXPECTED_ROOT / fixture).read_bytes()
                )
                self.assertEqual(bundle["bundle_digest"], bundle_digest(bundle))
                self.assertEqual(
                    validate_export_bundle(bundle, fixture, ROOT, profile=self.profile),
                    [],
                )

    def test_export_schemas_are_valid(self) -> None:
        self.assertEqual(
            set(load_export_schemas(ROOT)),
            {
                "evidence-export-candidate",
                "evidence-export-profile",
                "public-evidence-export",
            },
        )

    def test_status_is_preserved_exactly_for_all_six_states(self) -> None:
        for status, fixture in STATUS_FIXTURES.items():
            with self.subTest(status=status):
                _path, bundle = self.export_file(fixture)
                self.assertEqual(bundle["evidence_record"]["status"], status)
                self.assertEqual(bundle["sanitization_report"]["input_status"], status)
                self.assertEqual(bundle["sanitization_report"]["output_status"], status)
                self.assertEqual(bundle["evidence_record"]["lifecycle"], "sanitized")
                self.assertEqual(bundle["publication"]["status"], "candidate")
                self.assertEqual(
                    bundle["review_requirements"]["final_publication_approval"],
                    "required-not-provided",
                )

    def test_map_order_and_semantic_set_order_are_deterministic(self) -> None:
        original = load_json(INPUT_ROOT / "safe-pass.json")
        reordered = dict(reversed(list(copy.deepcopy(original).items())))
        reordered["evidence_record"] = dict(
            reversed(list(reordered["evidence_record"].items()))
        )
        extra = "sha256:" + "0" * 64
        original["evidence_record"]["input_digests"].append(extra)
        reordered["evidence_record"]["input_digests"].insert(0, extra)
        rebound(original)
        rebound(reordered)
        first = export_candidate(original, self.profile, ROOT)
        second = export_candidate(reordered, self.profile, ROOT)
        self.assertEqual(canonicalize(first), canonicalize(second))
        self.assertEqual(first["bundle_digest"], second["bundle_digest"])

    def test_approved_omission_has_value_free_log(self) -> None:
        _path, bundle = self.export_file("approved-omission.json")
        self.assertEqual(bundle["evidence_record"]["public_artifacts"], [])
        self.assertEqual(
            set(bundle["omissions"][0]),
            {"path", "rule_id", "category", "action", "human_review_digest"},
        )
        serialized = canonicalize(bundle["omissions"])
        self.assertNotIn(b"reports/synthetic-evidence.json", serialized)
        self.assertNotIn(b"original", serialized)

    def test_already_sanitized_history_is_not_rewritten(self) -> None:
        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        event = copy.deepcopy(candidate["sanitization_event"])
        candidate["evidence_record"]["lifecycle"] = "sanitized"
        candidate["evidence_record"]["lifecycle_history"].append(
            {
                "state": "sanitized",
                "recorded_at": event["recorded_at"],
                "review_digest": event["review_digest"],
            }
        )
        candidate["source_binding"]["original_lifecycle"] = "sanitized"
        rebound(candidate)
        original_history = copy.deepcopy(
            candidate["evidence_record"]["lifecycle_history"]
        )
        bundle = export_candidate(candidate, self.profile, ROOT)
        self.assertEqual(
            bundle["evidence_record"]["lifecycle_history"], original_history
        )

    def test_protocol_fixture_uses_reviewed_merged_digests(self) -> None:
        candidate = load_json(INPUT_ROOT / "protocol-conformance.json")
        pin = self.profile["reviewed_protocol_binding"]
        self.assertEqual(
            pin["merge_commit"], "2c314027f61ca0f0edbe2dcc55a8305710efd91d"
        )
        self.assertEqual(
            candidate["protocol_binding"]["state_machine_digest"],
            pin["state_machine_digest"],
        )
        self.assertEqual(
            candidate["protocol_binding"]["message_registry_digest"],
            pin["message_registry_digest"],
        )
        self.assertEqual(
            candidate["conformance_suite_binding"]["digest"],
            pin["conformance_suite_digest"],
        )

    def test_existing_evidence_schema_and_validator_accept_output(self) -> None:
        for fixture in STATUS_FIXTURES.values():
            with self.subTest(fixture=fixture):
                _path, bundle = self.export_file(fixture)
                findings = validate_record(
                    bundle["evidence_record"], fixture, load_schemas(ROOT)
                )
                self.assertEqual(findings, [])

    def test_required_invalid_fixtures_fail_closed(self) -> None:
        expectations = {
            "embedded-secret": "sensitive-value",
            "customer-identifier": "sensitive-value",
            "internal-url": "sensitive-value",
            "account-identifier": "sensitive-value",
            "private-repository-path": "sensitive-value",
            "status-rewrite": "status-preservation",
            "missing-source-digest": "candidate-schema",
            "unapproved-vulnerability": "candidate-schema",
            "unknown-field": "candidate-schema",
            "ambiguous-redaction": "candidate-schema",
        }
        for name, code in expectations.items():
            with self.subTest(name=name):
                candidate = load_json(INVALID_ROOT / f"{name}.json")
                self.assertRejected(candidate, code)

    def test_sensitive_string_classes_are_rejected_without_value_in_error(self) -> None:
        values = {
            "pem": "-----BEGIN PRIVATE KEY----- synthetic",
            "github": "ghp_SYNTHETIC012345678901234567890",
            "aws": "AKIASYNTHETIC0000000",
            "bearer": "Bearer SYNTHETIC01234567890",
            "jwt": "eyJAAAAA.eyJBBBBB.CCCCCCC",
            "dsn": "postgres://fixture-user:fixture-password@db.example.invalid/catalog",
            "localhost": "http://localhost/status",
            "private-ip": "https://10.1.2.3/status",
            "metadata": "http://169.254.169.254/latest/meta-data",
            "email": "synthetic@example.invalid",
            "phone": "+1 202 555 0101",
            "customer-id": "cust-SYNTHETIC001",
            "posix": "/home/synthetic/private/file",
            "posix-tmp": "/tmp/synthetic-private-file",
            "windows": "C:\\Users\\synthetic\\private\\file",
            "parent-segment": "reports/../private/file",
            "repo": "git@example.invalid:private-match-product/repository.git",
            "vulnerability": "exploit command for vulnerable private endpoint",
            "bidi": "safe\u202esecret",
            "zero-width": "to\u200bken",
            "encoded": "http%3A%2F%2F127.0.0.1%2Fprivate",
            "base64": "aHR0cDovLzEyNy4wLjAuMS9wcml2YXRl",
        }
        for name, value in values.items():
            with self.subTest(name=name):
                candidate = load_json(INPUT_ROOT / "safe-pass.json")
                candidate["evidence_record"]["summary"] = value
                rebound(candidate)
                error = self.assertRejected(candidate, "sensitive-value")
                self.assertNotIn(value, str(error))

    def test_prohibited_configuration_and_field_names_fail_closed(self) -> None:
        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["evidence_record"]["configuration"]["unknown"] = "synthetic"
        rebound(candidate)
        self.assertRejected(candidate, "configuration-allowlist")

        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["evidence_record"]["configuration"]["customer_id"] = "synthetic"
        rebound(candidate)
        self.assertRejected(candidate, "configuration-allowlist")

    def test_status_rewrites_and_lifecycle_rewrites_fail(self) -> None:
        candidate = load_json(INPUT_ROOT / "status-skip.json")
        candidate["source_binding"]["original_status"] = "pass"
        self.assertRejected(candidate, "status-preservation")

        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["source_binding"]["original_lifecycle"] = "collected"
        self.assertRejected(candidate, "lifecycle-preservation")

        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["evidence_record"]["lifecycle_history"] = list(
            reversed(candidate["evidence_record"]["lifecycle_history"])
        )
        rebound(candidate)
        self.assertTrue(self.assertRejected(candidate, "evidence-lifecycle-start"))

        bundle = export_candidate(
            load_json(INPUT_ROOT / "status-skip.json"), self.profile, ROOT
        )
        bundle["sanitization_report"]["output_status"] = "pass"
        bundle["bundle_digest"] = bundle_digest(bundle)
        with self.assertRaises(ExportError):
            validate_public_bundle(bundle, ROOT, self.profile)

    def test_ip_vulnerability_and_review_gates_fail_closed(self) -> None:
        cases = []
        for path, value in (
            (("sensitivity_markers", "unpublished_invention"), True),
            (("sensitivity_markers", "patent_candidate"), True),
        ):
            candidate = load_json(INPUT_ROOT / "safe-pass.json")
            candidate[path[0]][path[1]] = value
            cases.append(candidate)
        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["review_markers"].pop("ip")
        cases.append(candidate)
        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["review_markers"].pop("privacy")
        cases.append(candidate)
        for candidate in cases:
            with self.subTest(candidate=len(candidate)):
                with self.assertRaises(ExportError):
                    export_candidate(candidate, self.profile, ROOT)

    def test_final_publication_approval_cannot_be_supplied_or_generated(self) -> None:
        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["review_markers"]["final_publication_approval"] = {
            "status": "approved"
        }
        self.assertRejected(candidate, "candidate-schema")
        bundle = export_candidate(
            load_json(INPUT_ROOT / "safe-pass.json"), self.profile, ROOT
        )
        self.assertNotIn("publication_approval", bundle["exporter"])
        self.assertEqual(
            bundle["publication"],
            {"status": "candidate", "automation_permitted": False},
        )

    def test_bundle_rejects_raw_or_value_digest_redaction_fields(self) -> None:
        bundle = export_candidate(
            load_json(INPUT_ROOT / "approved-omission.json"), self.profile, ROOT
        )
        for field in ("original_value", "value_digest"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(bundle)
                mutated["omissions"][0][field] = "synthetic"
                mutated["bundle_digest"] = bundle_digest(mutated)
                with self.assertRaises(ExportError):
                    validate_public_bundle(mutated, ROOT, self.profile)

    def test_path_boundary_missing_directory_symlink_and_output_escape(self) -> None:
        kwargs = {
            "root": ROOT,
            "staging_root": Path("tests/fixtures/export/input"),
            "input_name": Path("safe-pass.json"),
            "profile_name": Path("profiles/public-evidence-export.v0.1.json"),
            "output_dir": self.temp_root.relative_to(ROOT) / "out",
        }
        for unsafe in (Path("../safe-pass.json"), Path("/etc/passwd")):
            with self.subTest(unsafe=unsafe), self.assertRaises(ExportError):
                run_export(**{**kwargs, "input_name": unsafe})
        with self.assertRaises(ExportError):
            run_export(**{**kwargs, "input_name": Path("missing.json")})
        with self.assertRaises(ExportError):
            run_export(**{**kwargs, "input_name": Path(".")})
        with self.assertRaises(ExportError):
            run_export(**{**kwargs, "output_dir": Path("../outside")})

        symlink = INPUT_ROOT / "synthetic-export-symlink.json"
        outside = self.temp_root / "outside.json"
        outside.write_bytes((INPUT_ROOT / "safe-pass.json").read_bytes())
        try:
            symlink.symlink_to(outside)
            with self.assertRaises(ExportError):
                run_export(**{**kwargs, "input_name": Path(symlink.name)})
        finally:
            symlink.unlink(missing_ok=True)

        link_dir = INPUT_ROOT / "synthetic-export-link-dir"
        try:
            link_dir.symlink_to(self.temp_root, target_is_directory=True)
            with self.assertRaises(ExportError):
                run_export(
                    **{**kwargs, "input_name": Path(link_dir.name) / "outside.json"}
                )
        finally:
            link_dir.unlink(missing_ok=True)

    def test_oversized_duplicate_key_invalid_utf8_and_json_numbers_fail(self) -> None:
        staging = self.temp_root / "staging"
        staging.mkdir()
        relative_staging = staging.relative_to(ROOT)
        output = self.temp_root.relative_to(ROOT) / "out"
        base = {
            "root": ROOT,
            "staging_root": relative_staging,
            "profile_name": Path("profiles/public-evidence-export.v0.1.json"),
            "output_dir": output,
        }
        payloads = {
            "oversized.json": b" " * 262_145,
            "duplicate.json": b'{"schema_version":"0.1","schema_version":"0.1"}',
            "utf8.json": b'{"x":"\xff"}',
            "nan.json": b'{"value":NaN}',
            "infinity.json": b'{"value":Infinity}',
            "negative-zero.json": b'{"value":-0}',
            "unsafe-integer.json": b'{"value":9007199254740992}',
        }
        for name, payload in payloads.items():
            with self.subTest(name=name):
                (staging / name).write_bytes(payload)
                with self.assertRaises(ExportError):
                    run_export(**base, input_name=Path(name))

    def test_rejection_leaves_no_output_and_cli_error_is_value_free(self) -> None:
        output = self.temp_root.relative_to(ROOT) / "rejected"
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main(
                [
                    "--root",
                    str(ROOT),
                    "--staging-root",
                    "tests/fixtures/export/invalid",
                    "--input",
                    "embedded-secret.json",
                    "--output-dir",
                    str(output),
                ]
            )
        self.assertEqual(code, 1)
        self.assertFalse((ROOT / output / "public-evidence-export.v0.1.json").exists())
        self.assertNotIn("SYNTHETIC_TEST_TOKEN", stderr.getvalue())
        self.assertIn("[sensitive-value]", stderr.getvalue())

    def test_successful_output_uses_restrictive_mode(self) -> None:
        output, _bundle = self.export_file("safe-pass.json")
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_exporter_does_not_call_network_or_subprocess(self) -> None:
        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        with (
            mock.patch.object(socket, "socket", side_effect=AssertionError("network")),
            mock.patch.object(
                subprocess, "run", side_effect=AssertionError("subprocess")
            ),
        ):
            bundle = export_candidate(candidate, self.profile, ROOT)
        self.assertEqual(bundle["sanitization_report"]["outcome"], "exported")

    def test_expected_bundle_is_strict_canonical_utf8(self) -> None:
        for path in EXPECTED_ROOT.glob("*.json"):
            with self.subTest(path=path.name):
                raw = path.read_bytes()
                value = strict_loads(raw, max_bytes=1_048_576)
                self.assertEqual(raw, canonicalize(value) + b"\n")

    def test_programmatic_negative_zero_is_rejected(self) -> None:
        with self.assertRaises(CanonicalJSONError):
            canonicalize({"value": -0.0})

    def test_rfc_8785_appendix_b_number_vectors(self) -> None:
        samples = {
            "0000000000000000": b"0",
            "0000000000000001": b"5e-324",
            "8000000000000001": b"-5e-324",
            "7fefffffffffffff": b"1.7976931348623157e+308",
            "ffefffffffffffff": b"-1.7976931348623157e+308",
            "44b52d02c7e14af6": b"1e+23",
            "3eb0c6f7a0b5ed8d": b"0.000001",
            "43143ff3c1cb0959": b"1424953923781206.2",
        }
        for hexadecimal, expected in samples.items():
            with self.subTest(hexadecimal=hexadecimal):
                value = struct.unpack(">d", bytes.fromhex(hexadecimal))[0]
                self.assertEqual(canonicalize(value), expected)

    def test_rfc_8785_canonical_sample_and_unicode_boundary(self) -> None:
        value = {
            "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
            "string": '€$\u000f\nA\'B"\\\\"/',
            "literals": [None, True, False],
        }
        expected = (
            b'{"literals":[null,true,false],"numbers":[333333333.3333333,'
            b'1e+30,4.5,0.002,1e-27],"string":"\xe2\x82\xac$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}'
        )
        self.assertEqual(canonicalize(value), expected)
        self.assertNotEqual(canonicalize("Caf\u00e9"), canonicalize("Cafe\u0301"))
        with self.assertRaises(CanonicalJSONError):
            canonicalize("\ud800")

    def test_rfc_8785_and_ruff_are_exact_and_hash_locked(self) -> None:
        direct = (ROOT / "requirements-dev.in").read_text(encoding="utf-8")
        locked = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
        for requirement in ("rfc8785==0.1.4", "ruff==0.15.15"):
            self.assertIn(requirement, direct)
            self.assertIn(requirement, locked)
        rfc_block = locked.split("rfc8785==0.1.4", 1)[1].split("\n\n", 1)[0]
        self.assertIn("--hash=sha256:", rfc_block)


if __name__ == "__main__":
    unittest.main()
