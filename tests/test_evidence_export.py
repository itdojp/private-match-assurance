from __future__ import annotations

import copy
import io
import shutil
import socket
import struct
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from scripts.canonical_json import (
    CanonicalJSONError,
    canonicalize,
    strict_loads,
)
from scripts.export_public_evidence import (
    EXPORT_CANDIDATE_MODE,
    TEST_FIXTURE_MODE,
    ExportError,
    _candidate_digest,
    _load_profile,
    bundle_digest,
    export_candidate,
    main,
    review_subject_digest,
    run_export,
    source_evidence_digest,
    validate_public_bundle,
)
from scripts.exporter_manifest import (
    EVIDENCE_SCHEMA_PATH,
    LOCK_PATHS,
    MANIFEST_PATH,
    RUNTIME_REQUIREMENTS,
    SCHEMA_PATHS,
    SOURCE_PATHS,
    TEST_TRUST_PATHS,
    TESTED_TARGET,
    ImplementationManifestError,
    build_implementation_manifest,
    canonical_manifest_bytes,
    implementation_digest,
    manifest_file_digest,
    verify_implementation_manifest,
)
from scripts.validate_assurance import (
    ExportArtifactError,
    load_export_fixture_catalog,
    load_export_schemas,
    load_schemas,
    validate_export_configuration,
    validate_export_bundle,
    validate_record,
)
from scripts.validate_assurance import main as assurance_main
from scripts.public_export_policy import (
    PROGRAMMATIC_INTERFACE,
    STAGED_FILE_INTERFACE,
    expected_sanitization_checks,
    scan_public_strings,
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


def bind_reviews(candidate: dict) -> dict:
    subject = review_subject_digest(candidate)
    candidate["review_subject_digest"] = subject
    for review in candidate["review_markers"].values():
        review["reviewed_subject_digest"] = subject
    return candidate


def export_fixture_candidate(candidate: dict, profile: dict, root: Path) -> dict:
    return export_candidate(candidate, profile, root, mode=TEST_FIXTURE_MODE)


def validate_fixture_bundle(bundle: dict, root: Path, profile: dict) -> None:
    validate_public_bundle(bundle, root, profile, mode=TEST_FIXTURE_MODE)


def real_candidate(candidate: dict) -> dict:
    candidate = copy.deepcopy(candidate)
    candidate["artifact_status"] = "export-candidate"
    candidate["export_candidate_id"] = (
        "PM-EXPORT-CANDIDATE-8D7D6658D2E84E568E39520A852A6D88"
    )
    for index, review in enumerate(candidate["review_markers"].values(), start=8):
        review["reviewer_role"] = "authorized-human"
        review["review_digest"] = "sha256:" + format(index, "x") * 64
    return bind_reviews(candidate)


def rebound(candidate: dict) -> dict:
    candidate["source_binding"]["source_evidence_record_digest"] = (
        source_evidence_digest(candidate["evidence_record"])
    )
    return bind_reviews(candidate)


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
            mode=TEST_FIXTURE_MODE,
        )

    def assertRejected(self, candidate: dict, code: str) -> ExportError:
        with self.assertRaises(ExportError) as caught:
            export_fixture_candidate(candidate, self.profile, ROOT)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def assertBothBundleValidatorsReject(
        self,
        bundle: dict,
        *,
        mode: str = TEST_FIXTURE_MODE,
        semantic_code: str | None = None,
    ) -> None:
        with self.assertRaises(ExportError) as caught:
            validate_public_bundle(bundle, ROOT, self.profile, mode=mode)
        findings = validate_export_bundle(
            bundle,
            "mutated-bundle",
            ROOT,
            profile=self.profile,
            mode=mode,
        )
        self.assertTrue(findings)
        if semantic_code is not None:
            self.assertEqual(caught.exception.code, semantic_code)
            self.assertIn(semantic_code, {finding.code for finding in findings})

    def copy_manifest_inputs(self, name: str = "manifest-root") -> Path:
        root = self.temp_root / name
        paths = {
            *SOURCE_PATHS,
            *SCHEMA_PATHS,
            *LOCK_PATHS,
            *TEST_TRUST_PATHS,
            EVIDENCE_SCHEMA_PATH,
        }
        for relative in sorted(paths):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        return root

    def copy_cli_root(self, name: str = "cli-root") -> Path:
        root = self.copy_manifest_inputs(name)
        for source in sorted((ROOT / "schema").glob("*.json")):
            destination = root / "schema" / source.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        for relative in (
            Path("profiles/public-evidence-export.v0.1.json"),
            MANIFEST_PATH,
        ):
            destination = root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / relative, destination)
        return root

    def run_assurance_cli(
        self,
        root: Path,
        bundle: dict,
        *,
        mode: str = TEST_FIXTURE_MODE,
    ) -> tuple[int, dict]:
        bundle_path = root / "bundle.json"
        bundle_path.write_bytes(canonicalize(bundle) + b"\n")
        report = root / "report"
        with redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            result = assurance_main(
                [
                    "--root",
                    str(root),
                    "--report-dir",
                    str(report),
                    "--export-profile",
                    "profiles/public-evidence-export.v0.1.json",
                    "--export-mode",
                    mode,
                    "--export-bundle",
                    "bundle.json",
                ]
            )
        return result, load_json(report / "assurance-schema-report.json")

    def test_valid_fixture_outputs_match_committed_bytes(self) -> None:
        for fixture in sorted(path.name for path in INPUT_ROOT.glob("*.json")):
            with self.subTest(fixture=fixture):
                output, bundle = self.export_file(fixture)
                self.assertEqual(
                    output.read_bytes(), (EXPECTED_ROOT / fixture).read_bytes()
                )
                self.assertEqual(bundle["bundle_digest"], bundle_digest(bundle))
                self.assertEqual(
                    validate_export_bundle(
                        bundle,
                        fixture,
                        ROOT,
                        profile=self.profile,
                        mode=TEST_FIXTURE_MODE,
                    ),
                    [],
                )

    def test_export_schemas_are_valid(self) -> None:
        self.assertEqual(
            set(load_export_schemas(ROOT)),
            {
                "evidence-export-candidate",
                "evidence-export-configuration",
                "evidence-export-fixture-catalog",
                "evidence-export-profile",
                "evidence-exporter-implementation",
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
                self.assertEqual(bundle["publication"]["status"], "test-only")
                self.assertEqual(
                    bundle["review_requirements"]["final_publication_approval"],
                    "not-applicable-test-only",
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
        first = export_candidate(real_candidate(original), self.profile, ROOT)
        second = export_candidate(real_candidate(reordered), self.profile, ROOT)
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
        bundle = export_candidate(real_candidate(candidate), self.profile, ROOT)
        self.assertEqual(
            bundle["evidence_record"]["lifecycle_history"], original_history
        )

    def test_lifecycle_requires_private_side_validation_before_export(self) -> None:
        validated = real_candidate(load_json(INPUT_ROOT / "safe-pass.json"))
        validated_bundle = export_candidate(validated, self.profile, ROOT)
        self.assertEqual(
            validated_bundle["sanitization_report"]["input_lifecycle"], "validated"
        )
        self.assertEqual(validated_bundle["evidence_record"]["lifecycle"], "sanitized")

        collected = real_candidate(load_json(INPUT_ROOT / "safe-pass.json"))
        collected["evidence_record"]["lifecycle"] = "collected"
        collected["evidence_record"]["lifecycle_history"] = collected[
            "evidence_record"
        ]["lifecycle_history"][:1]
        collected["source_binding"]["original_lifecycle"] = "collected"
        rebound(collected)
        self.assertNotIn("collected", self.profile["lifecycle_rule"]["allowed_input"])
        candidate_validator = load_export_schemas(ROOT)["evidence-export-candidate"]
        self.assertTrue(list(candidate_validator.iter_errors(collected)))
        with self.assertRaises(ExportError) as caught:
            export_candidate(collected, self.profile, ROOT)
        self.assertEqual(caught.exception.code, "lifecycle-not-validated")

        staging = self.temp_root / "collected-staging"
        staging.mkdir()
        (staging / "collected.json").write_bytes(canonicalize(collected) + b"\n")
        output = self.temp_root.relative_to(ROOT) / "collected-output"
        with self.assertRaises(ExportError) as caught:
            run_export(
                root=ROOT,
                staging_root=staging.relative_to(ROOT),
                input_name=Path("collected.json"),
                profile_name=Path("profiles/public-evidence-export.v0.1.json"),
                output_dir=output,
            )
        self.assertEqual(caught.exception.code, "lifecycle-not-validated")
        self.assertFalse((ROOT / output / "public-evidence-export.v0.1.json").exists())

        invalid_bundle = copy.deepcopy(validated_bundle)
        invalid_bundle["evidence_record"]["lifecycle"] = "collected"
        invalid_bundle["sanitization_report"]["output_lifecycle"] = "collected"
        invalid_bundle["bundle_digest"] = bundle_digest(invalid_bundle)
        self.assertTrue(
            validate_export_bundle(
                invalid_bundle, "collected", ROOT, profile=self.profile
            )
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
        self.assertRejected(candidate, "configuration-contract")

    def test_type_specific_configuration_contracts_are_fully_closed(self) -> None:
        valid_by_type = {
            "test": "safe-pass.json",
            "conformance": "protocol-conformance.json",
            "model-check": "model-check.json",
            "provenance": "not-publicly-reproducible.json",
            "review": "approved-omission.json",
        }
        for evidence_type, fixture in valid_by_type.items():
            with self.subTest(valid=evidence_type):
                candidate = load_json(INPUT_ROOT / fixture)
                self.assertEqual(
                    validate_export_configuration(
                        candidate["evidence_record"],
                        fixture,
                        ROOT,
                        self.profile,
                    ),
                    [],
                )

        mutations = []
        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["evidence_record"]["configuration"]["test_suite"] = {
            "identifier": "synthetic-export",
            "unknown": "synthetic",
        }
        mutations.append(("test suite object", candidate))
        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["evidence_record"]["configuration"]["case_count"] = "3"
        mutations.append(("test count string", candidate))

        candidate = load_json(INPUT_ROOT / "protocol-conformance.json")
        candidate["evidence_record"]["configuration"]["protocol"]["unknown"] = (
            "synthetic"
        )
        mutations.append(("protocol nested unknown", candidate))
        candidate = load_json(INPUT_ROOT / "protocol-conformance.json")
        candidate["evidence_record"]["configuration"]["conformance_suite"][
            "unknown"
        ] = "synthetic"
        mutations.append(("suite nested unknown", candidate))
        candidate = load_json(INPUT_ROOT / "protocol-conformance.json")
        candidate["evidence_record"]["configuration"]["protocol"]["version"] = {
            "value": "0.1"
        }
        mutations.append(("malformed versioned artifact", candidate))

        for fixture, field in (
            ("model-check.json", "unknown"),
            ("not-publicly-reproducible.json", "unknown"),
            ("approved-omission.json", "unknown"),
        ):
            candidate = load_json(INPUT_ROOT / fixture)
            candidate["evidence_record"]["configuration"][field] = "synthetic"
            mutations.append((f"{fixture} unknown", candidate))

        for name, candidate in mutations:
            with self.subTest(invalid=name):
                rebound(candidate)
                self.assertRejected(candidate, "configuration-contract")

        unknown_type = load_json(INPUT_ROOT / "safe-pass.json")
        unknown_type["evidence_record"]["type"] = "benchmark"
        rebound(unknown_type)
        self.assertRejected(unknown_type, "configuration-contract")

        binding_mismatch = load_json(INPUT_ROOT / "protocol-conformance.json")
        binding_mismatch["evidence_record"]["configuration"]["protocol"][
            "identifier"
        ] = "other-protocol"
        rebound(binding_mismatch)
        self.assertRejected(binding_mismatch, "configuration-binding")

        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["evidence_record"]["configuration"]["customer_id"] = "synthetic"
        rebound(candidate)
        self.assertRejected(candidate, "configuration-contract")

    def test_status_rewrites_and_lifecycle_rewrites_fail(self) -> None:
        candidate = load_json(INPUT_ROOT / "status-skip.json")
        candidate["source_binding"]["original_status"] = "pass"
        self.assertRejected(candidate, "status-preservation")

        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["source_binding"]["original_lifecycle"] = "collected"
        self.assertRejected(candidate, "lifecycle-not-validated")

        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["evidence_record"]["lifecycle_history"] = list(
            reversed(candidate["evidence_record"]["lifecycle_history"])
        )
        rebound(candidate)
        self.assertTrue(self.assertRejected(candidate, "evidence-lifecycle-start"))

        bundle = export_fixture_candidate(
            load_json(INPUT_ROOT / "status-skip.json"), self.profile, ROOT
        )
        bundle["sanitization_report"]["output_status"] = "pass"
        bundle["bundle_digest"] = bundle_digest(bundle)
        with self.assertRaises(ExportError):
            validate_fixture_bundle(bundle, ROOT, self.profile)

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
                    export_fixture_candidate(candidate, self.profile, ROOT)

    def test_final_publication_approval_cannot_be_supplied_or_generated(self) -> None:
        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        candidate["review_markers"]["final_publication_approval"] = {
            "status": "approved"
        }
        self.assertRejected(candidate, "candidate-schema")
        bundle = export_fixture_candidate(
            load_json(INPUT_ROOT / "safe-pass.json"), self.profile, ROOT
        )
        self.assertNotIn("publication_approval", bundle["exporter"])
        self.assertEqual(
            bundle["publication"],
            {"status": "test-only", "automation_permitted": False},
        )

    def test_bundle_rejects_raw_or_value_digest_redaction_fields(self) -> None:
        bundle = export_fixture_candidate(
            load_json(INPUT_ROOT / "approved-omission.json"), self.profile, ROOT
        )
        for field in ("original_value", "value_digest"):
            with self.subTest(field=field):
                mutated = copy.deepcopy(bundle)
                mutated["omissions"][0][field] = "synthetic"
                mutated["bundle_digest"] = bundle_digest(mutated)
                with self.assertRaises(ExportError):
                    validate_fixture_bundle(mutated, ROOT, self.profile)

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
        staging = self.temp_root / "sensitive-input"
        staging.mkdir()
        candidate = real_candidate(load_json(INVALID_ROOT / "embedded-secret.json"))
        (staging / "embedded-secret.json").write_bytes(canonicalize(candidate))
        output = self.temp_root.relative_to(ROOT) / "rejected"
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            code = main(
                [
                    "--root",
                    str(ROOT),
                    "--staging-root",
                    str(staging.relative_to(ROOT)),
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
            bundle = export_fixture_candidate(candidate, self.profile, ROOT)
        self.assertEqual(bundle["sanitization_report"]["outcome"], "exported")

    def test_expected_bundle_is_strict_canonical_utf8(self) -> None:
        for path in EXPECTED_ROOT.glob("*.json"):
            with self.subTest(path=path.name):
                raw = path.read_bytes()
                value = strict_loads(raw, max_bytes=1_048_576)
                self.assertEqual(raw, canonicalize(value) + b"\n")

    def test_trusted_execution_modes_and_public_bundle_distinction(self) -> None:
        synthetic = load_json(INPUT_ROOT / "safe-pass.json")
        real = real_candidate(synthetic)
        real_bundle = export_candidate(real, self.profile, ROOT)
        self.assertEqual(real_bundle["artifact_status"], "export-candidate")
        self.assertEqual(real_bundle["publication"]["status"], "candidate")
        self.assertEqual(
            real_bundle["review_requirements"]["final_publication_approval"],
            "required-not-provided",
        )
        self.assertEqual(
            validate_export_bundle(real_bundle, "real", ROOT, profile=self.profile),
            [],
        )

        with self.assertRaises(ExportError):
            export_candidate(synthetic, self.profile, ROOT)
        synthetic_role = copy.deepcopy(real)
        synthetic_role["review_markers"]["privacy"]["reviewer_role"] = (
            "synthetic-reviewer"
        )
        with self.assertRaises(ExportError):
            export_candidate(synthetic_role, self.profile, ROOT)
        fixture_digest = copy.deepcopy(real)
        fixture_digest["review_markers"]["privacy"]["review_digest"] = synthetic[
            "review_markers"
        ]["privacy"]["review_digest"]
        with self.assertRaises(ExportError) as caught:
            export_candidate(fixture_digest, self.profile, ROOT)
        self.assertEqual(caught.exception.code, "review-role")

        _path, synthetic_bundle = self.export_file("safe-pass.json")
        self.assertEqual(synthetic_bundle["artifact_status"], "test-only")
        self.assertEqual(synthetic_bundle["publication"]["status"], "test-only")
        self.assertTrue(
            all(
                item["reviewer_role"] == "synthetic-reviewer"
                for item in synthetic_bundle["review_provenance"]
            )
        )
        with self.assertRaises(ExportError):
            validate_public_bundle(synthetic_bundle, ROOT, self.profile)

        stale_catalog = copy.deepcopy(synthetic_bundle)
        stale_catalog["fixture_provenance"]["fixture_catalog_digest"] = (
            "sha256:" + "f" * 64
        )
        stale_catalog["bundle_digest"] = bundle_digest(stale_catalog)
        with self.assertRaises(ExportError) as caught:
            validate_fixture_bundle(stale_catalog, ROOT, self.profile)
        self.assertEqual(caught.exception.code, "fixture-provenance")

        uncatalogued = copy.deepcopy(synthetic)
        uncatalogued["export_candidate_id"] = "PM-EXPORT-CANDIDATE-UNLISTED"
        bind_reviews(uncatalogued)
        with self.assertRaises(ExportError) as caught:
            export_candidate(uncatalogued, self.profile, ROOT, mode=TEST_FIXTURE_MODE)
        self.assertEqual(caught.exception.code, "fixture-catalog")
        with self.assertRaises(ExportError) as caught:
            export_candidate(
                synthetic,
                self.profile,
                ROOT,
                mode=TEST_FIXTURE_MODE,
                input_name=Path("different-name.json"),
            )
        self.assertEqual(caught.exception.code, "fixture-catalog")

        authorized_fixture = copy.deepcopy(synthetic)
        authorized_fixture["review_markers"]["privacy"]["reviewer_role"] = (
            "authorized-human"
        )
        with self.assertRaises(ExportError) as caught:
            export_candidate(
                authorized_fixture, self.profile, ROOT, mode=TEST_FIXTURE_MODE
            )
        self.assertEqual(caught.exception.code, "review-role")

        with self.assertRaises(ExportError) as caught:
            run_export(
                root=ROOT,
                staging_root=self.temp_root.relative_to(ROOT),
                input_name=Path("safe-pass.json"),
                profile_name=Path("profiles/public-evidence-export.v0.1.json"),
                output_dir=self.temp_root.relative_to(ROOT) / "mode-out",
                mode=TEST_FIXTURE_MODE,
            )
        self.assertEqual(caught.exception.code, "fixture-root")

        promoted = copy.deepcopy(synthetic_bundle)
        promoted["artifact_status"] = "export-candidate"
        promoted["publication"]["status"] = "candidate"
        promoted["review_requirements"]["final_publication_approval"] = (
            "required-not-provided"
        )
        promoted["bundle_digest"] = bundle_digest(promoted)
        with self.assertRaises(ExportError):
            validate_public_bundle(promoted, ROOT, self.profile)

        demoted = copy.deepcopy(real_bundle)
        demoted["artifact_status"] = "test-only"
        demoted["publication"]["status"] = "test-only"
        demoted["review_requirements"]["final_publication_approval"] = (
            "not-applicable-test-only"
        )
        demoted["bundle_digest"] = bundle_digest(demoted)
        with self.assertRaises(ExportError):
            validate_public_bundle(demoted, ROOT, self.profile, mode=TEST_FIXTURE_MODE)

    def test_fixture_catalog_pins_candidates_and_bundle_provenance(self) -> None:
        catalog = load_json(ROOT / "tests/fixtures/export/fixture-catalog.v0.1.json")
        self.assertEqual(catalog["artifact_status"], "test-only")
        self.assertEqual(len(catalog["fixtures"]), 10)
        manifest = load_json(ROOT / MANIFEST_PATH)
        catalog_digest = next(
            item["digest"]
            for item in manifest["test_trust_artifacts"]
            if item["path"] == TEST_TRUST_PATHS[0]
        )
        for entry in catalog["fixtures"]:
            with self.subTest(fixture=entry["relative_input_path"]):
                candidate = load_json(INPUT_ROOT / entry["relative_input_path"])
                bundle = load_json(EXPECTED_ROOT / entry["relative_input_path"])
                self.assertEqual(
                    entry["candidate_digest"], _candidate_digest(candidate)
                )
                self.assertEqual(
                    bundle["fixture_provenance"],
                    {
                        "fixture_id": entry["fixture_id"],
                        "fixture_catalog_digest": catalog_digest,
                    },
                )

    def test_review_status_surfaces_are_exactly_consistent(self) -> None:
        fixture = export_fixture_candidate(
            load_json(INPUT_ROOT / "safe-pass.json"), self.profile, ROOT
        )
        candidate = export_candidate(
            real_candidate(load_json(INPUT_ROOT / "safe-pass.json")),
            self.profile,
            ROOT,
        )
        validate_fixture_bundle(fixture, ROOT, self.profile)
        validate_public_bundle(candidate, ROOT, self.profile)
        self.assertEqual(
            validate_export_bundle(
                fixture,
                "fixture",
                ROOT,
                profile=self.profile,
                mode=TEST_FIXTURE_MODE,
            ),
            [],
        )
        self.assertEqual(
            validate_export_bundle(candidate, "candidate", ROOT, profile=self.profile),
            [],
        )

        mutations = (
            ("privacy provenance", "privacy", "provenance", "not-applicable"),
            (
                "security provenance",
                "security-boundary",
                "provenance",
                "not-applicable",
            ),
            ("ip requirements", "ip", "requirements", "approved"),
            ("ip report", "ip", "report", "approved"),
            (
                "vulnerability requirements",
                "vulnerability",
                "requirements",
                "approved",
            ),
            ("vulnerability report", "vulnerability", "report", "approved"),
        )
        requirement_fields = {
            "privacy": "privacy",
            "security-boundary": "security_boundary",
            "ip": "ip",
            "vulnerability": "vulnerability",
        }
        report_fields = {
            "privacy": "privacy_review_marker",
            "security-boundary": "security_review_marker",
            "ip": "ip_review_marker",
            "vulnerability": "vulnerability_review_marker",
        }
        for name, scope, surface, value in mutations:
            mutated = copy.deepcopy(fixture)
            if surface == "provenance":
                next(
                    item
                    for item in mutated["review_provenance"]
                    if item["scope"] == scope
                )["status"] = value
            elif surface == "requirements":
                mutated["review_requirements"][requirement_fields[scope]] = value
            else:
                mutated["sanitization_report"][report_fields[scope]] = value
            mutated["bundle_digest"] = bundle_digest(mutated)
            with self.subTest(name=name):
                self.assertBothBundleValidatorsReject(mutated)

        candidate_mismatch = copy.deepcopy(candidate)
        candidate_mismatch["review_requirements"]["ip"] = "approved"
        candidate_mismatch["bundle_digest"] = bundle_digest(candidate_mismatch)
        self.assertBothBundleValidatorsReject(
            candidate_mismatch,
            mode=EXPORT_CANDIDATE_MODE,
            semantic_code="review-status",
        )

    def test_fixture_provenance_binds_one_exact_catalog_entry(self) -> None:
        bundle = export_fixture_candidate(
            load_json(INPUT_ROOT / "safe-pass.json"), self.profile, ROOT
        )
        validate_fixture_bundle(bundle, ROOT, self.profile)

        unknown = copy.deepcopy(bundle)
        unknown["fixture_provenance"]["fixture_id"] = "FIXTURE-UNKNOWN-ENTRY"
        unknown["bundle_digest"] = bundle_digest(unknown)
        self.assertBothBundleValidatorsReject(
            unknown, semantic_code="fixture-provenance"
        )

        another = copy.deepcopy(bundle)
        another["fixture_provenance"]["fixture_id"] = "FIXTURE-MODEL-CHECK"
        another["bundle_digest"] = bundle_digest(another)
        self.assertBothBundleValidatorsReject(
            another, semantic_code="fixture-provenance"
        )

        changed_candidate = copy.deepcopy(bundle)
        changed_candidate["export_candidate_digest"] = "sha256:" + "0" * 64
        changed_candidate["digest_bindings"]["input_candidate_digest"] = (
            changed_candidate["export_candidate_digest"]
        )
        changed_candidate["bundle_digest"] = bundle_digest(changed_candidate)
        self.assertBothBundleValidatorsReject(
            changed_candidate, semantic_code="fixture-provenance"
        )

        stale_catalog = copy.deepcopy(bundle)
        stale_catalog["fixture_provenance"]["fixture_catalog_digest"] = (
            "sha256:" + "f" * 64
        )
        stale_catalog["bundle_digest"] = bundle_digest(stale_catalog)
        self.assertBothBundleValidatorsReject(
            stale_catalog, semantic_code="fixture-provenance"
        )

        candidate = export_candidate(
            real_candidate(load_json(INPUT_ROOT / "safe-pass.json")),
            self.profile,
            ROOT,
        )
        self.assertIsNone(candidate["fixture_provenance"])
        validate_public_bundle(candidate, ROOT, self.profile)
        candidate["fixture_provenance"] = copy.deepcopy(bundle["fixture_provenance"])
        candidate["bundle_digest"] = bundle_digest(candidate)
        self.assertBothBundleValidatorsReject(candidate, mode=EXPORT_CANDIDATE_MODE)

        for mutation in ("artifact-status", "duplicate-id"):
            with self.subTest(catalog=mutation):
                temp_root = self.copy_manifest_inputs()
                path = temp_root / TEST_TRUST_PATHS[0]
                catalog = load_json(path)
                if mutation == "artifact-status":
                    catalog["fixtures"][0]["artifact_status"] = "export-candidate"
                else:
                    catalog["fixtures"][1]["fixture_id"] = catalog["fixtures"][0][
                        "fixture_id"
                    ]
                path.write_bytes(canonicalize(catalog) + b"\n")
                with self.assertRaises(ExportArtifactError):
                    load_export_fixture_catalog(temp_root)

    def test_visible_bound_and_current_profile_digests_match(self) -> None:
        fixture = export_fixture_candidate(
            load_json(INPUT_ROOT / "safe-pass.json"), self.profile, ROOT
        )
        candidate = export_candidate(
            real_candidate(load_json(INPUT_ROOT / "safe-pass.json")),
            self.profile,
            ROOT,
        )
        for bundle, mode in (
            (fixture, TEST_FIXTURE_MODE),
            (candidate, EXPORT_CANDIDATE_MODE),
        ):
            current = self.profile["profile_digest"]
            self.assertEqual(bundle["export_profile"]["digest"], current)
            self.assertEqual(
                bundle["digest_bindings"]["export_profile_digest"], current
            )
            validate_public_bundle(bundle, ROOT, self.profile, mode=mode)

            visible_only = copy.deepcopy(bundle)
            visible_only["export_profile"]["digest"] = "sha256:" + "e" * 64
            visible_only["bundle_digest"] = bundle_digest(visible_only)
            self.assertBothBundleValidatorsReject(
                visible_only, mode=mode, semantic_code="profile-digest"
            )

            binding_only = copy.deepcopy(bundle)
            binding_only["digest_bindings"]["export_profile_digest"] = (
                "sha256:" + "d" * 64
            )
            binding_only["bundle_digest"] = bundle_digest(binding_only)
            self.assertBothBundleValidatorsReject(
                binding_only, mode=mode, semantic_code="profile-digest"
            )

            both_stale = copy.deepcopy(bundle)
            both_stale["export_profile"]["digest"] = "sha256:" + "c" * 64
            both_stale["digest_bindings"]["export_profile_digest"] = both_stale[
                "export_profile"
            ]["digest"]
            both_stale["bundle_digest"] = bundle_digest(both_stale)
            self.assertBothBundleValidatorsReject(
                both_stale, mode=mode, semantic_code="profile-digest"
            )

    def test_public_bundle_validation_requires_one_complete_profile(self) -> None:
        fixture_bundle = export_fixture_candidate(
            load_json(INPUT_ROOT / "safe-pass.json"), self.profile, ROOT
        )
        candidate_bundle = export_candidate(
            real_candidate(load_json(INPUT_ROOT / "safe-pass.json")),
            self.profile,
            ROOT,
        )
        for name, bundle, mode in (
            ("fixture", fixture_bundle, TEST_FIXTURE_MODE),
            ("candidate", candidate_bundle, EXPORT_CANDIDATE_MODE),
        ):
            root = self.copy_cli_root(f"valid-profile-{name}")
            result, report = self.run_assurance_cli(root, bundle, mode=mode)
            self.assertEqual(result, 0)
            self.assertEqual(report["summary"]["errors"], 0)

        with self.assertRaises(TypeError):
            validate_export_bundle(fixture_bundle, "missing-profile", ROOT)  # type: ignore[call-arg]

        root = self.copy_cli_root("explicit-profile-required")
        bundle_path = root / "bundle.json"
        bundle_path.write_bytes(canonicalize(fixture_bundle) + b"\n")
        report_path = root / "report"
        with redirect_stdout(io.StringIO()):
            result = assurance_main(
                [
                    "--root",
                    str(root),
                    "--report-dir",
                    str(report_path),
                    "--export-mode",
                    TEST_FIXTURE_MODE,
                    "--export-bundle",
                    "bundle.json",
                ]
            )
        self.assertEqual(result, 1)
        report = load_json(report_path / "assurance-schema-report.json")
        self.assertIn(
            "export-profile-required",
            {item["code"] for item in report["findings"]},
        )

        for mutation, expected_code in (
            ("missing", "export-profile-required"),
            ("symlink", "export-profile-required"),
            ("malformed", "export-profile-parse"),
            ("schema", "export-profile-schema"),
            ("digest", "export-profile-digest"),
            ("manifest-binding", "export-profile-binding"),
        ):
            with self.subTest(mutation=mutation):
                root = self.copy_cli_root(f"profile-{mutation}")
                profile_path = root / "profiles/public-evidence-export.v0.1.json"
                if mutation == "missing":
                    profile_path.unlink()
                elif mutation == "symlink":
                    target = profile_path.with_name("reviewed-profile.json")
                    profile_path.rename(target)
                    profile_path.symlink_to(target.name)
                elif mutation == "malformed":
                    profile_path.write_bytes(b"{")
                elif mutation == "schema":
                    value = load_json(profile_path)
                    value["unknown"] = "synthetic"
                    profile_path.write_bytes(canonicalize(value) + b"\n")
                elif mutation == "digest":
                    value = load_json(profile_path)
                    value["profile_digest"] = "sha256:" + "0" * 64
                    profile_path.write_bytes(canonicalize(value) + b"\n")
                else:
                    manifest_path = root / MANIFEST_PATH
                    manifest = load_json(manifest_path)
                    manifest["expected_export_profile_digest"] = "sha256:" + "0" * 64
                    manifest["implementation_digest"] = implementation_digest(manifest)
                    manifest_path.write_bytes(canonicalize(manifest) + b"\n")
                result, report = self.run_assurance_cli(root, fixture_bundle)
                self.assertEqual(result, 1)
                codes = {item["code"] for item in report["findings"]}
                self.assertIn(expected_code, codes)

        root = self.copy_cli_root("no-bundle-no-profile")
        (root / "profiles/public-evidence-export.v0.1.json").unlink()
        report = root / "report"
        with redirect_stdout(io.StringIO()):
            result = assurance_main(["--root", str(root), "--report-dir", str(report)])
        self.assertEqual(result, 0)
        self.assertEqual(
            load_json(report / "assurance-schema-report.json")["summary"]["errors"],
            0,
        )

    def test_all_recomputable_public_digest_bindings_are_enforced(self) -> None:
        fixture = export_fixture_candidate(
            load_json(INPUT_ROOT / "safe-pass.json"), self.profile, ROOT
        )
        candidate = export_candidate(
            real_candidate(load_json(INPUT_ROOT / "safe-pass.json")),
            self.profile,
            ROOT,
        )
        mutations = (
            ("subject binding", ("digest_bindings", "subject_artifact_digest")),
            ("Evidence subject", ("evidence_record", "subject", "digest")),
            ("output binding", ("digest_bindings", "evidence_output_digest")),
            ("Evidence output", ("evidence_record", "output_digest")),
            (
                "Protocol source",
                ("digest_bindings", "protocol_source_revision_digest"),
            ),
            (
                "State Machine",
                ("digest_bindings", "protocol_state_machine_digest"),
            ),
            (
                "message registry",
                ("digest_bindings", "protocol_message_registry_digest"),
            ),
            (
                "conformance suite",
                ("digest_bindings", "protocol_conformance_suite_digest"),
            ),
        )
        for bundle, mode in (
            (fixture, TEST_FIXTURE_MODE),
            (candidate, EXPORT_CANDIDATE_MODE),
        ):
            validate_public_bundle(bundle, ROOT, self.profile, mode=mode)
            self.assertEqual(
                validate_export_bundle(
                    bundle, "valid-binding", ROOT, profile=self.profile, mode=mode
                ),
                [],
            )
            for name, fields in mutations:
                mutated = copy.deepcopy(bundle)
                target = mutated
                for field in fields[:-1]:
                    target = target[field]
                target[fields[-1]] = "sha256:" + "0" * 64
                mutated["bundle_digest"] = bundle_digest(mutated)
                with self.subTest(mode=mode, mutation=name):
                    self.assertBothBundleValidatorsReject(
                        mutated, mode=mode, semantic_code="digest-binding"
                    )

    def test_candidate_ids_are_opaque_and_all_public_strings_are_scanned(self) -> None:
        valid = real_candidate(load_json(INPUT_ROOT / "safe-pass.json"))
        bundle = export_candidate(valid, self.profile, ROOT)
        self.assertEqual(
            bundle["export_candidate_id"],
            "PM-EXPORT-CANDIDATE-8D7D6658D2E84E568E39520A852A6D88",
        )

        for identifier in (
            "PM-EXPORT-CANDIDATE-CUSTOMER-ACME",
            "PM-EXPORT-CANDIDATE-TENANT-SYNTHETIC",
            "PM-EXPORT-CANDIDATE-ACCOUNT-SYNTHETIC",
            "PM-EXPORT-CANDIDATE-ORGANIZATION-SYNTHETIC",
        ):
            candidate = real_candidate(load_json(INPUT_ROOT / "safe-pass.json"))
            candidate["export_candidate_id"] = identifier
            bind_reviews(candidate)
            with self.subTest(identifier=identifier):
                with self.assertRaises(ExportError) as caught:
                    export_candidate(candidate, self.profile, ROOT)
                self.assertEqual(caught.exception.code, "candidate-id")
                self.assertNotIn(identifier, str(caught.exception))

        fixture = load_json(INPUT_ROOT / "safe-pass.json")
        fixture_bundle = export_fixture_candidate(fixture, self.profile, ROOT)
        self.assertEqual(
            fixture_bundle["export_candidate_id"], fixture["export_candidate_id"]
        )

        wrong_mode = real_candidate(load_json(INPUT_ROOT / "safe-pass.json"))
        wrong_mode["export_candidate_id"] = fixture["export_candidate_id"]
        bind_reviews(wrong_mode)
        with self.assertRaises(ExportError) as caught:
            export_candidate(wrong_mode, self.profile, ROOT)
        self.assertEqual(caught.exception.code, "candidate-id")

        findings = scan_public_strings(
            {"future_candidate_controlled_field": "synthetic@example.invalid"}
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].category, "customer-or-personal-identifier")

        exposed = copy.deepcopy(bundle)
        exposed["evidence_record"]["summary"] = "synthetic@example.invalid"
        exposed["bundle_digest"] = bundle_digest(exposed)
        self.assertBothBundleValidatorsReject(exposed, mode=EXPORT_CANDIDATE_MODE)

    def test_checks_executed_are_exact_and_truthful_for_the_context(self) -> None:
        fixture_output, staged_fixture = self.export_file("safe-pass.json")
        self.assertTrue(fixture_output.is_file())
        self.assertEqual(
            staged_fixture["sanitization_report"]["input_interface"],
            STAGED_FILE_INTERFACE,
        )
        self.assertEqual(
            staged_fixture["sanitization_report"]["checks_executed"],
            expected_sanitization_checks(
                self.profile, TEST_FIXTURE_MODE, STAGED_FILE_INTERFACE
            ),
        )

        programmatic_fixture = export_fixture_candidate(
            load_json(INPUT_ROOT / "safe-pass.json"), self.profile, ROOT
        )
        self.assertEqual(
            programmatic_fixture["sanitization_report"]["input_interface"],
            PROGRAMMATIC_INTERFACE,
        )
        self.assertNotIn(
            "path-boundary",
            programmatic_fixture["sanitization_report"]["checks_executed"],
        )

        real = real_candidate(load_json(INPUT_ROOT / "safe-pass.json"))
        staging = self.temp_root / "candidate-staging"
        staging.mkdir()
        (staging / "candidate.json").write_bytes(canonicalize(real) + b"\n")
        _path, staged_candidate = run_export(
            root=ROOT,
            staging_root=staging.relative_to(ROOT),
            input_name=Path("candidate.json"),
            profile_name=Path("profiles/public-evidence-export.v0.1.json"),
            output_dir=self.temp_root.relative_to(ROOT) / "candidate-output",
            mode=EXPORT_CANDIDATE_MODE,
        )
        self.assertEqual(
            staged_candidate["sanitization_report"]["checks_executed"],
            expected_sanitization_checks(
                self.profile, EXPORT_CANDIDATE_MODE, STAGED_FILE_INTERFACE
            ),
        )

        mutations: list[tuple[str, dict, str, str | None]] = []
        unknown = copy.deepcopy(staged_fixture)
        unknown["sanitization_report"]["checks_executed"].append("unknown-check")
        mutations.append(("unknown", unknown, TEST_FIXTURE_MODE, None))
        missing = copy.deepcopy(staged_fixture)
        missing["sanitization_report"]["checks_executed"].remove("digest-bindings")
        mutations.append(("missing", missing, TEST_FIXTURE_MODE, "sanitization-checks"))
        duplicate = copy.deepcopy(staged_fixture)
        duplicate["sanitization_report"]["checks_executed"].append(
            duplicate["sanitization_report"]["checks_executed"][0]
        )
        mutations.append(("duplicate", duplicate, TEST_FIXTURE_MODE, None))
        candidate_fixture_check = copy.deepcopy(staged_candidate)
        candidate_fixture_check["sanitization_report"]["checks_executed"].append(
            "fixture-entry-binding"
        )
        candidate_fixture_check["sanitization_report"]["checks_executed"].sort()
        mutations.append(
            (
                "candidate fixture check",
                candidate_fixture_check,
                EXPORT_CANDIDATE_MODE,
                "sanitization-checks",
            )
        )
        fixture_missing = copy.deepcopy(staged_fixture)
        fixture_missing["sanitization_report"]["checks_executed"].remove(
            "fixture-entry-binding"
        )
        mutations.append(
            (
                "fixture missing",
                fixture_missing,
                TEST_FIXTURE_MODE,
                "sanitization-checks",
            )
        )
        reordered = copy.deepcopy(staged_fixture)
        reordered["sanitization_report"]["checks_executed"].reverse()
        mutations.append(
            ("reordered", reordered, TEST_FIXTURE_MODE, "sanitization-checks")
        )
        for name, mutated, mode, code in mutations:
            mutated["bundle_digest"] = bundle_digest(mutated)
            with self.subTest(mutation=name):
                self.assertBothBundleValidatorsReject(
                    mutated, mode=mode, semantic_code=code
                )

    def test_review_subject_covers_every_reviewable_candidate_field(self) -> None:
        base = real_candidate(load_json(INPUT_ROOT / "safe-pass.json"))

        def update_source(candidate: dict) -> None:
            candidate["source_binding"]["source_evidence_record_digest"] = (
                source_evidence_digest(candidate["evidence_record"])
            )

        mutations: list[tuple[str, object]] = []

        def add(name: str, mutator: object) -> None:
            mutations.append((name, mutator))

        add(
            "summary",
            lambda c: c["evidence_record"].__setitem__(
                "summary", "Changed reviewed summary."
            ),
        )
        add(
            "configuration",
            lambda c: c["evidence_record"]["configuration"].__setitem__(
                "case_count", 4
            ),
        )
        add(
            "status",
            lambda c: (
                c["evidence_record"].__setitem__("status", "fail"),
                c["source_binding"].__setitem__("original_status", "fail"),
            ),
        )
        add(
            "source revision",
            lambda c: c["source_binding"].__setitem__(
                "private_source_revision_digest", "sha256:" + "1" * 64
            ),
        )
        add(
            "source set",
            lambda c: c["source_binding"].__setitem__(
                "source_evidence_set_digest", "sha256:" + "2" * 64
            ),
        )
        add(
            "subject artifact",
            lambda c: (
                c["evidence_record"]["subject"].__setitem__(
                    "digest", "sha256:" + "3" * 64
                ),
                c["artifact_binding"].__setitem__(
                    "subject_artifact_digest", "sha256:" + "3" * 64
                ),
            ),
        )
        add(
            "state machine",
            lambda c: c["protocol_binding"].__setitem__(
                "state_machine_digest", "sha256:" + "4" * 64
            ),
        )
        add(
            "message registry",
            lambda c: c["protocol_binding"].__setitem__(
                "message_registry_digest", "sha256:" + "5" * 64
            ),
        )
        add(
            "conformance suite",
            lambda c: c["conformance_suite_binding"].__setitem__(
                "digest", "sha256:" + "6" * 64
            ),
        )
        add(
            "sensitivity",
            lambda c: c["sensitivity_markers"].__setitem__(
                "contains_customer_or_personal_data", True
            ),
        )
        add(
            "sanitization time",
            lambda c: c["sanitization_event"].__setitem__(
                "recorded_at", "2026-07-21T01:03:00Z"
            ),
        )
        add(
            "sanitization review",
            lambda c: c["sanitization_event"].__setitem__(
                "review_digest", "sha256:" + "7" * 64
            ),
        )
        add(
            "omission added",
            lambda c: c["requested_omissions"].append(
                {
                    "path": "$.evidence_record.public_artifacts",
                    "rule_id": "OMIT-PUBLIC-ARTIFACTS",
                    "human_review_digest": "sha256:" + "8" * 64,
                }
            ),
        )
        add(
            "profile digest",
            lambda c: c["export_profile"].__setitem__("digest", "sha256:" + "9" * 64),
        )
        add(
            "candidate id",
            lambda c: c.__setitem__(
                "export_candidate_id", "PM-EXPORT-CANDIDATE-CHANGED"
            ),
        )

        lifecycle = copy.deepcopy(base)
        lifecycle["evidence_record"]["lifecycle"] = "collected"
        lifecycle["evidence_record"]["lifecycle_history"] = lifecycle[
            "evidence_record"
        ]["lifecycle_history"][:1]
        lifecycle["source_binding"]["original_lifecycle"] = "collected"
        update_source(lifecycle)
        mutations.append(("lifecycle", lambda _candidate: None))

        omission_base = real_candidate(load_json(INPUT_ROOT / "approved-omission.json"))
        omission_removed = copy.deepcopy(omission_base)
        omission_removed["requested_omissions"] = []
        omission_changed = copy.deepcopy(omission_base)
        omission_changed["requested_omissions"][0]["rule_id"] = "OTHER-RULE"

        for name, mutator in mutations:
            candidate = lifecycle if name == "lifecycle" else copy.deepcopy(base)
            if callable(mutator):
                mutator(candidate)
            if name in {"summary", "configuration", "status", "subject artifact"}:
                update_source(candidate)
            with self.subTest(field=name):
                self.assertNotEqual(
                    candidate["review_subject_digest"], review_subject_digest(candidate)
                )
                with self.assertRaises(ExportError):
                    export_candidate(candidate, self.profile, ROOT)

        for name, candidate in (
            ("omission removed", omission_removed),
            ("omission rule", omission_changed),
        ):
            with self.subTest(field=name):
                self.assertNotEqual(
                    candidate["review_subject_digest"], review_subject_digest(candidate)
                )
                with self.assertRaises(ExportError):
                    export_candidate(candidate, self.profile, ROOT)

    def test_review_provenance_is_complete_and_value_safe(self) -> None:
        candidate = real_candidate(load_json(INPUT_ROOT / "safe-pass.json"))
        bundle = export_candidate(candidate, self.profile, ROOT)
        self.assertEqual(
            {item["scope"] for item in bundle["review_provenance"]},
            {"privacy", "security-boundary", "ip", "vulnerability"},
        )
        for item in bundle["review_provenance"]:
            self.assertEqual(
                item["reviewed_subject_digest"], bundle["review_subject_digest"]
            )
            self.assertEqual(item["reviewer_role"], "authorized-human")
            self.assertEqual(
                set(item),
                {
                    "scope",
                    "status",
                    "reviewer_role",
                    "review_digest",
                    "reviewed_subject_digest",
                },
            )

    def test_implementation_manifest_covers_all_behavior_inputs(self) -> None:
        manifest = load_json(ROOT / MANIFEST_PATH)
        verify_implementation_manifest(manifest, ROOT, self.profile["profile_digest"])
        first = build_implementation_manifest(ROOT, self.profile["profile_digest"])
        second = build_implementation_manifest(ROOT, self.profile["profile_digest"])
        self.assertEqual(
            canonical_manifest_bytes(first), canonical_manifest_bytes(second)
        )
        self.assertEqual(manifest_file_digest(manifest), manifest_file_digest(first))

        required = {
            "scripts/export_public_evidence.py",
            "scripts/canonical_json.py",
            "scripts/validate_assurance.py",
            "schema/evidence-export-candidate.v0.1.schema.json",
            "schema/evidence-export-configuration.v0.1.schema.json",
            "schema/public-evidence-export.v0.1.schema.json",
            "schema/evidence-item.schema.json",
            "requirements-build.txt",
            "requirements-dev.txt",
            "tests/fixtures/export/fixture-catalog.v0.1.json",
        }
        listed = {
            item["path"]
            for field in (
                "source_files",
                "schema_files",
                "dependency_lock_files",
                "test_trust_artifacts",
            )
            for item in manifest[field]
        }
        listed.add(manifest["evidence_schema_reference"]["path"])
        self.assertTrue(required.issubset(listed))

        for changed_path in sorted(required):
            with self.subTest(changed=changed_path):
                changed = copy.deepcopy(manifest)
                entries = [
                    item
                    for field in (
                        "source_files",
                        "schema_files",
                        "dependency_lock_files",
                        "test_trust_artifacts",
                    )
                    for item in changed[field]
                ] + [changed["evidence_schema_reference"]]
                entry = next(item for item in entries if item["path"] == changed_path)
                entry["digest"] = "sha256:" + "f" * 64
                changed["implementation_digest"] = implementation_digest(changed)
                self.assertNotEqual(
                    changed["implementation_digest"], manifest["implementation_digest"]
                )
                with self.assertRaises(ImplementationManifestError):
                    verify_implementation_manifest(
                        changed, ROOT, self.profile["profile_digest"]
                    )

    def test_manifest_tracks_all_runtime_loaded_schemas_and_fixture_trust(self) -> None:
        root = self.copy_manifest_inputs()
        baseline = build_implementation_manifest(root, self.profile["profile_digest"])
        for relative in (*SCHEMA_PATHS, EVIDENCE_SCHEMA_PATH, *TEST_TRUST_PATHS):
            with self.subTest(relative=relative):
                path = root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                changed = build_implementation_manifest(
                    root, self.profile["profile_digest"]
                )
                self.assertNotEqual(
                    baseline["implementation_digest"],
                    changed["implementation_digest"],
                )
                path.write_bytes(original)

        unrelated = root / "schema/claim.schema.json"
        unrelated.parent.mkdir(parents=True, exist_ok=True)
        unrelated.write_bytes((ROOT / "schema/claim.schema.json").read_bytes())
        before = build_implementation_manifest(root, self.profile["profile_digest"])
        unrelated.write_bytes(unrelated.read_bytes() + b"\n")
        after = build_implementation_manifest(root, self.profile["profile_digest"])
        self.assertEqual(
            before["implementation_digest"], after["implementation_digest"]
        )

        candidate = load_json(INPUT_ROOT / "safe-pass.json")
        with mock.patch(
            "scripts.validate_assurance.load_schemas",
            side_effect=AssertionError("non-Evidence Schemas must not be loaded"),
        ):
            bundle = export_fixture_candidate(candidate, self.profile, ROOT)
        self.assertEqual(bundle["evidence_record"]["record_type"], "evidence")

    def test_manifest_enforces_runtime_requirements_and_labels_tested_target(
        self,
    ) -> None:
        manifest = load_json(ROOT / MANIFEST_PATH)
        self.assertEqual(manifest["runtime_requirements"], RUNTIME_REQUIREMENTS)
        self.assertEqual(manifest["tested_target"], TESTED_TARGET)
        self.assertFalse(manifest["tested_target"]["execution_provenance"])

        for field, value in (
            ("python_implementation", "PyPy"),
            ("python_major_minor", "3.11"),
            ("canonicalization_package_version", "0.1.3"),
        ):
            facts = dict(RUNTIME_REQUIREMENTS)
            facts[field] = value
            with (
                self.subTest(field=field),
                self.assertRaises(ImplementationManifestError),
            ):
                verify_implementation_manifest(
                    manifest,
                    ROOT,
                    self.profile["profile_digest"],
                    runtime_facts=facts,
                )

    def test_implementation_manifest_rejects_profile_paths_and_stale_bundle(
        self,
    ) -> None:
        manifest = load_json(ROOT / MANIFEST_PATH)
        with self.assertRaises(ImplementationManifestError):
            verify_implementation_manifest(manifest, ROOT, "sha256:" + "0" * 64)

        invalid_manifests = []
        missing = copy.deepcopy(manifest)
        missing["source_files"].pop()
        invalid_manifests.append(missing)
        duplicate = copy.deepcopy(manifest)
        duplicate["source_files"].append(copy.deepcopy(duplicate["source_files"][0]))
        invalid_manifests.append(duplicate)
        missing_trust = copy.deepcopy(manifest)
        missing_trust["test_trust_artifacts"].clear()
        invalid_manifests.append(missing_trust)
        escape = copy.deepcopy(manifest)
        escape["source_files"][0]["path"] = "../outside.py"
        invalid_manifests.append(escape)
        for value in invalid_manifests:
            value["implementation_digest"] = implementation_digest(value)
            with self.assertRaises(ImplementationManifestError):
                verify_implementation_manifest(
                    value, ROOT, self.profile["profile_digest"]
                )

        stale_trust = copy.deepcopy(manifest)
        stale_trust["test_trust_artifacts"][0]["digest"] = "sha256:" + "e" * 64
        stale_trust["implementation_digest"] = implementation_digest(stale_trust)
        with self.assertRaises(ImplementationManifestError):
            verify_implementation_manifest(
                stale_trust, ROOT, self.profile["profile_digest"]
            )

        bundle = export_candidate(
            real_candidate(load_json(INPUT_ROOT / "safe-pass.json")),
            self.profile,
            ROOT,
        )
        bundle["exporter"]["implementation_digest"] = "sha256:" + "f" * 64
        bundle["digest_bindings"]["exporter_implementation_digest"] = (
            "sha256:" + "f" * 64
        )
        bundle["bundle_digest"] = bundle_digest(bundle)
        with self.assertRaises(ExportError):
            validate_public_bundle(bundle, ROOT, self.profile)

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
