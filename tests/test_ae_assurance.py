from __future__ import annotations

import copy
import io
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts.ae_assurance_common import (
    AssuranceIntegrationError,
    build_schema_registry,
    read_strict_json,
    resolve_regular_file,
    resolve_new_directory,
    validate_relative_path,
    validate_schema_instance,
)
from scripts.ae_assurance_implementation import (
    MANIFEST_PATH,
    adapter_source_digest,
    build_manifest,
    verify_manifest,
    renderer_source_digest,
)
from scripts.ae_assurance_output_set import (
    JSON_NAME,
    MARKDOWN_NAME,
    OUTPUT_SET_NAME,
    build_output_set,
    validate_output_directory,
)
from scripts.ae_assurance_policy import (
    ASSURANCE_CONTENT_DOMAIN,
    ASSURANCE_PACKAGE_DOMAIN,
    EVIDENCE_RECORD_DOMAIN,
    FIXTURE_CATALOG_PATH,
    JSON_REPORT_DOMAIN,
    MARKDOWN_REPORT_DOMAIN,
    OUTPUT_SET_DOMAIN,
    PIN_DOMAIN,
    PRODUCER_PACKAGE_DOMAIN,
    PROFILE_DOMAIN,
    TOOL_INVENTORY_DOMAIN,
    CANDIDATE_TOOL_IDENTITIES,
    CANDIDATE_TOOL_LIMITATION,
    FIXTURE_TOOL_BINDINGS,
    artifact_digest,
    load_authority,
    load_schemas,
    tool_binding_digest,
)
from scripts.ae_framework_adapter import (
    _native_manifest,
    _run_bounded_process,
    _run_native,
    build_assurance_package,
    derive_native_judgment,
    native_generator_lineage,
    validate_producer_package,
)
from scripts.ae_framework_manifest import (
    SOURCE_COMMIT,
    build_source_manifest,
    verify_source_manifest,
)
from scripts.canonical_json import (
    CanonicalJSONError,
    canonicalize,
    domain_digest,
    file_digest,
    strict_loads,
)
from scripts.generate_ae_assurance_fixtures import check_fixtures
from scripts.render_ae_assurance_report import render_markdown
from scripts.run_ae_assurance import build_parser, run_one
from scripts.run_ae_assurance import main as runner_main
from scripts.validate_ae_assurance import (
    validate_judgment_approval_boundary,
    validate_package,
    validate_repository,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests/fixtures/ae-framework"


class AeAssuranceAuthorityTests(unittest.TestCase):
    def test_exact_authority_profile_inventory_and_source_closure(self) -> None:
        pin, inventory, profile = load_authority(ROOT)
        self.assertEqual(pin["commit"], SOURCE_COMMIT)
        self.assertEqual(pin["repository"], "itdojp/ae-framework")
        self.assertEqual(pin["package"], {"name": "ae-framework", "version": "1.0.0"})
        self.assertEqual(pin["entrypoint"]["type"], "vendored-reviewed-subset")
        self.assertEqual(len(inventory["tools"]), 5)
        self.assertEqual(len(profile["producer_status_mapping"]), 30)
        self.assertEqual(
            profile["tool_binding_contract"]["native_generator_lineage"],
            "implementation-digest-derived",
        )
        self.assertFalse(
            profile["tool_binding_contract"]["digest_inequality_proves_independence"]
        )
        for mapping in profile["producer_status_mapping"]:
            self.assertEqual(
                mapping["raw_producer_status"], mapping["normalized_evidence_status"]
            )
        source = build_source_manifest(ROOT)
        verify_source_manifest(source, ROOT)
        self.assertEqual(len(source["files"]), 9)

    def test_authority_digests_are_detached_and_current(self) -> None:
        pin, inventory, profile = load_authority(ROOT)
        self.assertEqual(
            pin["pin_digest"], artifact_digest(PIN_DOMAIN, pin, "pin_digest")
        )
        self.assertEqual(
            inventory["inventory_digest"],
            artifact_digest(TOOL_INVENTORY_DOMAIN, inventory, "inventory_digest"),
        )
        self.assertEqual(
            profile["profile_digest"],
            artifact_digest(PROFILE_DOMAIN, profile, "profile_digest"),
        )

    def test_all_new_schemas_self_validate_with_complete_registry(self) -> None:
        schemas = load_schemas(ROOT)
        registry = build_schema_registry(schemas.values())
        self.assertGreaterEqual(len(schemas), 10)
        for value in schemas.values():
            validate_schema_instance(
                {},
                {"$schema": "https://json-schema.org/draft/2020-12/schema"},
                registry=registry,
            )

    def test_pin_rejects_wrong_commit_repository_version_and_entrypoint(self) -> None:
        schemas = load_schemas(ROOT)
        pin, _, _ = load_authority(ROOT)
        for path, value in (
            (("commit",), "0" * 40),
            (("repository",), "example/other"),
            (("package", "version"), "1.0.1"),
            (("entrypoint", "path"), "other.mjs"),
            (("license",), "MIT"),
        ):
            mutated = copy.deepcopy(pin)
            target = mutated
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            with self.assertRaises(AssuranceIntegrationError):
                validate_schema_instance(
                    mutated,
                    schemas["pin"],
                    registry=build_schema_registry(schemas.values()),
                )

    def test_stale_source_and_runner_manifests_are_rejected(self) -> None:
        source = build_source_manifest(ROOT)
        source["source_tree_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(AssuranceIntegrationError):
            verify_source_manifest(source, ROOT)
        manifest = build_manifest(ROOT)
        manifest["implementation_digest"] = "sha256:" + "0" * 64
        with self.assertRaises(AssuranceIntegrationError):
            verify_manifest(manifest, ROOT)

    def test_repository_and_implementation_manifest_validate(self) -> None:
        validate_repository(ROOT)
        manifest = read_strict_json(ROOT / MANIFEST_PATH)
        verify_manifest(manifest, ROOT)
        self.assertEqual(manifest["adapter_source_digest"], adapter_source_digest(ROOT))

    def test_workflow_is_read_only_pinned_and_does_not_upload_reports(self) -> None:
        workflow = (ROOT / ".github/workflows/assurance-schema.yml").read_text()
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("upload-artifact", workflow)
        self.assertNotIn("scripts/export_public_evidence.py", workflow)
        self.assertNotIn("private-match-product", workflow)
        self.assertNotIn("git clone", workflow)
        for action in re.findall(r"uses:\s+[^@\s]+@([^\s]+)", workflow):
            self.assertRegex(action, r"^[0-9a-f]{40}$")

    def test_runner_does_not_call_public_exporter(self) -> None:
        for relative in (
            "scripts/run_ae_assurance.py",
            "scripts/ae_framework_adapter.py",
        ):
            self.assertNotIn(
                "export_public_evidence.py",
                (ROOT / relative).read_text(encoding="utf-8"),
            )


class AeAssuranceFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = read_strict_json(ROOT / FIXTURE_CATALOG_PATH)
        cls.inputs = {
            Path(item["input_path"]).stem: read_strict_json(
                FIXTURE_ROOT / item["input_path"]
            )
            for item in cls.catalog["fixtures"]
        }
        cls.packages = {
            Path(item["expected_json_path"]).parent.name: read_strict_json(
                FIXTURE_ROOT / item["expected_json_path"], max_bytes=2_097_152
            )
            for item in cls.catalog["fixtures"]
        }

    def test_every_fixture_runs_twice_byte_identically(self) -> None:
        check_fixtures(ROOT)

    def test_six_statuses_are_preserved_across_catalog(self) -> None:
        observed = set()
        for package in self.packages.values():
            validate_package(ROOT, package)
            observed.update(record["status"] for record in package["evidence_records"])
            self.assertEqual(
                [record["status"] for record in package["evidence_records"]],
                [record["status"] for record in package["evidence_record_refs"]],
            )
        self.assertEqual(
            observed, {"pass", "fail", "skip", "unsupported", "timeout", "tool-error"}
        )

    def test_success_and_optional_absence_are_satisfied_without_approval(self) -> None:
        for name in ("success", "optional-unavailable"):
            package = self.packages[name]
            self.assertEqual(
                package["automated_judgment"]["state"],
                "satisfied-with-warnings",
            )
            self.assertEqual(
                package["human_approval"]["state"], "not-applicable-test-only"
            )
            self.assertFalse(package["human_approval"]["reviewer_identity_verified"])
            optional = package["optional_gate_results"]
            self.assertTrue(
                any(item["status"] in {"skip", "unsupported"} for item in optional)
            )
            self.assertTrue(all(item["gate_state"] != "blocked" for item in optional))

    def test_required_nonpass_fixtures_block_without_status_conversion(self) -> None:
        cases = {
            "required-fail": "fail",
            "required-missing-tool": "unsupported",
            "required-timeout": "timeout",
            "required-tool-error": "tool-error",
        }
        for name, status in cases.items():
            with self.subTest(name=name):
                package = self.packages[name]
                self.assertEqual(package["automated_judgment"]["state"], "blocked")
                self.assertTrue(
                    any(
                        item["status"] == status and item["gate_state"] == "blocked"
                        for item in package["required_gate_results"]
                    )
                )
                self.assertGreaterEqual(package["status_counts"][status], 1)

    def test_every_external_tool_and_version_remains_visible(self) -> None:
        expected = [
            (binding["identity"], binding["version"])
            for binding in self.inputs["success"]["tool_bindings"]
        ]
        for package in self.packages.values():
            self.assertEqual(
                [
                    (item["tool_id"], item["tool_version"])
                    for item in package["external_tool_inventory"]
                ],
                expected,
            )
            self.assertNotIn(
                "same-generator-lineage",
                package["native_ae_judgment"]["warning_codes"],
            )
            required = {
                record["configuration"]["tool_role_id"]: record["execution"]["required"]
                for record in package["evidence_records"]
            }
            self.assertTrue(required["PMAE-CI-PIPELINE-V0-1"])
            self.assertTrue(required["PMAE-CONFORMANCE-RUNNER-V0-1"])
            self.assertFalse(required["PMAE-FORMAL-TOOL-V0-1"])

    def test_markdown_is_generated_from_json_and_states_boundaries(self) -> None:
        package = self.packages["success"]
        markdown = render_markdown(package)
        self.assertEqual(
            markdown,
            (FIXTURE_ROOT / "expected/success" / MARKDOWN_NAME).read_text(),
        )
        for status in ("pass", "fail", "skip", "unsupported", "timeout", "tool-error"):
            self.assertIn(f"| {status} |", markdown)
        self.assertIn("not a security proof oracle", markdown)
        self.assertIn("not a certification authority", markdown)
        self.assertIn("not human approval or publication approval", markdown)
        self.assertIn("## Native ae-framework judgment", markdown)
        self.assertIn("missing-spec-derived-evidence", markdown)
        self.assertIn("visible-nonblocking", markdown)

    def test_native_warning_is_explicitly_policy_evaluated(self) -> None:
        package = self.packages["success"]
        self.assertEqual(package["producer_gate_judgment"]["state"], "satisfied")
        self.assertEqual(package["native_ae_judgment"]["state"], "warning")
        self.assertEqual(
            package["automated_judgment"]["state"], "satisfied-with-warnings"
        )
        self.assertEqual(
            package["native_ae_judgment"]["warning_codes"],
            ["missing-spec-derived-evidence"],
        )

    def test_report_semantic_and_package_digests_validate(self) -> None:
        for package in self.packages.values():
            validate_package(ROOT, package)
            self.assertEqual(
                package["package_digest"],
                artifact_digest(ASSURANCE_PACKAGE_DOMAIN, package, "package_digest"),
            )

    def test_expected_packages_contain_no_local_path_or_live_publication_state(
        self,
    ) -> None:
        for package in self.packages.values():
            serialized = canonicalize(package).decode("utf-8")
            self.assertNotIn(str(ROOT), serialized)
            self.assertNotIn("/home/", serialized)
            self.assertFalse(package["lifecycle_boundary"]["public_export_eligible"])
            self.assertFalse(package["lifecycle_boundary"]["public_export_invoked"])
            self.assertNotEqual(package["human_approval"]["state"], "approved")


class AeAssuranceNegativeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pin, self.inventory, self.profile = load_authority(ROOT)
        self.success_path = FIXTURE_ROOT / "input/success.json"
        self.success = read_strict_json(self.success_path)
        self.success_expected = read_strict_json(
            FIXTURE_ROOT / "expected/success" / JSON_NAME, max_bytes=2_097_152
        )

    def _producer(self, mutate) -> dict:
        value = copy.deepcopy(self.success)
        mutate(value)
        value["package_digest"] = artifact_digest(
            PRODUCER_PACKAGE_DOMAIN, value, "package_digest"
        )
        return value

    def _private_candidate(self) -> dict:
        value = copy.deepcopy(self.success)
        value.update(
            {
                "package_id": "PMAE-PRODUCER-PRIVATE-CANDIDATE-V0-1",
                "mode": "private-candidate",
                "artifact_status": "private-candidate",
                "subject": {
                    "type": "source-revision",
                    "identifier": "private-match-product",
                    "version": "0.1",
                    "digest": value["source_revision_digest"],
                },
                "limitations": [
                    "All identifiers are closed role IDs and digests bind the private candidate source revision.",
                    "The package is retained privately and is not eligible for public export or live approval.",
                ],
            }
        )
        candidate_bindings = []
        for index, role in enumerate(self.inventory["tools"], start=1):
            binding = {
                "tool_role_id": role["tool_id"],
                "producer_type": role["producer_type"],
                "mode": "private-candidate",
                "identity": CANDIDATE_TOOL_IDENTITIES[role["tool_id"]],
                "version": f"0.1.{index}",
                "implementation_digest": "sha256:" + f"{index:x}" * 64,
                "input_contract": role["input_contract"],
                "output_contract": role["output_contract"],
                "limitations": [CANDIDATE_TOOL_LIMITATION],
            }
            binding["binding_digest"] = tool_binding_digest(binding)
            candidate_bindings.append(binding)
        value["tool_bindings"] = candidate_bindings
        bindings_by_role = {
            binding["tool_role_id"]: binding for binding in candidate_bindings
        }
        for record in value["records"]:
            producer_type = record["producer_type"]
            binding = bindings_by_role[record["tool_id"]]
            record["producer_id"] = f"private-match-product-{producer_type}"
            record["tool_identity"] = binding["identity"]
            record["tool_version"] = binding["version"]
            record["tool_implementation_digest"] = binding["implementation_digest"]
            record["test_only"] = False
            record["retention_classification"] = "private-assurance-retained"
            record["summary"] = f"Private candidate {producer_type} status record."
            record["limitations"][1] = (
                "Private candidate metadata only; no raw Product data is represented."
            )
        value["package_digest"] = artifact_digest(
            PRODUCER_PACKAGE_DOMAIN, value, "package_digest"
        )
        return value

    def _rebind_candidate_implementations(
        self, candidate: dict, implementation_digests: dict[str, str]
    ) -> dict:
        bindings_by_role = {}
        for binding in candidate["tool_bindings"]:
            if binding["tool_role_id"] in implementation_digests:
                binding["implementation_digest"] = implementation_digests[
                    binding["tool_role_id"]
                ]
                binding["binding_digest"] = tool_binding_digest(binding)
            bindings_by_role[binding["tool_role_id"]] = binding
        for record in candidate["records"]:
            record["tool_implementation_digest"] = bindings_by_role[record["tool_id"]][
                "implementation_digest"
            ]
        candidate["package_digest"] = artifact_digest(
            PRODUCER_PACKAGE_DOMAIN, candidate, "package_digest"
        )
        return candidate

    def _result(self, mutate, source: dict | None = None) -> dict:
        value = copy.deepcopy(source if source is not None else self.success_expected)
        mutate(value)
        content = copy.deepcopy(value)
        for field in (
            "human_approval",
            "assurance_content_digest",
            "report_digests",
            "package_digest",
        ):
            content.pop(field, None)
        value["assurance_content_digest"] = artifact_digest(
            ASSURANCE_CONTENT_DOMAIN,
            {**content, "assurance_content_digest": "unused"},
            "assurance_content_digest",
        )
        value["human_approval"]["bound_assurance_content_digest"] = value[
            "assurance_content_digest"
        ]
        report = copy.deepcopy(value)
        report.pop("report_digests", None)
        report.pop("package_digest", None)
        value["report_digests"] = {
            "json_model_digest": artifact_digest(
                JSON_REPORT_DOMAIN,
                {**report, "json_model_digest": "unused"},
                "json_model_digest",
            ),
            "markdown_model_digest": artifact_digest(
                MARKDOWN_REPORT_DOMAIN,
                {**report, "markdown_model_digest": "unused"},
                "markdown_model_digest",
            ),
        }
        value["package_digest"] = artifact_digest(
            ASSURANCE_PACKAGE_DOMAIN, value, "package_digest"
        )
        return value

    def test_native_manifest_lineage_uses_implementation_digest_not_role(self) -> None:
        candidate = self._private_candidate()
        shared_digest = "sha256:" + "e" * 64
        self._rebind_candidate_implementations(
            candidate,
            {
                "PMAE-CI-PIPELINE-V0-1": shared_digest,
                "PMAE-CONFORMANCE-RUNNER-V0-1": shared_digest,
            },
        )
        bindings = {
            binding["tool_role_id"]: binding for binding in candidate["tool_bindings"]
        }
        self.assertNotEqual(
            bindings["PMAE-CI-PIPELINE-V0-1"]["identity"],
            bindings["PMAE-CONFORMANCE-RUNNER-V0-1"]["identity"],
        )
        manifest = _native_manifest(candidate)
        self.assertEqual(
            manifest["entries"][0]["generatorLineage"],
            manifest["entries"][1]["generatorLineage"],
        )
        self.assertEqual(
            manifest["entries"][0]["generatorLineage"],
            f"implementation/{shared_digest}",
        )
        for malformed in ({}, {"implementation_digest": "sha256:invalid"}):
            with self.assertRaises(AssuranceIntegrationError):
                native_generator_lineage(malformed)

    def test_result_authority_inventory_and_record_bindings_fail_closed(self) -> None:
        mutations = (
            lambda value: value["integration_profile"].__setitem__(
                "digest", "sha256:" + "0" * 64
            ),
            lambda value: value["ae_framework"].__setitem__("commit", "0" * 40),
            lambda value: value["adapter"].__setitem__(
                "implementation_digest", "sha256:" + "0" * 64
            ),
            lambda value: value["external_tool_inventory"][0].__setitem__(
                "tool_version", "9.9.9"
            ),
            lambda value: value["producer_inventory"][0].__setitem__(
                "producer_version", "9.9.9"
            ),
            lambda value: value["evidence_record_refs"][0].__setitem__(
                "record_digest", "sha256:" + "0" * 64
            ),
            lambda value: value["evidence_records"][0]["tool"].__setitem__(
                "source", "sha256:" + "0" * 64
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(AssuranceIntegrationError):
                    validate_package(ROOT, self._result(mutation))

    def test_unknown_producer_type_and_status_fail_closed(self) -> None:
        for mutate in (
            lambda value: value["records"][0].__setitem__("producer_type", "unknown"),
            lambda value: value["records"][0].__setitem__("status", "success"),
        ):
            with self.assertRaises(AssuranceIntegrationError):
                validate_producer_package(
                    ROOT, self._producer(mutate), self.inventory, self.profile
                )

    def test_missing_required_or_optional_record_remains_an_error(self) -> None:
        for index in (0, 2):
            with self.subTest(index=index):
                package = self._producer(
                    lambda value, index=index: value["records"].pop(index)
                )
                with self.assertRaises(AssuranceIntegrationError):
                    validate_producer_package(
                        ROOT, package, self.inventory, self.profile
                    )

    def test_wrong_tool_version_digest_or_inventory_id_fails(self) -> None:
        mutations = (
            lambda value: value["records"][0].__setitem__("tool_version", "9.9.9"),
            lambda value: value["records"][0].__setitem__(
                "tool_implementation_digest", "sha256:" + "0" * 64
            ),
            lambda value: value["records"][0].__setitem__(
                "tool_id", "PMAE-UNKNOWN-V0-1"
            ),
        )
        for mutation in mutations:
            with self.assertRaises(AssuranceIntegrationError):
                validate_producer_package(
                    ROOT, self._producer(mutation), self.inventory, self.profile
                )

    def test_mode_specific_tool_bindings_fail_closed(self) -> None:
        def rebound(candidate: dict, index: int = 0) -> dict:
            binding = candidate["tool_bindings"][index]
            binding["binding_digest"] = tool_binding_digest(binding)
            candidate["package_digest"] = artifact_digest(
                PRODUCER_PACKAGE_DOMAIN, candidate, "package_digest"
            )
            return candidate

        synthetic_identity = self._private_candidate()
        synthetic_identity["tool_bindings"][0]["identity"] = FIXTURE_TOOL_BINDINGS[
            "PMAE-CI-PIPELINE-V0-1"
        ][0]
        synthetic_identity["records"][0]["tool_identity"] = synthetic_identity[
            "tool_bindings"
        ][0]["identity"]
        synthetic_digest = self._private_candidate()
        synthetic_digest["tool_bindings"][0]["implementation_digest"] = (
            FIXTURE_TOOL_BINDINGS["PMAE-CI-PIPELINE-V0-1"][1]
        )
        synthetic_digest["records"][0]["tool_implementation_digest"] = synthetic_digest[
            "tool_bindings"
        ][0]["implementation_digest"]
        missing = self._private_candidate()
        missing["tool_bindings"].pop()
        extra = self._private_candidate()
        extra["tool_bindings"].append(copy.deepcopy(extra["tool_bindings"][0]))
        duplicate_role = self._private_candidate()
        duplicate_role["tool_bindings"][1]["tool_role_id"] = duplicate_role[
            "tool_bindings"
        ][0]["tool_role_id"]
        duplicate_role["tool_bindings"][1]["binding_digest"] = tool_binding_digest(
            duplicate_role["tool_bindings"][1]
        )
        wrong_type = self._private_candidate()
        wrong_type["tool_bindings"][0]["producer_type"] = "formal-tool"
        unknown_role = self._private_candidate()
        unknown_role["tool_bindings"][0]["tool_role_id"] = "PMAE-UNKNOWN-V0-1"
        fixture_private = copy.deepcopy(self.success)
        fixture_private["tool_bindings"][0]["identity"] = CANDIDATE_TOOL_IDENTITIES[
            "PMAE-CI-PIPELINE-V0-1"
        ]

        candidates = (
            rebound(synthetic_identity),
            rebound(synthetic_digest),
            rebound(missing),
            rebound(extra),
            rebound(duplicate_role, 1),
            rebound(wrong_type),
            rebound(unknown_role),
            rebound(fixture_private),
        )
        for candidate in candidates:
            with self.subTest(candidate=candidate["tool_bindings"][0]):
                with self.assertRaises(AssuranceIntegrationError):
                    validate_producer_package(
                        ROOT, candidate, self.inventory, self.profile
                    )

    def test_record_binding_version_and_digest_mismatch_fail_closed(self) -> None:
        for field, value in (
            ("tool_version", "9.9.9"),
            ("tool_implementation_digest", "sha256:" + "9" * 64),
        ):
            candidate = self._private_candidate()
            candidate["records"][0][field] = value
            candidate["package_digest"] = artifact_digest(
                PRODUCER_PACKAGE_DOMAIN, candidate, "package_digest"
            )
            with (
                self.subTest(field=field),
                self.assertRaises(AssuranceIntegrationError),
            ):
                validate_producer_package(ROOT, candidate, self.inventory, self.profile)

    def test_single_source_revision_contract_fails_closed_and_moves_atomically(
        self,
    ) -> None:
        for count in (1, 2):
            candidate = self._private_candidate()
            for record in candidate["records"][:count]:
                record["source_revision_digest"] = "sha256:" + "9" * 64
            candidate["package_digest"] = artifact_digest(
                PRODUCER_PACKAGE_DOMAIN, candidate, "package_digest"
            )
            with (
                self.subTest(count=count),
                self.assertRaises(AssuranceIntegrationError),
            ):
                validate_producer_package(ROOT, candidate, self.inventory, self.profile)

        mismatched_subject = self._private_candidate()
        mismatched_subject["subject"]["digest"] = "sha256:" + "8" * 64
        mismatched_subject["package_digest"] = artifact_digest(
            PRODUCER_PACKAGE_DOMAIN, mismatched_subject, "package_digest"
        )
        with self.assertRaises(AssuranceIntegrationError):
            validate_producer_package(
                ROOT, mismatched_subject, self.inventory, self.profile
            )

        moved = self._private_candidate()
        moved["source_revision_digest"] = "sha256:" + "7" * 64
        moved["subject"]["digest"] = moved["source_revision_digest"]
        moved["package_digest"] = artifact_digest(
            PRODUCER_PACKAGE_DOMAIN, moved, "package_digest"
        )
        validate_producer_package(ROOT, moved, self.inventory, self.profile)

        def mixed_output(value: dict) -> None:
            record = value["evidence_records"][0]
            record["subject"]["digest"] = "sha256:" + "6" * 64
            value["evidence_record_refs"][0]["record_digest"] = domain_digest(
                EVIDENCE_RECORD_DOMAIN, record
            )

        with self.assertRaises(AssuranceIntegrationError):
            validate_package(ROOT, self._result(mixed_output))

    def test_fixture_status_promotion_with_recomputed_digest_is_rejected(self) -> None:
        pass_limitation = next(
            item["required_limitation"]
            for item in self.inventory["tools"][3]["status_mappings"]
            if item["raw_producer_status"] == "pass"
        )

        def promote(value):
            record = value["records"][3]
            record["status"] = "pass"
            record["product_output_digest"] = "sha256:" + "1" * 64
            record["limitations"] = [
                pass_limitation,
                "Public synthetic fixture only; no private Product execution is represented.",
            ]

        promoted = self._producer(promote)
        validate_producer_package(ROOT, promoted, self.inventory, self.profile)
        catalog_entry = next(
            item
            for item in read_strict_json(ROOT / FIXTURE_CATALOG_PATH)["fixtures"]
            if item["input_path"] == "input/success.json"
        )
        self.assertNotEqual(
            file_digest(canonicalize(promoted) + b"\n"), catalog_entry["input_digest"]
        )
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            input_root = Path(temp)
            (input_root / "success.json").write_bytes(canonicalize(promoted) + b"\n")
            with self.assertRaises(AssuranceIntegrationError):
                run_one(
                    root=ROOT,
                    profile_path="profiles/private-match-ae-assurance.v0.1.json",
                    input_root=input_root,
                    relative_input="success.json",
                    output_root=input_root,
                    relative_output="result",
                    mode="fixture-test",
                )

    def test_duplicate_evidence_id_and_missing_status_limitation_fail(self) -> None:
        duplicate = self._producer(
            lambda value: value["records"][1].__setitem__(
                "evidence_id", value["records"][0]["evidence_id"]
            )
        )
        missing = self._producer(
            lambda value: value["records"][0].__setitem__(
                "limitations", ["different limitation"]
            )
        )
        for package in (duplicate, missing):
            with self.assertRaises(AssuranceIntegrationError):
                validate_producer_package(ROOT, package, self.inventory, self.profile)

    def test_private_fields_secrets_credentials_hosts_and_paths_fail(self) -> None:
        mutations = (
            lambda value: value["records"][0].__setitem__(
                "raw_private_input", "synthetic"
            ),
            lambda value: value["records"][0].__setitem__(
                "summary", "-----BEGIN PRIVATE KEY-----"
            ),
            lambda value: value["records"][0].__setitem__(
                "summary", "AKIAABCDEFGHIJKLMNOP"
            ),
            lambda value: value["records"][0].__setitem__(
                "summary", "service.private.internal"
            ),
            lambda value: value["records"][0].__setitem__(
                "summary", "/home/example/private.json"
            ),
            lambda value: value["records"][0].__setitem__(
                "summary", "customer_identifier=CUST-123"
            ),
            lambda value: value["records"][0].__setitem__(
                "summary", "credential=synthetic-secret"
            ),
            lambda value: value["records"][0].__setitem__(
                "summary", "person@example.com"
            ),
            lambda value: value["records"][0].__setitem__("summary", "+819012345678"),
            lambda value: value["records"][0].__setitem__(
                "summary", "tenant_id=TENANT-123"
            ),
            lambda value: value["records"][0].__setitem__(
                "summary", "account_identifier=ACCOUNT-123"
            ),
            lambda value: value["records"][0].__setitem__(
                "summary", "github.com/private-org/private-repository"
            ),
            lambda value: value["records"][0].__setitem__(
                "producer_id", "customer-id=CUST-123"
            ),
            lambda value: value["records"][0].__setitem__(
                "summary", "ae-framework certifies the Product"
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(AssuranceIntegrationError):
                    validate_producer_package(
                        ROOT, self._producer(mutation), self.inventory, self.profile
                    )

    def test_strict_json_rejects_duplicate_invalid_utf8_and_oversize(self) -> None:
        with self.assertRaises(CanonicalJSONError):
            strict_loads(b'{"a":1,"a":2}', max_bytes=100)
        with self.assertRaises(CanonicalJSONError):
            strict_loads(b'"\xff"', max_bytes=100)
        with self.assertRaises(CanonicalJSONError):
            strict_loads(b'"' + b"a" * 101 + b'"', max_bytes=100)

    def test_path_boundary_rejects_absolute_windows_backslash_dot_and_parent(
        self,
    ) -> None:
        for value in (
            "/absolute.json",
            "C:/absolute.json",
            "a\\b.json",
            "./a.json",
            "a/../b.json",
            "a//b.json",
        ):
            with (
                self.subTest(value=value),
                self.assertRaises(AssuranceIntegrationError),
            ):
                validate_relative_path(value)

    def test_file_boundary_rejects_intermediate_final_symlink_directory_and_missing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            base = Path(temp)
            (base / "inside").mkdir()
            (base / "inside/file.json").write_text("{}")
            (base / "intermediate").symlink_to(
                base / "inside", target_is_directory=True
            )
            (base / "root-link").symlink_to(base / "inside", target_is_directory=True)
            (base / "final.json").symlink_to(base / "inside/file.json")
            for relative in (
                "intermediate/file.json",
                "final.json",
                "inside",
                "missing.json",
            ):
                with (
                    self.subTest(relative=relative),
                    self.assertRaises(AssuranceIntegrationError),
                ):
                    resolve_regular_file(base, relative)
            with self.assertRaises(AssuranceIntegrationError):
                resolve_regular_file(base / "root-link", "file.json")

    def test_arbitrary_executable_and_arguments_are_not_cli_contract(self) -> None:
        parser = build_parser()
        base = [
            "--profile",
            "profiles/private-match-ae-assurance.v0.1.json",
            "--input-root",
            "x",
            "--input",
            "x.json",
            "--output-root",
            "y",
            "--output",
            "result",
            "--mode",
            "fixture-test",
        ]
        for option in ("--executable", "--native-arg"):
            with (
                self.assertRaises(SystemExit),
                mock.patch("sys.stderr", new=io.StringIO()),
            ):
                parser.parse_args([*base, option, "bad"])

    def test_subprocess_timeout_and_output_bound_are_value_free_failures(self) -> None:
        node = subprocess.CompletedProcess(
            ["node", "--version"], 0, stdout=b"v22.22.2\n", stderr=b""
        )
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            staging = Path(temp)
            with (
                mock.patch(
                    "scripts.ae_framework_adapter._run_bounded_process",
                    side_effect=[node, subprocess.TimeoutExpired("node", 1)],
                ),
            ):
                with self.assertRaisesRegex(AssuranceIntegrationError, "timed out"):
                    _run_native(ROOT, self.success, self.profile, staging)
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            staging = Path(temp)
            with (
                mock.patch(
                    "scripts.ae_framework_adapter._run_bounded_process",
                    side_effect=[
                        node,
                        AssuranceIntegrationError(
                            "pinned ae-framework output exceeded its bound"
                        ),
                    ],
                ),
            ):
                with self.assertRaisesRegex(AssuranceIntegrationError, "exceeded"):
                    _run_native(ROOT, self.success, self.profile, staging)
        with self.assertRaisesRegex(AssuranceIntegrationError, "exceeded"):
            _run_bounded_process(
                [sys.executable, "-c", "print('x' * 70000)"],
                cwd=ROOT,
                env={"PATH": str(Path(sys.executable).parent)},
                timeout_seconds=5,
                max_output_bytes=65536,
            )

    def test_native_subprocess_uses_fixed_arguments_no_shell_and_allowlisted_environment(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            with mock.patch(
                "scripts.ae_framework_adapter.subprocess.Popen", wraps=subprocess.Popen
            ) as execute:
                projection = _run_native(ROOT, self.success, self.profile, Path(temp))
            self.assertEqual(
                projection["schema_version"], "assurance-summary/v1-safe-projection"
            )
            invocations = [
                item
                for item in execute.call_args_list
                if item.args and "scripts/assurance/aggregate-lanes.mjs" in item.args[0]
            ]
            self.assertEqual(len(invocations), 1)
            invocation = invocations[0]
            self.assertEqual(
                invocation.args[0][
                    invocation.args[0].index("scripts/assurance/aggregate-lanes.mjs")
                ],
                "scripts/assurance/aggregate-lanes.mjs",
            )
            self.assertIn("--permission", invocation.args[0])
            self.assertFalse(
                any(arg == "--allow-child-process" for arg in invocation.args[0])
            )
            self.assertIs(invocation.kwargs["shell"], False)
            self.assertEqual(
                set(invocation.kwargs["env"]),
                {
                    "PATH",
                    "LANG",
                    "LC_ALL",
                    "TZ",
                    "CI",
                    "GIT_COMMIT",
                    "GIT_BRANCH",
                    "RUNNER_NAME",
                    "RUNNER_OS",
                    "RUNNER_ARCH",
                },
            )

    def test_malformed_native_summary_and_missing_field_fail_closed(self) -> None:
        node = subprocess.CompletedProcess(
            ["node", "--version"], 0, stdout=b"v22.22.2\n", stderr=b""
        )

        def malformed(command, **_kwargs):
            if command[-1] == "--version":
                return node
            output = Path(command[command.index("--output-json") + 1])
            markdown = Path(command[command.index("--output-md") + 1])
            output.write_text("{}\n", encoding="utf-8")
            markdown.write_text("invalid\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            with (
                mock.patch(
                    "scripts.ae_framework_adapter._run_bounded_process",
                    side_effect=malformed,
                ),
            ):
                with self.assertRaises(AssuranceIntegrationError):
                    _run_native(ROOT, self.success, self.profile, Path(temp))

    def test_native_warning_policy_blocks_and_unknown_codes_fail_closed(self) -> None:
        projection = copy.deepcopy(
            self.success_expected["native_ae_summary_projection"]
        )
        blocking_profile = copy.deepcopy(self.profile)
        blocking_profile["native_ae_judgment_policy"][
            "visible_nonblocking_warning_codes"
        ] = []
        blocking_profile["native_ae_judgment_policy"]["blocking_warning_codes"].append(
            "missing-spec-derived-evidence"
        )
        self.assertEqual(
            derive_native_judgment(projection, blocking_profile)["state"], "blocked"
        )
        projection["warning_codes"] = ["unreviewed-native-warning"]
        projection["claims"][0]["warning_codes"] = ["unreviewed-native-warning"]
        with self.assertRaises(AssuranceIntegrationError):
            derive_native_judgment(projection, self.profile)
        with self.assertRaises(AssuranceIntegrationError):
            validate_package(
                ROOT,
                self._result(
                    lambda value: value["automated_judgment"].__setitem__(
                        "state", "satisfied"
                    )
                ),
            )

    def test_native_missing_surface_blocks_and_status_changes_bind_package(
        self,
    ) -> None:
        projection = copy.deepcopy(
            self.success_expected["native_ae_summary_projection"]
        )
        projection["claims"][0]["missing_lanes"] = ["runtime"]
        self.assertEqual(
            derive_native_judgment(projection, self.profile)["state"], "blocked"
        )

        baseline_projection = copy.deepcopy(
            self.success_expected["native_ae_summary_projection"]
        )
        changed_projection = copy.deepcopy(baseline_projection)
        changed_projection["claims"][0]["status"] = "satisfied"
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            staging = Path(temp)
            with mock.patch(
                "scripts.ae_framework_adapter._run_native",
                return_value=baseline_projection,
            ):
                baseline = build_assurance_package(ROOT, self.success, staging)
            with mock.patch(
                "scripts.ae_framework_adapter._run_native",
                return_value=changed_projection,
            ):
                changed = build_assurance_package(ROOT, self.success, staging)
        self.assertNotEqual(baseline["package_digest"], changed["package_digest"])
        self.assertEqual(
            [record["status"] for record in baseline["evidence_records"]],
            [record["status"] for record in changed["evidence_records"]],
        )

    def test_output_is_transactional_and_failure_leaves_no_partial_tree(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            output = Path(temp) / "final"
            with mock.patch(
                "scripts.run_ae_assurance.build_assurance_package",
                side_effect=RuntimeError("private raw detail"),
            ):
                with self.assertRaises(RuntimeError):
                    run_one(
                        root=ROOT,
                        profile_path="profiles/private-match-ae-assurance.v0.1.json",
                        input_root=FIXTURE_ROOT,
                        relative_input="input/success.json",
                        output_root=Path(temp),
                        relative_output="final",
                        mode="fixture-test",
                    )
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(temp).glob(".final.partial-*")), [])

    def test_output_root_requires_one_confined_new_relative_directory(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            trusted = Path(temp) / "trusted"
            unrelated = Path(temp) / "unrelated"
            trusted.mkdir()
            unrelated.mkdir()
            (trusted / "nested").mkdir()
            self.assertEqual(
                resolve_new_directory(trusted, "nested/result"),
                trusted.resolve() / "nested/result",
            )
            for relative in (
                "/absolute",
                "C:/windows",
                "a\\b",
                ".",
                "./a",
                "a/../b",
                "../unrelated/escaped",
                "a//b",
            ):
                with (
                    self.subTest(relative=relative),
                    self.assertRaises(AssuranceIntegrationError),
                ):
                    resolve_new_directory(trusted, relative)
            (trusted / "existing").mkdir()
            with self.assertRaises(AssuranceIntegrationError):
                resolve_new_directory(trusted, "existing")
            (trusted / "partial").write_text("partial", encoding="utf-8")
            with self.assertRaises(AssuranceIntegrationError):
                resolve_new_directory(trusted, "partial")
            (trusted / "inside-target").mkdir()
            (trusted / "inside-link").symlink_to(
                trusted / "inside-target", target_is_directory=True
            )
            (trusted / "outside-link").symlink_to(unrelated, target_is_directory=True)
            for relative in ("inside-link/result", "outside-link/result"):
                with self.assertRaises(AssuranceIntegrationError):
                    resolve_new_directory(trusted, relative)
            self.assertEqual(list(unrelated.iterdir()), [])

    def test_output_set_binds_exact_json_markdown_and_path_set(self) -> None:
        entry = next(
            item
            for item in read_strict_json(ROOT / FIXTURE_CATALOG_PATH)["fixtures"]
            if item["fixture_id"] == "PMAE-FIXTURE-SUCCESS-V0-1"
        )
        source = (FIXTURE_ROOT / entry["expected_output_set_path"]).parent
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            base = Path(temp)

            def fresh(name: str) -> Path:
                target = base / name
                shutil.copytree(source, target)
                return target

            valid = fresh("valid")
            manifest = validate_output_directory(ROOT, valid)
            self.assertEqual(
                manifest["renderer"]["implementation_digest"],
                renderer_source_digest(ROOT),
            )
            package = read_strict_json(valid / JSON_NAME)
            with mock.patch(
                "scripts.ae_assurance_output_set.renderer_source_digest",
                return_value="sha256:" + "0" * 64,
            ):
                changed_renderer = build_output_set(
                    ROOT,
                    package,
                    (valid / JSON_NAME).read_bytes(),
                    (valid / MARKDOWN_NAME).read_bytes(),
                )
            self.assertNotEqual(
                manifest["output_set_digest"], changed_renderer["output_set_digest"]
            )

            markdown_changed = fresh("markdown-changed")
            (markdown_changed / MARKDOWN_NAME).write_text(
                (markdown_changed / MARKDOWN_NAME).read_text() + "changed\n",
                encoding="utf-8",
            )
            rebound = read_strict_json(markdown_changed / OUTPUT_SET_NAME)
            rebound["markdown_report"]["file_digest"] = file_digest(
                (markdown_changed / MARKDOWN_NAME).read_bytes()
            )
            rebound["output_set_digest"] = artifact_digest(
                OUTPUT_SET_DOMAIN, rebound, "output_set_digest"
            )
            (markdown_changed / OUTPUT_SET_NAME).write_bytes(
                canonicalize(rebound) + b"\n"
            )
            with self.assertRaises(AssuranceIntegrationError):
                validate_output_directory(ROOT, markdown_changed)

            json_changed = fresh("json-changed")
            (json_changed / JSON_NAME).write_bytes(
                (json_changed / JSON_NAME).read_bytes() + b" \n"
            )
            with self.assertRaises(AssuranceIntegrationError):
                validate_output_directory(ROOT, json_changed)

            for name, mutation in (
                ("missing", lambda target: (target / MARKDOWN_NAME).unlink()),
                ("extra", lambda target: (target / "stale.txt").write_text("stale")),
            ):
                target = fresh(name)
                mutation(target)
                with self.assertRaises(AssuranceIntegrationError):
                    validate_output_directory(ROOT, target)

            stale_renderer = fresh("stale-renderer")
            output_set = read_strict_json(stale_renderer / OUTPUT_SET_NAME)
            output_set["renderer"]["implementation_digest"] = "sha256:" + "0" * 64
            output_set["output_set_digest"] = artifact_digest(
                OUTPUT_SET_DOMAIN, output_set, "output_set_digest"
            )
            (stale_renderer / OUTPUT_SET_NAME).write_bytes(
                canonicalize(output_set) + b"\n"
            )
            with self.assertRaises(AssuranceIntegrationError):
                validate_output_directory(ROOT, stale_renderer)

    def test_cli_failure_is_bounded_and_does_not_emit_exception_detail(self) -> None:
        arguments = [
            "--profile",
            "profiles/private-match-ae-assurance.v0.1.json",
            "--input-root",
            str(FIXTURE_ROOT),
            "--input",
            "input/success.json",
            "--output-root",
            str(ROOT / ".codex-local/tmp"),
            "--output",
            "never-created-output",
            "--mode",
            "fixture-test",
        ]
        stderr = io.StringIO()
        with (
            mock.patch(
                "scripts.run_ae_assurance.run_one",
                side_effect=RuntimeError("/home/private SECRET"),
            ),
            mock.patch("sys.stderr", new=stderr),
        ):
            self.assertEqual(runner_main(arguments), 2)
        self.assertEqual(
            stderr.getvalue(), "ae Assurance execution failed: contract violation\n"
        )

    def test_markdown_escapes_arbitrary_labels(self) -> None:
        package = copy.deepcopy(self.success_expected)
        package["producer_inventory"][0]["producer_id"] = "<script>|line\nnext"
        markdown = render_markdown(package)
        self.assertNotIn("<script>", markdown)
        self.assertIn("&lt;script&gt;\\|line next", markdown)

    def test_fabricated_fixture_approval_and_live_conversion_are_rejected(self) -> None:
        mutations = (
            lambda value: value["human_approval"].update(
                {
                    "state": "approved",
                    "reviewer_role": "authorized-human",
                    "reviewer_identity_verified": True,
                }
            ),
            lambda value: value["human_approval"].update(
                {
                    "state": "rejected",
                    "reviewer_role": "authorized-human",
                    "reviewer_identity_verified": True,
                }
            ),
            lambda value: value["human_approval"].__setitem__(
                "reviewer_identity_verified", True
            ),
            lambda value: value["human_approval"].__setitem__(
                "approval_decision_generated_by_automation", True
            ),
        )
        for mutation in mutations:
            with self.assertRaises(AssuranceIntegrationError):
                validate_package(ROOT, self._result(mutation))
        self.assertTrue(
            self.success_expected["human_approval"][
                "boundary_artifact_generated_by_automation"
            ]
        )
        self.assertFalse(
            self.success_expected["human_approval"]["approval_decision_present"]
        )
        with self.assertRaisesRegex(AssuranceIntegrationError, "cannot represent"):
            validate_judgment_approval_boundary("blocked", "approved")

    def test_private_candidate_runner_is_deterministic_and_truthful(self) -> None:
        candidate = self._private_candidate()
        validate_producer_package(ROOT, candidate, self.inventory, self.profile)
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            base = Path(temp)
            (base / "candidate.json").write_bytes(canonicalize(candidate) + b"\n")
            outputs = []
            for name in ("first", "second"):
                outputs.append(
                    run_one(
                        root=ROOT,
                        profile_path="profiles/private-match-ae-assurance.v0.1.json",
                        input_root=base,
                        relative_input="candidate.json",
                        output_root=base,
                        relative_output=name,
                        mode="private-candidate",
                    )
                )
                validate_output_directory(ROOT, base / name)
            self.assertEqual(outputs[0], outputs[1])
            mutated = base / "mutated"
            shutil.copytree(base / "first", mutated)
            (mutated / MARKDOWN_NAME).write_text(
                (mutated / MARKDOWN_NAME).read_text() + "changed\n",
                encoding="utf-8",
            )
            rebound = read_strict_json(mutated / OUTPUT_SET_NAME)
            rebound["markdown_report"]["file_digest"] = file_digest(
                (mutated / MARKDOWN_NAME).read_bytes()
            )
            rebound["output_set_digest"] = artifact_digest(
                OUTPUT_SET_DOMAIN, rebound, "output_set_digest"
            )
            (mutated / OUTPUT_SET_NAME).write_bytes(canonicalize(rebound) + b"\n")
            with self.assertRaises(AssuranceIntegrationError):
                validate_output_directory(ROOT, mutated)
            package = read_strict_json(base / "first" / JSON_NAME)
        self.assertEqual(package["artifact_status"], "private-candidate")
        self.assertEqual(package["human_approval"]["state"], "required-not-provided")
        self.assertFalse(package["human_approval"]["reviewer_identity_verified"])
        self.assertFalse(package["lifecycle_boundary"]["public_export_eligible"])
        self.assertNotIn(
            "same-generator-lineage",
            package["native_ae_judgment"]["warning_codes"],
        )
        self.assertEqual(package["native_ae_judgment"]["state"], "warning")
        self.assertEqual(
            package["automated_judgment"]["state"], "satisfied-with-warnings"
        )
        self.assertTrue(
            all(
                record["subject"] == candidate["subject"]
                for record in package["evidence_records"]
            )
        )
        self.assertTrue(
            all(
                "source_revision_digest" not in record
                for record in candidate["records"]
            )
        )
        binding_by_role = {
            binding["tool_role_id"]: binding for binding in candidate["tool_bindings"]
        }
        self.assertEqual(
            package["external_tool_inventory"],
            [
                {
                    "tool_role_id": role["tool_id"],
                    "producer_type": role["producer_type"],
                    "requirement": role["requirement"],
                    "mode": binding_by_role[role["tool_id"]]["mode"],
                    "tool_id": binding_by_role[role["tool_id"]]["identity"],
                    "tool_version": binding_by_role[role["tool_id"]]["version"],
                    "tool_implementation_digest": binding_by_role[role["tool_id"]][
                        "implementation_digest"
                    ],
                    "input_contract": binding_by_role[role["tool_id"]][
                        "input_contract"
                    ],
                    "output_contract": binding_by_role[role["tool_id"]][
                        "output_contract"
                    ],
                    "limitations": binding_by_role[role["tool_id"]]["limitations"],
                    "tool_binding_digest": binding_by_role[role["tool_id"]][
                        "binding_digest"
                    ],
                }
                for role in self.inventory["tools"]
            ],
        )
        serialized = canonicalize(package).decode("utf-8")
        for forbidden in (
            "synthetic-private-match-product",
            "synthetic-reviewer",
            "synthetic-",
            "private-match-synthetic-",
            "Public synthetic fixture only",
            "Synthetic fixture identity only",
            '"test_only":true',
            "synthetic-public-fixture",
        ):
            self.assertNotIn(forbidden, serialized)
        for _, fixture_digest in FIXTURE_TOOL_BINDINGS.values():
            self.assertNotIn(fixture_digest, serialized)
        self.assertTrue(
            all(
                record["configuration"]["retention_classification"]
                == "private-assurance-retained"
                for record in package["evidence_records"]
            )
        )
        with self.assertRaises(AssuranceIntegrationError):
            validate_package(
                ROOT,
                self._result(
                    lambda value: value["human_approval"].update(
                        {
                            "state": "approved",
                            "reviewer_role": "authorized-human",
                            "reviewer_identity_verified": True,
                        }
                    ),
                    source=package,
                ),
            )
        validate_package(ROOT, package)

    def test_same_implementation_lineage_blocks_without_status_rewrite(self) -> None:
        candidate = self._private_candidate()
        shared_digest = "sha256:" + "e" * 64
        self._rebind_candidate_implementations(
            candidate,
            {
                binding["tool_role_id"]: shared_digest
                for binding in candidate["tool_bindings"]
            },
        )
        validate_producer_package(ROOT, candidate, self.inventory, self.profile)
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            base = Path(temp)
            (base / "candidate.json").write_bytes(canonicalize(candidate) + b"\n")
            output_bytes = []
            for name in ("first", "second"):
                run_one(
                    root=ROOT,
                    profile_path="profiles/private-match-ae-assurance.v0.1.json",
                    input_root=base,
                    relative_input="candidate.json",
                    output_root=base,
                    relative_output=name,
                    mode="private-candidate",
                )
                validate_output_directory(ROOT, base / name)
                output_bytes.append(
                    tuple(
                        (base / name / filename).read_bytes()
                        for filename in (JSON_NAME, MARKDOWN_NAME, OUTPUT_SET_NAME)
                    )
                )
            self.assertEqual(output_bytes[0], output_bytes[1])
            package = read_strict_json(base / "first" / JSON_NAME)
            output_set = read_strict_json(base / "first" / OUTPUT_SET_NAME)

        self.assertIn(
            "same-generator-lineage",
            package["native_ae_judgment"]["warning_codes"],
        )
        self.assertEqual(package["native_ae_judgment"]["state"], "blocked")
        self.assertEqual(package["automated_judgment"]["state"], "blocked")
        self.assertEqual(package["producer_gate_judgment"]["state"], "satisfied")
        self.assertEqual(
            [record["status"] for record in package["evidence_records"]],
            [record["status"] for record in candidate["records"]],
        )
        self.assertEqual(
            {
                item["tool_implementation_digest"]
                for item in package["external_tool_inventory"]
            },
            {shared_digest},
        )
        self.assertEqual(
            [item["tool_id"] for item in package["external_tool_inventory"]],
            [
                CANDIDATE_TOOL_IDENTITIES[role["tool_id"]]
                for role in self.inventory["tools"]
            ],
        )
        self.assertEqual(package["human_approval"]["state"], "required-not-provided")
        self.assertFalse(package["lifecycle_boundary"]["public_export_eligible"])
        self.assertRegex(package["package_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertRegex(output_set["output_set_digest"], r"^sha256:[0-9a-f]{64}$")

    def test_partial_shared_lineage_follows_pinned_observed_evidence_rule(self) -> None:
        candidate = self._private_candidate()
        shared_digest = "sha256:" + "d" * 64
        self._rebind_candidate_implementations(
            candidate,
            {
                "PMAE-CI-PIPELINE-V0-1": shared_digest,
                "PMAE-CONFORMANCE-RUNNER-V0-1": shared_digest,
            },
        )
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            base = Path(temp)
            (base / "candidate.json").write_bytes(canonicalize(candidate) + b"\n")
            run_one(
                root=ROOT,
                profile_path="profiles/private-match-ae-assurance.v0.1.json",
                input_root=base,
                relative_input="candidate.json",
                output_root=base,
                relative_output="result",
                mode="private-candidate",
            )
            package = read_strict_json(base / "result" / JSON_NAME)

        self.assertIn(
            "same-generator-lineage",
            package["native_ae_judgment"]["warning_codes"],
        )
        self.assertEqual(package["native_ae_judgment"]["state"], "blocked")
        self.assertEqual(package["automated_judgment"]["state"], "blocked")
        self.assertEqual(package["producer_gate_judgment"]["state"], "satisfied")
        self.assertGreater(
            len(
                {
                    item["tool_implementation_digest"]
                    for item in package["external_tool_inventory"]
                }
            ),
            1,
        )

    def test_candidate_tool_metadata_mutation_changes_bound_outputs(self) -> None:
        original = self._private_candidate()
        mutated = copy.deepcopy(original)
        binding = mutated["tool_bindings"][0]
        binding["version"] = "0.2.0"
        binding["implementation_digest"] = "sha256:" + "a" * 64
        binding["binding_digest"] = tool_binding_digest(binding)
        mutated["records"][0]["tool_version"] = binding["version"]
        mutated["records"][0]["tool_implementation_digest"] = binding[
            "implementation_digest"
        ]
        mutated["package_digest"] = artifact_digest(
            PRODUCER_PACKAGE_DOMAIN, mutated, "package_digest"
        )
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            base = Path(temp)
            outputs = []
            for name, source in (("original", original), ("mutated", mutated)):
                input_name = f"{name}.json"
                (base / input_name).write_bytes(canonicalize(source) + b"\n")
                run_one(
                    root=ROOT,
                    profile_path="profiles/private-match-ae-assurance.v0.1.json",
                    input_root=base,
                    relative_input=input_name,
                    output_root=base,
                    relative_output=name,
                    mode="private-candidate",
                )
                validate_output_directory(ROOT, base / name)
                outputs.append(
                    (
                        read_strict_json(base / name / JSON_NAME)["package_digest"],
                        read_strict_json(base / name / OUTPUT_SET_NAME)[
                            "output_set_digest"
                        ],
                    )
                )
        self.assertNotEqual(outputs[0], outputs[1])

    def test_json_markdown_mismatch_and_nondeterministic_fields_fail(self) -> None:
        package = copy.deepcopy(self.success_expected)
        package["status_counts"]["pass"] += 1
        with self.assertRaises(AssuranceIntegrationError):
            validate_package(ROOT, package)
        nondeterministic = self._producer(
            lambda value: value.__setitem__("generated_at", "now")
        )
        with self.assertRaises(AssuranceIntegrationError):
            validate_producer_package(
                ROOT, nondeterministic, self.inventory, self.profile
            )


if __name__ == "__main__":
    unittest.main()
