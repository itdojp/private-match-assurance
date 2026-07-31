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
    NATIVE_PROJECTION_DOMAIN,
    OUTPUT_SET_DOMAIN,
    PIN_DOMAIN,
    PROTOCOL_AUTHORITY_DOMAIN,
    PRODUCER_PACKAGE_DOMAIN,
    PROFILE_DOMAIN,
    TOOL_INVENTORY_DOMAIN,
    CANDIDATE_TOOL_IDENTITIES,
    CANDIDATE_TOOL_LIMITATION,
    FIXTURE_TOOL_BINDINGS,
    artifact_digest,
    load_authority,
    load_protocol_authority,
    load_schemas,
    protocol_authority_binding,
    tool_binding_digest,
)
from scripts.ae_framework_adapter import (
    _native_manifest,
    _combined_automated_judgment,
    _evidence_record,
    _run_bounded_process,
    _run_native,
    build_assurance_package,
    build_native_manifest_from_assurance_package,
    derive_native_judgment,
    native_generator_lineage,
    recompute_native_projection_from_assurance_package,
    run_pinned_ae_framework_manifest,
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
        protocol_authority = load_protocol_authority(ROOT)
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
        self.assertEqual(
            protocol_authority["commit"],
            "9bb59d3b5e1435885fdea60280d6602f937305c9",
        )
        self.assertEqual(
            protocol_authority["conformance_suite"]["semantic_digest"],
            "sha256:83787c69ec1128eb9ba4b8dcdfcb4ae218674b6158cd8c6c573d898a6f72ceba",
        )
        self.assertEqual(
            profile["protocol_conformance_authority"]["suite_binding_contract"],
            {
                "single_suite_per_package": True,
                "producer_record_scope": "all-reviewed-producer-roles",
                "evidence_input_digest_count": 5,
                "evidence_suite_digest_index": 0,
            },
        )
        self.assertEqual(
            profile["path_execution_contract"]["native_validation_temporary_boundary"],
            "process-owned-system-temporary-directory",
        )
        self.assertEqual(
            profile["formal_tool_evidence_contract"]["mode"], "proof-check-only"
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
        protocol_authority = load_protocol_authority(ROOT)
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
        self.assertEqual(
            protocol_authority["authority_digest"],
            artifact_digest(
                PROTOCOL_AUTHORITY_DOMAIN,
                protocol_authority,
                "authority_digest",
            ),
        )

    def test_protocol_authority_rejects_stale_or_floating_labels(self) -> None:
        schemas = load_schemas(ROOT)
        authority = load_protocol_authority(ROOT)
        mutations = (
            lambda value: value.__setitem__("commit", "0" * 40),
            lambda value: value.__setitem__("ref", "main"),
            lambda value: value["protocol"].__setitem__("identifier", "other"),
            lambda value: value["protocol"].__setitem__("version", "0.2"),
            lambda value: value["protocol"].__setitem__(
                "semantic_digest", "sha256:" + "0" * 64
            ),
            lambda value: value["conformance_suite"].__setitem__("identifier", "other"),
            lambda value: value["conformance_suite"].__setitem__("version", "0.2"),
            lambda value: value["conformance_suite"].__setitem__(
                "semantic_digest", "sha256:" + "0" * 64
            ),
        )
        registry = build_schema_registry(schemas.values())
        for mutation in mutations:
            value = copy.deepcopy(authority)
            mutation(value)
            value["authority_digest"] = artifact_digest(
                PROTOCOL_AUTHORITY_DOMAIN, value, "authority_digest"
            )
            with self.assertRaises(AssuranceIntegrationError):
                validate_schema_instance(
                    value, schemas["protocol_authority"], registry=registry
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
        self.assertIn("validation recorded at: `2030-01-01T00:02:00Z`", markdown)
        self.assertIn("conformance suite: `private-match-core/0.1`", markdown)

    def test_fixture_protocol_and_validation_authority_are_exact(self) -> None:
        authority = protocol_authority_binding(load_protocol_authority(ROOT))
        for name, package in self.packages.items():
            with self.subTest(name=name):
                producer = self.inputs[name]
                self.assertEqual(producer["protocol_conformance_authority"], authority)
                self.assertEqual(package["protocol_conformance_authority"], authority)
                self.assertEqual(
                    package["validation_provenance"]["validated_at"],
                    producer["validation_event"]["validated_at"],
                )
                self.assertEqual(
                    package["native_ae_summary_projection"]["generated_at"],
                    producer["validation_event"]["validated_at"],
                )
                conformance = next(
                    record
                    for record in package["evidence_records"]
                    if record["type"] == "conformance"
                )
                self.assertEqual(
                    conformance["configuration"]["protocol"],
                    {"identifier": "private-match-core", "version": "0.1"},
                )
                self.assertEqual(
                    conformance["configuration"]["conformance_suite"],
                    {"identifier": "private-match-core", "version": "0.1"},
                )

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

    def _rebound_native_projection(self, source: dict, mutate) -> dict:
        value = copy.deepcopy(source)
        mutate(value["native_ae_summary_projection"])
        value["ae_framework"]["native_projection_digest"] = domain_digest(
            NATIVE_PROJECTION_DOMAIN, value["native_ae_summary_projection"]
        )
        value["native_ae_judgment"] = derive_native_judgment(
            value["native_ae_summary_projection"], self.profile
        )
        value["automated_judgment"] = _combined_automated_judgment(
            value["producer_gate_judgment"], value["native_ae_judgment"]
        )
        return self._result(lambda _: None, source=value)

    def _rebound_evidence_inputs(self, mutate) -> dict:
        """Mutate stored Evidence input digests and rebind every package digest."""

        value = copy.deepcopy(self.success_expected)
        mutate(value["evidence_records"])
        refs = {item["evidence_id"]: item for item in value["evidence_record_refs"]}
        for record in value["evidence_records"]:
            refs[record["id"]]["record_digest"] = domain_digest(
                EVIDENCE_RECORD_DOMAIN, record
            )
        return self._result(lambda _: None, source=value)

    def _assert_rebound_output_rejected(self, package: dict) -> None:
        """Rebind exact output bytes and require stored-package validation to fail."""

        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "result"
            output.mkdir()
            json_bytes = canonicalize(package) + b"\n"
            markdown_bytes = render_markdown(package).encode("utf-8")
            output_set = build_output_set(ROOT, package, json_bytes, markdown_bytes)
            (output / JSON_NAME).write_bytes(json_bytes)
            (output / MARKDOWN_NAME).write_bytes(markdown_bytes)
            (output / OUTPUT_SET_NAME).write_bytes(canonicalize(output_set) + b"\n")
            with self.assertRaises(AssuranceIntegrationError):
                validate_output_directory(ROOT, output)

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

    def test_native_projection_is_recomputed_from_bound_evidence(self) -> None:
        required_fail = read_strict_json(
            FIXTURE_ROOT / "expected/required-fail" / JSON_NAME,
            max_bytes=2_097_152,
        )

        def strengthen(value: dict) -> None:
            claim = value["claims"][0]
            claim["status"] = "satisfied"
            claim["warning_codes"] = []
            value["warning_codes"] = []
            value["summary"]["warningClaims"] = 0
            value["summary"]["satisfiedClaims"] = 1
            value["summary"]["warningCount"] = 0

        mutations = (
            (self.success_expected, strengthen),
            (
                self.success_expected,
                lambda value: value["claims"][0].__setitem__("status", "satisfied"),
            ),
            (
                required_fail,
                lambda value: value["claims"][0].__setitem__("missing_lanes", []),
            ),
            (
                required_fail,
                lambda value: value["claims"][0].__setitem__(
                    "missing_evidence_kinds", []
                ),
            ),
            (
                self.success_expected,
                lambda value: value["lane_coverage"]["runtime"].__setitem__(
                    "observedClaims", 0
                ),
            ),
            (
                self.success_expected,
                lambda value: value["summary"].__setitem__("warningCount", 0),
            ),
            (
                self.success_expected,
                lambda value: value.__setitem__("warning_codes", []),
            ),
        )
        for source, mutation in mutations:
            with self.subTest(mutation=mutation):
                tampered = self._rebound_native_projection(source, mutation)
                with self.assertRaisesRegex(
                    AssuranceIntegrationError,
                    "native ae projection does not match bound Evidence",
                ):
                    validate_package(ROOT, tampered)
                with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
                    output = Path(temp) / "result"
                    output.mkdir()
                    json_bytes = canonicalize(tampered) + b"\n"
                    markdown_bytes = render_markdown(tampered).encode("utf-8")
                    output_set = build_output_set(
                        ROOT, tampered, json_bytes, markdown_bytes
                    )
                    (output / JSON_NAME).write_bytes(json_bytes)
                    (output / MARKDOWN_NAME).write_bytes(markdown_bytes)
                    (output / OUTPUT_SET_NAME).write_bytes(
                        canonicalize(output_set) + b"\n"
                    )
                    with self.assertRaisesRegex(
                        AssuranceIntegrationError,
                        "native ae projection does not match bound Evidence",
                    ):
                        validate_output_directory(ROOT, output)

    def test_bound_evidence_status_changes_recomputed_native_projection(self) -> None:
        required_fail = read_strict_json(
            FIXTURE_ROOT / "expected/required-fail" / JSON_NAME,
            max_bytes=2_097_152,
        )
        self.assertNotEqual(
            self.success_expected["native_ae_summary_projection"],
            required_fail["native_ae_summary_projection"],
        )
        self.assertNotEqual(
            build_native_manifest_from_assurance_package(self.success_expected),
            build_native_manifest_from_assurance_package(required_fail),
        )

    def test_native_manifest_is_reconstructed_from_stored_evidence(self) -> None:
        manifest = build_native_manifest_from_assurance_package(self.success_expected)
        self.assertEqual(manifest, _native_manifest(self.success))
        formal = next(
            entry
            for entry in manifest["entries"]
            if entry["artifactPath"].endswith("PM-EVIDENCE-0003")
        )
        self.assertEqual(
            (formal["lane"], formal["kind"], formal["sourceKind"]),
            ("proof", "proof-check", "model-derived"),
        )
        self.assertNotIn("model-check", canonicalize(manifest).decode("utf-8"))

    def test_formal_tool_uses_proof_check_and_preserves_every_status(self) -> None:
        authority = protocol_authority_binding(load_protocol_authority(ROOT))
        formal_role = next(
            role
            for role in self.inventory["tools"]
            if role["producer_type"] == "formal-tool"
        )
        formal_binding = next(
            binding
            for binding in self.success["tool_bindings"]
            if binding["producer_type"] == "formal-tool"
        )
        formal_record = next(
            record
            for record in self.success["records"]
            if record["producer_type"] == "formal-tool"
        )
        for status in ("pass", "fail", "skip", "unsupported", "timeout", "tool-error"):
            record = copy.deepcopy(formal_record)
            mapping = next(
                item
                for item in formal_role["status_mappings"]
                if item["raw_producer_status"] == status
            )
            record["status"] = status
            record["product_output_digest"] = (
                "sha256:" + "a" * 64 if status in {"pass", "fail"} else None
            )
            record["limitations"][0] = mapping["required_limitation"]
            evidence = _evidence_record(
                record,
                formal_binding,
                self.success["package_digest"],
                self.success["subject"],
                authority,
                self.success["validation_event"]["validated_at"],
                required=False,
            )
            self.assertEqual(evidence["status"], status)
            self.assertEqual(evidence["type"], "proof-check")
            self.assertIsNone(evidence["model_check"])
        with self.assertRaises(AssuranceIntegrationError):
            validate_producer_package(
                ROOT,
                self._producer(
                    lambda value: value["records"][2].__setitem__(
                        "native_kind", "model-check"
                    )
                ),
                self.inventory,
                self.profile,
            )

    def test_unknown_producer_type_and_status_fail_closed(self) -> None:
        for mutate in (
            lambda value: value["records"][0].__setitem__("producer_type", "unknown"),
            lambda value: value["records"][0].__setitem__("status", "success"),
        ):
            with self.assertRaises(AssuranceIntegrationError):
                validate_producer_package(
                    ROOT, self._producer(mutate), self.inventory, self.profile
                )

    def test_producer_protocol_authority_and_suite_digest_fail_closed(self) -> None:
        mutations = (
            lambda value: value["protocol_conformance_authority"][
                "protocol"
            ].__setitem__("identifier", "other"),
            lambda value: value["protocol_conformance_authority"][
                "protocol"
            ].__setitem__("version", "0.2"),
            lambda value: value["protocol_conformance_authority"][
                "protocol"
            ].__setitem__("digest", "sha256:" + "0" * 64),
            lambda value: value["protocol_conformance_authority"][
                "conformance_suite"
            ].__setitem__("identifier", "other"),
            lambda value: value["protocol_conformance_authority"][
                "conformance_suite"
            ].__setitem__("version", "0.2"),
            lambda value: value["protocol_conformance_authority"][
                "conformance_suite"
            ].__setitem__("digest", "sha256:" + "0" * 64),
            lambda value: value["protocol_conformance_authority"].__setitem__(
                "authority_id", "unknown"
            ),
            lambda value: next(
                record
                for record in value["records"]
                if record["producer_type"] == "test-runner"
            ).__setitem__("protocol_suite_digest", "sha256:" + "0" * 64),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                package = self._producer(mutation)
                with self.assertRaises(AssuranceIntegrationError):
                    validate_producer_package(
                        ROOT, package, self.inventory, self.profile
                    )

    def test_every_producer_role_is_bound_to_one_reviewed_suite(self) -> None:
        expected = protocol_authority_binding(load_protocol_authority(ROOT))[
            "conformance_suite"
        ]["digest"]
        self.assertEqual(
            {record["protocol_suite_digest"] for record in self.success["records"]},
            {expected},
        )
        for index, record in enumerate(self.success["records"]):
            with self.subTest(producer_type=record["producer_type"]):
                package = self._producer(
                    lambda value, index=index: value["records"][index].__setitem__(
                        "protocol_suite_digest", "sha256:" + "0" * 64
                    )
                )
                with self.assertRaisesRegex(
                    AssuranceIntegrationError,
                    "producer record does not match reviewed suite authority",
                ):
                    validate_producer_package(
                        ROOT, package, self.inventory, self.profile
                    )

        all_unreviewed = self._producer(
            lambda value: [
                record.__setitem__("protocol_suite_digest", "sha256:" + "1" * 64)
                for record in value["records"]
            ]
        )
        with self.assertRaisesRegex(
            AssuranceIntegrationError,
            "producer record does not match reviewed suite authority",
        ):
            validate_producer_package(
                ROOT, all_unreviewed, self.inventory, self.profile
            )

    def test_producer_suite_digest_missing_malformed_or_stale_authority_fails(
        self,
    ) -> None:
        mutations = (
            lambda value: value["records"][0].pop("protocol_suite_digest"),
            lambda value: value["records"][0].__setitem__(
                "protocol_suite_digest", "sha256:invalid"
            ),
            lambda value: value["protocol_conformance_authority"].__setitem__(
                "authority_digest", "sha256:" + "0" * 64
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(AssuranceIntegrationError):
                    validate_producer_package(
                        ROOT,
                        self._producer(mutation),
                        self.inventory,
                        self.profile,
                    )

    def test_every_stored_evidence_record_has_closed_suite_digest_position(
        self,
    ) -> None:
        expected = protocol_authority_binding(load_protocol_authority(ROOT))[
            "conformance_suite"
        ]["digest"]
        for record in self.success_expected["evidence_records"]:
            self.assertEqual(len(record["input_digests"]), 5)
            self.assertEqual(record["input_digests"][0], expected)

        mutations = (
            lambda records: records[0]["input_digests"].__setitem__(
                0, "sha256:" + "0" * 64
            ),
            lambda records: records[0]["input_digests"].append("sha256:" + "0" * 64),
            lambda records: records[0].__setitem__(
                "input_digests",
                [
                    records[0]["input_digests"][1],
                    records[0]["input_digests"][0],
                    *records[0]["input_digests"][2:],
                ],
            ),
            lambda records: records[0]["input_digests"].pop(0),
            lambda records: [
                record["input_digests"].__setitem__(0, "sha256:" + "1" * 64)
                for record in records
            ],
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                package = self._rebound_evidence_inputs(mutation)
                with self.assertRaisesRegex(
                    AssuranceIntegrationError,
                    "Evidence input digests do not match the reviewed suite authority",
                ):
                    validate_package(ROOT, package)
                self._assert_rebound_output_rejected(package)

    def test_validation_event_orders_records_creation_and_validation(self) -> None:
        validate_producer_package(ROOT, self.success, self.inventory, self.profile)
        mutations = (
            lambda value: value["validation_event"].__setitem__(
                "validated_at", "2030-01-01T00:00:01Z"
            ),
            lambda value: value.update(
                {
                    "created_at": "2030-01-01T00:00:00Z",
                    "validation_event": {"validated_at": "2030-01-01T00:00:00Z"},
                }
            ),
            lambda value: value["records"][0].__setitem__(
                "completed_at", "2030-01-01T00:01:01Z"
            ),
            lambda value: value["validation_event"].__setitem__(
                "validated_at", "2030-01-01T00:02:00+00:00"
            ),
            lambda value: value.pop("validation_event"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with self.assertRaises(AssuranceIntegrationError):
                    validate_producer_package(
                        ROOT,
                        self._producer(mutation),
                        self.inventory,
                        self.profile,
                    )

    def test_evidence_lifecycle_is_bound_to_validation_provenance(self) -> None:
        value = copy.deepcopy(self.success_expected)
        record = value["evidence_records"][0]
        record["lifecycle_history"][1]["recorded_at"] = record["completed_at"]
        ref = next(
            item
            for item in value["evidence_record_refs"]
            if item["evidence_id"] == record["id"]
        )
        ref["record_digest"] = domain_digest(EVIDENCE_RECORD_DOMAIN, record)
        value = self._result(lambda _: None, source=value)
        with self.assertRaisesRegex(AssuranceIntegrationError, "Evidence lifecycle"):
            validate_package(ROOT, value)

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

    def test_stored_validation_uses_private_process_temp_without_output_leak(
        self,
    ) -> None:
        captured: list[Path] = []

        def invoke(*args, **kwargs):
            staging = Path(args[4])
            captured.append(staging)
            self.assertTrue(staging.exists())
            if sys.platform != "win32":
                self.assertEqual(staging.stat().st_mode & 0o077, 0)
            return run_pinned_ae_framework_manifest(*args, **kwargs)

        with mock.patch(
            "scripts.ae_framework_adapter.run_pinned_ae_framework_manifest",
            side_effect=invoke,
        ):
            validate_package(ROOT, self.success_expected)
        self.assertEqual(len(captured), 1)
        staging = captured[0]
        self.assertTrue(staging.name.startswith("private-match-ae-native-validation-"))
        self.assertFalse(staging.exists())

        json_bytes = canonicalize(self.success_expected) + b"\n"
        markdown_bytes = render_markdown(self.success_expected).encode("utf-8")
        output_set = canonicalize(
            build_output_set(ROOT, self.success_expected, json_bytes, markdown_bytes)
        )
        encoded_path = str(staging).encode("utf-8")
        for output in (json_bytes, markdown_bytes, output_set):
            self.assertNotIn(encoded_path, output)

    def test_stored_validation_ignores_repository_local_codex_symlinks(self) -> None:
        projection = self.success_expected["native_ae_summary_projection"]
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            scenarios: list[tuple[str, Path, Path]] = []

            outside_a = base / "outside-a"
            outside_a.mkdir()
            (outside_a / "sentinel").write_text("untouched", encoding="utf-8")
            root_a = base / "repo-a"
            root_a.mkdir()
            (root_a / ".codex-local").symlink_to(outside_a, target_is_directory=True)
            scenarios.append(("codex-local-symlink", root_a, outside_a))

            outside_b = base / "outside-b"
            outside_b.mkdir()
            (outside_b / "sentinel").write_text("untouched", encoding="utf-8")
            root_b = base / "repo-b"
            (root_b / ".codex-local").mkdir(parents=True)
            (root_b / ".codex-local/tmp").symlink_to(
                outside_b, target_is_directory=True
            )
            scenarios.append(("tmp-symlink", root_b, outside_b))

            root_c = base / "repo-c"
            local_tmp = root_c / ".codex-local/tmp"
            local_tmp.mkdir(parents=True)
            (local_tmp / "sentinel").write_text("untouched", encoding="utf-8")
            scenarios.append(("preexisting-content", root_c, local_tmp))

            for name, fake_root, sentinel_root in scenarios:
                captured: list[Path] = []

                def invoke(*args, **_kwargs):
                    captured.append(Path(args[4]))
                    return copy.deepcopy(projection)

                with (
                    self.subTest(name=name),
                    mock.patch(
                        "scripts.ae_framework_adapter.run_pinned_ae_framework_manifest",
                        side_effect=invoke,
                    ),
                ):
                    _, result = recompute_native_projection_from_assurance_package(
                        fake_root, self.success_expected, self.profile
                    )
                    self.assertEqual(result, projection)
                self.assertEqual(len(captured), 1)
                self.assertFalse(captured[0].is_relative_to(fake_root))
                self.assertFalse(captured[0].exists())
                self.assertEqual(
                    (sentinel_root / "sentinel").read_text(encoding="utf-8"),
                    "untouched",
                )
                self.assertEqual(
                    sorted(path.name for path in sentinel_root.iterdir()), ["sentinel"]
                )

    def test_stored_validation_temp_cleans_all_failure_paths_and_bounds_errors(
        self,
    ) -> None:
        failures = (
            ("native-schema", AssuranceIntegrationError("native Schema is invalid")),
            ("nonzero", AssuranceIntegrationError("native process failed")),
            ("timeout", subprocess.TimeoutExpired(["node"], 1)),
            ("output-bound", AssuranceIntegrationError("native output exceeded")),
        )
        for name, failure in failures:
            captured: list[Path] = []

            def fail(*args, failure=failure, **_kwargs):
                captured.append(Path(args[4]))
                raise failure

            with (
                self.subTest(name=name),
                mock.patch(
                    "scripts.ae_framework_adapter.run_pinned_ae_framework_manifest",
                    side_effect=fail,
                ),
                self.assertRaisesRegex(
                    AssuranceIntegrationError, "stored native recomputation failed"
                ) as raised,
            ):
                recompute_native_projection_from_assurance_package(
                    ROOT, self.success_expected, self.profile
                )
            self.assertEqual(len(captured), 1)
            self.assertFalse(captured[0].exists())
            self.assertNotIn(str(captured[0]), str(raised.exception))

        captured = []

        def unexpected(*args, **_kwargs):
            staging = Path(args[4])
            captured.append(staging)
            raise RuntimeError(f"unexpected failure at {staging}")

        with (
            mock.patch(
                "scripts.ae_framework_adapter.run_pinned_ae_framework_manifest",
                side_effect=unexpected,
            ),
            self.assertRaisesRegex(
                AssuranceIntegrationError, "stored native recomputation failed"
            ) as raised,
        ):
            recompute_native_projection_from_assurance_package(
                ROOT, self.success_expected, self.profile
            )
        self.assertFalse(captured[0].exists())
        self.assertNotIn(str(captured[0]), str(raised.exception))

    def test_projection_mismatch_cleans_temp_and_malformed_package_creates_none(
        self,
    ) -> None:
        captured: list[Path] = []
        projection = copy.deepcopy(
            self.success_expected["native_ae_summary_projection"]
        )
        projection["summary"]["warningCount"] += 1

        def mismatch(*args, **_kwargs):
            captured.append(Path(args[4]))
            return projection

        with (
            mock.patch(
                "scripts.ae_framework_adapter.run_pinned_ae_framework_manifest",
                side_effect=mismatch,
            ),
            self.assertRaisesRegex(
                AssuranceIntegrationError,
                "native ae projection does not match bound Evidence",
            ),
        ):
            validate_package(ROOT, self.success_expected)
        self.assertEqual(len(captured), 1)
        self.assertFalse(captured[0].exists())

        malformed = copy.deepcopy(self.success_expected)
        malformed.pop("evidence_records")
        with (
            mock.patch(
                "scripts.ae_framework_adapter.tempfile.TemporaryDirectory"
            ) as temporary,
            self.assertRaises(AssuranceIntegrationError),
        ):
            validate_package(ROOT, malformed)
        temporary.assert_not_called()

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
                "scripts.ae_framework_adapter.run_pinned_ae_framework_manifest",
                return_value=baseline_projection,
            ):
                baseline = build_assurance_package(ROOT, self.success, staging)
            with mock.patch(
                "scripts.ae_framework_adapter.run_pinned_ae_framework_manifest",
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
