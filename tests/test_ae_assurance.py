from __future__ import annotations

import copy
import io
from pathlib import Path
import re
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
    validate_relative_path,
    validate_schema_instance,
)
from scripts.ae_assurance_implementation import (
    MANIFEST_PATH,
    adapter_source_digest,
    build_manifest,
    verify_manifest,
)
from scripts.ae_assurance_policy import (
    ASSURANCE_CONTENT_DOMAIN,
    ASSURANCE_PACKAGE_DOMAIN,
    FIXTURE_CATALOG_PATH,
    JSON_REPORT_DOMAIN,
    MARKDOWN_REPORT_DOMAIN,
    PIN_DOMAIN,
    PRODUCER_PACKAGE_DOMAIN,
    PROFILE_DOMAIN,
    TOOL_INVENTORY_DOMAIN,
    artifact_digest,
    load_authority,
    load_schemas,
)
from scripts.ae_framework_adapter import (
    _run_bounded_process,
    _run_native,
    build_assurance_package,
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
        cls.packages = {
            Path(item["expected_json_path"]).stem: read_strict_json(
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
            self.assertEqual(package["automated_judgment"]["state"], "satisfied")
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
        _, inventory, _ = load_authority(ROOT)
        expected = [(item["tool_id"], item["version"]) for item in inventory["tools"]]
        for package in self.packages.values():
            self.assertEqual(
                [
                    (item["tool_id"], item["version"])
                    for item in package["external_tool_inventory"]
                ],
                expected,
            )
            required = {
                record["tool"]["name"]: record["execution"]["required"]
                for record in package["evidence_records"]
            }
            self.assertTrue(required["PMAE-CI-PIPELINE-V0-1"])
            self.assertTrue(required["PMAE-CONFORMANCE-RUNNER-V0-1"])
            self.assertFalse(required["PMAE-FORMAL-TOOL-V0-1"])

    def test_markdown_is_generated_from_json_and_states_boundaries(self) -> None:
        package = self.packages["success"]
        markdown = render_markdown(package)
        self.assertEqual(markdown, (FIXTURE_ROOT / "expected/success.md").read_text())
        for status in ("pass", "fail", "skip", "unsupported", "timeout", "tool-error"):
            self.assertIn(f"| {status} |", markdown)
        self.assertIn("not a security proof oracle", markdown)
        self.assertIn("not a certification authority", markdown)
        self.assertIn("not human approval or publication approval", markdown)

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
            FIXTURE_ROOT / "expected/success.json", max_bytes=2_097_152
        )

    def _producer(self, mutate) -> dict:
        value = copy.deepcopy(self.success)
        mutate(value)
        value["package_digest"] = artifact_digest(
            PRODUCER_PACKAGE_DOMAIN, value, "package_digest"
        )
        return value

    def _result(self, mutate) -> dict:
        value = copy.deepcopy(self.success_expected)
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
            "json_semantic_digest": artifact_digest(
                JSON_REPORT_DOMAIN,
                {**report, "json_semantic_digest": "unused"},
                "json_semantic_digest",
            ),
            "markdown_semantic_digest": artifact_digest(
                MARKDOWN_REPORT_DOMAIN,
                {**report, "markdown_semantic_digest": "unused"},
                "markdown_semantic_digest",
            ),
        }
        value["package_digest"] = artifact_digest(
            ASSURANCE_PACKAGE_DOMAIN, value, "package_digest"
        )
        return value

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
                "version", "9.9.9"
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
                    output_root=input_root / "out",
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
                        output_root=output,
                        mode="fixture-test",
                    )
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(temp).glob(".final.partial-*")), [])

    def test_cli_failure_is_bounded_and_does_not_emit_exception_detail(self) -> None:
        arguments = [
            "--profile",
            "profiles/private-match-ae-assurance.v0.1.json",
            "--input-root",
            str(FIXTURE_ROOT),
            "--input",
            "input/success.json",
            "--output-root",
            str(ROOT / ".codex-local/tmp/never-created-output"),
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
        fabricated = copy.deepcopy(self.success_expected)
        fabricated["human_approval"]["state"] = "approved"
        fabricated["human_approval"]["reviewer_role"] = "authorized-human"
        fabricated["human_approval"]["reviewer_identity_verified"] = True
        with self.assertRaises(AssuranceIntegrationError):
            validate_package(ROOT, fabricated)
        live = copy.deepcopy(self.success_expected)
        live["execution_mode"] = "private-candidate"
        live["artifact_status"] = "private-candidate"
        live["human_approval"]["state"] = "approved"
        live["human_approval"]["reviewer_role"] = "authorized-human"
        live["human_approval"]["reviewer_identity_verified"] = True
        with self.assertRaises(AssuranceIntegrationError):
            validate_package(ROOT, live)
        with self.assertRaisesRegex(AssuranceIntegrationError, "cannot override"):
            validate_judgment_approval_boundary("blocked", "approved")

    def test_private_candidate_runner_never_creates_human_approval(self) -> None:
        candidate = copy.deepcopy(self.success)
        candidate["mode"] = "private-candidate"
        candidate["artifact_status"] = "private-candidate"
        candidate["package_digest"] = artifact_digest(
            PRODUCER_PACKAGE_DOMAIN, candidate, "package_digest"
        )
        with self.assertRaises(AssuranceIntegrationError):
            validate_producer_package(ROOT, candidate, self.inventory, self.profile)
        for record in candidate["records"]:
            record["test_only"] = False
            record["retention_classification"] = "private-assurance-retained"
        candidate["package_digest"] = artifact_digest(
            PRODUCER_PACKAGE_DOMAIN, candidate, "package_digest"
        )
        with tempfile.TemporaryDirectory(dir=ROOT / ".codex-local/tmp") as temp:
            package = build_assurance_package(ROOT, candidate, Path(temp))
        self.assertEqual(package["execution_mode"], "private-candidate")
        self.assertEqual(package["human_approval"]["state"], "required-not-provided")
        self.assertFalse(package["human_approval"]["reviewer_identity_verified"])
        self.assertFalse(package["lifecycle_boundary"]["public_export_eligible"])
        validate_package(ROOT, package)

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
