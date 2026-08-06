from __future__ import annotations

import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts.canonical_json import (
    CanonicalJSONError,
    canonicalize,
    domain_digest,
    file_digest,
    strict_loads,
)
from scripts.public_release import (
    ALGORITHM,
    EXPECTED_BUNDLE_PATH,
    EXPECTED_STATUS_CHAINS_PATH,
    EXPECTED_VERIFICATION_RESULTS_PATH,
    MANIFEST_PATH,
    NEGATIVE_FIXTURE_CASES,
    OUTPUT_SET_DOMAIN,
    OUTPUT_SET_PATH,
    RELEASE_ENVELOPE_PATH,
    RELEASE_KEY_ID,
    RELEASE_PAYLOAD_TYPE,
    REPORT_JSON_PATH,
    REPORT_MD_PATH,
    STATUS_ENVELOPE_PATH,
    STATUS_KEY_ID,
    STATUS_SET_DOMAIN,
    STATUS_SET_PATH,
    STATUS_CHAIN_MANIFEST_PATH,
    STATUS_CHAIN_MANIFEST_DOMAIN,
    STATUS_CHAIN_OUTPUT_SET_PATH,
    STATUS_CHAIN_TREE_DOMAIN,
    STATUS_CHAIN_VARIANTS,
    TRUST_ROOT_PATH,
    VERIFICATION_TIME,
    PublicReleaseError,
    _run_crypto,
    build_fixture_catalog,
    build_output_set_from_directory,
    build_release_manifest,
    build_report_model,
    build_status_set,
    build_status_chain_output_set,
    create_public_release_process_scratch,
    detached_digest,
    detached_jcs_sha256,
    dsse_pae,
    finalize_status_set,
    generate_fixture_bundle,
    generate_fixture_suite,
    generate_status_chain,
    load_public_release_schemas,
    load_release_authority,
    public_release_process_scratch,
    render_verification_markdown,
    render_content_markdown,
    sign_fixture_dsse,
    validate_fixture_catalog,
    validate_fixture_private_key_boundary,
    validate_trust_root,
    verify_public_release_bundle,
    verify_rfc8032_vector,
)
from scripts.public_release_implementation import build_manifest, validate_manifest


ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT / ".codex-local" / "tmp"


def load_json(path: Path) -> dict:
    return strict_loads(path.read_bytes(), max_bytes=8 * 1024 * 1024)


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonicalize(value))


class PublicReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        SCRATCH.mkdir(parents=True, exist_ok=True)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="issue6-test-", dir=SCRATCH)
        self.temp_root = Path(self.temp.name)
        self.bundle = self.temp_root / "bundle"
        shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
        self.status_chain = self.temp_root / "status-chain"
        shutil.copytree(
            ROOT / EXPECTED_STATUS_CHAINS_PATH / "active", self.status_chain
        )
        self.trust = self.temp_root / "trust.json"
        shutil.copy2(ROOT / TRUST_ROOT_PATH, self.trust)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def verify(self, *, trust: Path | None = None) -> tuple[dict, int]:
        return verify_public_release_bundle(
            ROOT,
            self.bundle,
            trust or self.trust,
            self.status_chain,
            VERIFICATION_TIME,
        )

    def refresh_output_set(self) -> None:
        (self.bundle / OUTPUT_SET_PATH).unlink(missing_ok=True)
        output = build_output_set_from_directory(self.bundle)
        write_json(self.bundle / OUTPUT_SET_PATH, output)

    def refresh_status_chain_output_set(self) -> None:
        (self.status_chain / STATUS_CHAIN_OUTPUT_SET_PATH).unlink(missing_ok=True)
        output = build_status_chain_output_set(self.status_chain)
        write_json(self.status_chain / STATUS_CHAIN_OUTPUT_SET_PATH, output)

    def redigest_status_chain(self) -> None:
        chain = load_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH)
        tree = []
        for entry in chain["revisions"]:
            status_path = self.status_chain / entry["status_set_path"]
            signature_path = self.status_chain / entry["status_signature_path"]
            status = load_json(status_path)
            entry.update(
                {
                    "revision": status["revision"],
                    "generated_at": status["generated_at"],
                    "status_set_digest": status["status_set_digest"],
                    "status_set_file_digest": file_digest(status_path.read_bytes()),
                    "status_signature_digest": file_digest(signature_path.read_bytes()),
                    "previous_status_set_digest": status["previous_status_set_digest"],
                }
            )
            for path, role in (
                (status_path, "status-set"),
                (signature_path, "status-signature"),
            ):
                raw = path.read_bytes()
                tree.append(
                    {
                        "path": path.relative_to(self.status_chain).as_posix(),
                        "file_digest": file_digest(raw),
                        "size": len(raw),
                        "role": role,
                    }
                )
        latest = load_json(
            self.status_chain / chain["revisions"][-1]["status_set_path"]
        )
        chain["latest_revision"] = latest["revision"]
        chain["latest_status_set_digest"] = latest["status_set_digest"]
        chain["generated_at"] = latest["generated_at"]
        chain["chain_tree_digest"] = domain_digest(
            STATUS_CHAIN_TREE_DOMAIN, sorted(tree, key=lambda item: item["path"])
        )
        chain["chain_manifest_digest"] = detached_digest(
            STATUS_CHAIN_MANIFEST_DOMAIN, chain, "chain_manifest_digest"
        )
        write_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH, chain)
        self.refresh_status_chain_output_set()

    def use_status_chain(self, variant: str) -> None:
        shutil.rmtree(self.status_chain)
        shutil.copytree(ROOT / EXPECTED_STATUS_CHAINS_PATH / variant, self.status_chain)

    def resign_status_revision(self, revision: int) -> dict:
        relative = f"revisions/{revision:04d}"
        path = self.status_chain / relative / "public-release-status-set.v0.1.json"
        envelope_path = (
            self.status_chain / relative / "public-release-status-set.dsse.v0.1.json"
        )
        status = load_json(path)
        entries = status["key_statuses"] + status["release_statuses"]
        status["entry_set_digest"] = domain_digest(
            "private-match-public-release-status-entry-set/v0.1", entries
        )
        status["status_set_digest"] = detached_digest(
            STATUS_SET_DOMAIN, status, "status_set_digest"
        )
        write_json(path, status)
        write_json(
            envelope_path,
            sign_fixture_dsse(
                ROOT,
                "application/vnd.itdo.private-match.assurance-release-status-set.v0.1+json",
                canonicalize(status),
                "release-status-signing",
            ),
        )
        return status

    def redigest_chain_manifest_only(self) -> None:
        chain = load_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH)
        chain["chain_manifest_digest"] = detached_digest(
            STATUS_CHAIN_MANIFEST_DOMAIN, chain, "chain_manifest_digest"
        )
        write_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH, chain)
        self.refresh_status_chain_output_set()

    def records_and_artifacts(self) -> tuple[dict, dict]:
        records = {}
        artifacts = {}
        manifest = load_json(self.bundle / MANIFEST_PATH)
        for entry in manifest["content_files"]:
            value = load_json(self.bundle / entry["path"])
            if entry["path"].startswith("records/"):
                records[value["id"]] = value
            else:
                artifacts[entry["path"]] = value
        return records, artifacts

    def regenerate_active_chain(self, manifest_digest: str) -> None:
        shutil.rmtree(self.status_chain)
        generate_status_chain(
            ROOT,
            self.temp_root,
            "status-chain",
            manifest_digest,
            "active",
        )

    def regenerate_from_content(self) -> None:
        records, artifacts = self.records_and_artifacts()
        report_model = build_report_model(ROOT, records, artifacts)
        manifest = build_release_manifest(ROOT, records, artifacts, report_model)
        write_json(self.bundle / MANIFEST_PATH, manifest)
        write_json(
            self.bundle / RELEASE_ENVELOPE_PATH,
            sign_fixture_dsse(
                ROOT, RELEASE_PAYLOAD_TYPE, canonicalize(manifest), "release-signing"
            ),
        )
        write_json(self.bundle / REPORT_JSON_PATH, report_model)
        (self.bundle / REPORT_MD_PATH).write_bytes(
            render_content_markdown(report_model)
        )
        self.refresh_output_set()
        self.regenerate_active_chain(manifest["manifest_digest"])

    def mutate_manifest_and_resign(self, mutate) -> None:
        manifest = load_json(self.bundle / MANIFEST_PATH)
        mutate(manifest)
        manifest["manifest_digest"] = detached_jcs_sha256(manifest, "manifest_digest")
        write_json(self.bundle / MANIFEST_PATH, manifest)
        write_json(
            self.bundle / RELEASE_ENVELOPE_PATH,
            sign_fixture_dsse(
                ROOT, RELEASE_PAYLOAD_TYPE, canonicalize(manifest), "release-signing"
            ),
        )
        records, artifacts = self.records_and_artifacts()
        model = build_report_model(ROOT, records, artifacts)
        write_json(self.bundle / REPORT_JSON_PATH, model)
        (self.bundle / REPORT_MD_PATH).write_bytes(render_content_markdown(model))
        self.refresh_output_set()
        self.regenerate_active_chain(manifest["manifest_digest"])

    def write_resigned_manifest_only(self, manifest: dict) -> None:
        manifest["manifest_digest"] = detached_jcs_sha256(manifest, "manifest_digest")
        write_json(self.bundle / MANIFEST_PATH, manifest)
        write_json(
            self.bundle / RELEASE_ENVELOPE_PATH,
            sign_fixture_dsse(
                ROOT,
                RELEASE_PAYLOAD_TYPE,
                canonicalize(manifest),
                "release-signing",
            ),
        )
        self.refresh_output_set()

    def set_status(
        self,
        state: str = "active",
        key_status: str = "active",
        *,
        replacement: bool = False,
        notice: bool = False,
    ) -> None:
        manifest = load_json(self.bundle / MANIFEST_PATH)
        status = finalize_status_set(
            build_status_set(
                release_state=state,
                release_key_status=key_status,
                release_key_reason=(
                    "fixture-key-compromised"
                    if key_status == "revoked"
                    else "fixture-key-active"
                ),
                replacement_release_id=(
                    "fixture-release-0.2.0" if replacement else None
                ),
                replacement_bundle_digest=(
                    "sha256:" + "9a" * 32 if replacement else None
                ),
                notice_digest=("sha256:" + "9b" * 32 if notice else None),
            ),
            manifest["manifest_digest"],
        )
        write_json(self.status_chain / STATUS_SET_PATH, status)
        write_json(
            self.status_chain / STATUS_ENVELOPE_PATH,
            sign_fixture_dsse(
                ROOT,
                "application/vnd.itdo.private-match.assurance-release-status-set.v0.1+json",
                canonicalize(status),
                "release-status-signing",
            ),
        )
        self.redigest_status_chain()

    def test_authority_profiles_and_schemas_validate(self) -> None:
        standards, signing, verification = load_release_authority(ROOT)
        self.assertEqual(standards["standards"][0]["standard_id"], "RFC-8785")
        self.assertEqual(signing["algorithm"], ALGORITHM)
        self.assertEqual(verification["network"], "forbidden")

    def test_implementation_manifest_is_exact_and_mutation_resistant(self) -> None:
        path = ROOT / "manifests/public-release-verifier-implementation.v0.1.json"
        current = load_json(path)
        self.assertEqual(current, build_manifest(ROOT))
        validate_manifest(ROOT, current)
        mutations = (
            lambda value: value["files"].pop(),
            lambda value: value["files"].append(dict(value["files"][0])),
            lambda value: value["files"][0].__setitem__(
                "digest", "sha256:" + "76" * 32
            ),
            lambda value: value["files"][0].__setitem__("path", "../escape"),
            lambda value: value["bindings"].__setitem__(
                "signing_profile_digest", "sha256:" + "77" * 32
            ),
            lambda value: value["bindings"].__setitem__(
                "trust_root_digest", "sha256:" + "78" * 32
            ),
            lambda value: value["bindings"].__setitem__(
                "pnpm_lock_digest", "sha256:" + "79" * 32
            ),
        )
        for mutation in mutations:
            changed = json.loads(json.dumps(current))
            mutation(changed)
            changed["implementation_digest"] = detached_digest(
                "private-match-public-release-verifier-implementation/v0.1",
                changed,
                "implementation_digest",
            )
            with self.assertRaises(PublicReleaseError):
                validate_manifest(ROOT, changed)

    def test_workflow_enforces_fixture_only_offline_release_validation(self) -> None:
        workflow = (ROOT / ".github/workflows/assurance-schema.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("Validate signed public release fixture offline", workflow)
        self.assertIn("HTTP_PROXY: http://127.0.0.1:9", workflow)
        self.assertIn("GITHUB_TOKEN: ''", workflow)
        self.assertIn("public_release_implementation.py --check", workflow)
        self.assertIn("generate_public_release_fixture.py --check", workflow)
        self.assertIn("verify_public_release_bundle.py", workflow)
        self.assertIn("--status-chain-root", workflow)
        self.assertNotIn("--status-set", workflow)
        self.assertIn("fixture-a/status-chains/active", workflow)
        self.assertNotIn("actions/upload-artifact", workflow)
        self.assertNotIn("gh release", workflow)
        self.assertNotIn("permissions:\n  contents: write", workflow)
        self.assertGreaterEqual(len(load_public_release_schemas(ROOT)), 15)

    def test_rfc8032_vector_and_dsse_pae(self) -> None:
        vectors = verify_rfc8032_vector(ROOT)
        self.assertTrue(vectors["verified"])
        self.assertEqual(
            vectors["vectors"],
            ["RFC8032-7.1-TEST-1", "RFC8032-7.1-TEST-2"],
        )
        self.assertEqual(
            dsse_pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world",
        )

    def test_ed25519_fixture_signature_is_deterministic(self) -> None:
        payload = b"fixture payload"
        first = sign_fixture_dsse(
            ROOT, RELEASE_PAYLOAD_TYPE, payload, "release-signing"
        )
        second = sign_fixture_dsse(
            ROOT, RELEASE_PAYLOAD_TYPE, payload, "release-signing"
        )
        self.assertEqual(first, second)
        self.assertEqual(first["signatures"][0]["keyid"], RELEASE_KEY_ID)

    def test_release_and_status_keys_are_separate(self) -> None:
        release = sign_fixture_dsse(ROOT, RELEASE_PAYLOAD_TYPE, b"x", "release-signing")
        status = sign_fixture_dsse(
            ROOT,
            "application/vnd.itdo.private-match.assurance-release-status-set.v0.1+json",
            b"x",
            "release-status-signing",
        )
        self.assertEqual(release["signatures"][0]["keyid"], RELEASE_KEY_ID)
        self.assertEqual(status["signatures"][0]["keyid"], STATUS_KEY_ID)
        self.assertNotEqual(RELEASE_KEY_ID, STATUS_KEY_ID)

    def test_fixture_private_key_allowlist_is_exact(self) -> None:
        validate_fixture_private_key_boundary(ROOT)

    def test_fixture_trust_root_is_external_and_valid(self) -> None:
        trust = load_json(self.trust)
        keys = validate_trust_root(ROOT, trust, load_public_release_schemas(ROOT))
        self.assertEqual(keys[RELEASE_KEY_ID]["usage"], "release-signing")
        self.assertEqual(keys[STATUS_KEY_ID]["usage"], "release-status-signing")
        manifest = load_json(self.bundle / MANIFEST_PATH)
        self.assertNotIn("public_key", json.dumps(manifest))

    def test_valid_active_fixture_verifies(self) -> None:
        result, code = self.verify()
        self.assertEqual(code, 0)
        self.assertEqual(
            result["overall"]["status"], "verified-fixture-with-limitations"
        )
        self.assertTrue(result["release_signature"]["signature_valid"])
        self.assertEqual(result["release_lifecycle"]["state"], "active")

        later_result, later_code = verify_public_release_bundle(
            ROOT,
            self.bundle,
            self.trust,
            self.status_chain,
            "2026-12-01T00:00:00Z",
        )
        self.assertEqual(later_code, 0)
        self.assertEqual(later_result["verification_time"], "2026-12-01T00:00:00Z")

        expired_result, expired_code = verify_public_release_bundle(
            ROOT,
            self.bundle,
            self.trust,
            self.status_chain,
            "2027-08-02T00:00:00Z",
        )
        self.assertEqual(
            (expired_result["overall"]["status"], expired_code),
            ("expired-release", 4),
        )

    def test_claim_support_is_distinct_from_signature(self) -> None:
        result, code = self.verify()
        self.assertEqual(code, 0)
        self.assertTrue(result["release_signature"]["signature_valid"])
        self.assertEqual(
            result["claims"]["status_counts"],
            {
                "supported": 3,
                "supported-with-assumptions": 1,
                "not-supported": 0,
                "not-evaluated": 0,
                "invalid-reference": 0,
            },
        )

    def test_all_evidence_status_counts_remain_visible(self) -> None:
        result, _ = self.verify()
        self.assertEqual(
            result["evidence_status_counts"],
            {
                "pass": 3,
                "fail": 0,
                "skip": 0,
                "unsupported": 1,
                "timeout": 0,
                "tool-error": 0,
            },
        )

    def test_manifest_and_status_payloads_equal_exact_canonical_files(self) -> None:
        for base, payload_path, envelope_path in (
            (self.bundle, MANIFEST_PATH, RELEASE_ENVELOPE_PATH),
            (self.status_chain, STATUS_SET_PATH, STATUS_ENVELOPE_PATH),
        ):
            raw = (base / payload_path).read_bytes()
            self.assertEqual(raw, canonicalize(load_json(base / payload_path)))
            envelope = load_json(base / envelope_path)
            self.assertEqual(base64.b64decode(envelope["payload"]), raw)

    def test_manifest_digest_is_sha256_of_detached_jcs_bytes(self) -> None:
        manifest = load_json(self.bundle / MANIFEST_PATH)
        self.assertEqual(
            manifest["manifest_digest"],
            detached_jcs_sha256(manifest, "manifest_digest"),
        )

    def test_fixture_catalog_matches_expected_bundle(self) -> None:
        catalog = validate_fixture_catalog(ROOT)
        self.assertEqual(len(catalog["negative_cases"]), len(NEGATIVE_FIXTURE_CASES))
        self.assertEqual(len(catalog["status_chains"]), 6)
        self.assertEqual(
            catalog, build_fixture_catalog(ROOT, ROOT / EXPECTED_BUNDLE_PATH)
        )

    def test_generated_fixture_matches_committed_bytes(self) -> None:
        generated = generate_fixture_bundle(ROOT, self.temp_root, "generated")
        expected = ROOT / EXPECTED_BUNDLE_PATH
        actual_tree = {
            p.relative_to(generated).as_posix(): p.read_bytes()
            for p in generated.rglob("*")
            if p.is_file()
        }
        expected_tree = {
            p.relative_to(expected).as_posix(): p.read_bytes()
            for p in expected.rglob("*")
            if p.is_file()
        }
        self.assertEqual(actual_tree, expected_tree)

    def test_generation_twice_is_byte_identical(self) -> None:
        first = generate_fixture_bundle(ROOT, self.temp_root, "first")
        second = generate_fixture_bundle(ROOT, self.temp_root, "second")
        self.assertEqual(
            {
                p.relative_to(first).as_posix(): p.read_bytes()
                for p in first.rglob("*")
                if p.is_file()
            },
            {
                p.relative_to(second).as_posix(): p.read_bytes()
                for p in second.rglob("*")
                if p.is_file()
            },
        )

    def test_complete_fixture_suite_is_deterministic_and_matches_committed(
        self,
    ) -> None:
        first = generate_fixture_suite(ROOT, self.temp_root, "suite-first")
        second = generate_fixture_suite(ROOT, self.temp_root, "suite-second")
        expected = ROOT / "tests/fixtures/public-release/expected"

        def tree(directory: Path) -> dict[str, bytes]:
            return {
                path.relative_to(directory).as_posix(): path.read_bytes()
                for path in sorted(directory.rglob("*"))
                if path.is_file()
            }

        self.assertEqual(tree(first), tree(second))
        self.assertEqual(tree(first), tree(expected))
        self.assertEqual(len(tree(first)), 65)

    def test_immutable_bundle_excludes_status_and_dynamic_results(self) -> None:
        output = load_json(self.bundle / OUTPUT_SET_PATH)
        paths = output["exact_paths"]
        self.assertFalse(any(path.startswith("status/") for path in paths))
        self.assertFalse(any("status-set" in path for path in paths))
        self.assertFalse(any("verification-result" in path for path in paths))
        self.assertNotIn("status_set_digest", output)
        self.assertNotIn("status_signature_digest", output)
        self.assertNotIn("verification_result_digest", output)
        self.assertIn(REPORT_JSON_PATH, paths)
        static = load_json(self.bundle / REPORT_JSON_PATH)
        for dynamic in (
            "verification_time",
            "release_signature",
            "trust",
            "release_lifecycle",
            "overall",
            "status_chain",
        ):
            self.assertNotIn(dynamic, static)

    def test_same_immutable_bundle_supports_all_lifecycle_status_chains(self) -> None:
        immutable = {
            path.relative_to(self.bundle).as_posix(): path.read_bytes()
            for path in self.bundle.rglob("*")
            if path.is_file()
        }
        release_signature = immutable[RELEASE_ENVELOPE_PATH]
        for variant, policy in STATUS_CHAIN_VARIANTS.items():
            with self.subTest(variant=variant):
                self.use_status_chain(variant)
                before = dict(immutable)
                result, code = self.verify()
                after = {
                    path.relative_to(self.bundle).as_posix(): path.read_bytes()
                    for path in self.bundle.rglob("*")
                    if path.is_file()
                }
                self.assertEqual(before, after)
                self.assertEqual(after[RELEASE_ENVELOPE_PATH], release_signature)
                self.assertEqual(
                    result["overall"]["status"], policy["expected_overall"]
                )
                self.assertEqual(code, policy["expected_exit_code"])
                self.assertEqual(
                    result["status_chain"]["latest_revision"],
                    policy["latest_revision"],
                )
                expected_root = ROOT / EXPECTED_VERIFICATION_RESULTS_PATH / variant
                self.assertEqual(
                    canonicalize(result),
                    (
                        expected_root / "public-release-verification-result.v0.1.json"
                    ).read_bytes(),
                )
                self.assertEqual(
                    render_verification_markdown(result),
                    (
                        expected_root / "public-release-verification-result.v0.1.md"
                    ).read_bytes(),
                )

    def test_revisioned_status_chains_have_exact_ordered_digest_closure(self) -> None:
        for variant, policy in STATUS_CHAIN_VARIANTS.items():
            with self.subTest(variant=variant):
                chain_root = ROOT / EXPECTED_STATUS_CHAINS_PATH / variant
                chain = load_json(chain_root / STATUS_CHAIN_MANIFEST_PATH)
                output = load_json(chain_root / STATUS_CHAIN_OUTPUT_SET_PATH)
                self.assertEqual(
                    [entry["revision"] for entry in chain["revisions"]],
                    list(range(1, policy["latest_revision"] + 1)),
                )
                previous = None
                for entry in chain["revisions"]:
                    status = load_json(chain_root / entry["status_set_path"])
                    self.assertEqual(status["previous_status_set_digest"], previous)
                    self.assertEqual(
                        entry["status_set_digest"], status["status_set_digest"]
                    )
                    previous = status["status_set_digest"]
                    self.assertEqual(
                        set(item["key_id"] for item in status["key_statuses"]),
                        {RELEASE_KEY_ID},
                    )
                self.assertEqual(chain["latest_status_set_digest"], previous)
                self.assertEqual(
                    output["chain_manifest_digest"], chain["chain_manifest_digest"]
                )
                self.assertEqual(output["latest_revision"], policy["latest_revision"])

    def test_status_key_authority_is_external_and_not_self_asserted(self) -> None:
        trust = load_json(self.trust)
        status_key = next(
            key for key in trust["keys"] if key["key_id"] == STATUS_KEY_ID
        )
        self.assertEqual(status_key["usage"], "release-status-signing")
        for variant in STATUS_CHAIN_VARIANTS:
            chain = ROOT / EXPECTED_STATUS_CHAINS_PATH / variant
            manifest = load_json(chain / STATUS_CHAIN_MANIFEST_PATH)
            for revision in manifest["revisions"]:
                status = load_json(chain / revision["status_set_path"])
                self.assertNotIn(
                    STATUS_KEY_ID, {entry["key_id"] for entry in status["key_statuses"]}
                )

    def test_status_chain_negative_mutations_fail_closed(self) -> None:
        cases = []

        def run(case_id: str, variant: str, mutation) -> None:
            self.use_status_chain(variant)
            mutation()
            result, code = self.verify()
            cases.append(case_id)
            self.assertNotEqual(code, 0, case_id)
            self.assertNotEqual(
                result["overall"]["status"],
                "verified-fixture-with-limitations",
                case_id,
            )

        def remove_revision_one() -> None:
            (self.status_chain / STATUS_SET_PATH).unlink()

        run("revision-2-without-revision-1", "withdrawn", remove_revision_one)

        for case_id, revision, previous in (
            ("duplicate-revision", 1, None),
            ("revision-gap", 3, None),
            ("revision-rollback", 0, None),
            ("wrong-previous-digest", 2, "sha256:" + "31" * 32),
            ("forked-previous-digest", 2, "sha256:" + "32" * 32),
        ):

            def mutate_status(revision=revision, previous=previous) -> None:
                path = (
                    self.status_chain
                    / "revisions/0002"
                    / "public-release-status-set.v0.1.json"
                )
                status = load_json(path)
                status["revision"] = revision
                if previous is not None:
                    status["previous_status_set_digest"] = previous
                write_json(path, status)
                self.resign_status_revision(2)
                self.redigest_status_chain()

            run(case_id, "withdrawn", mutate_status)

        def nonincreasing_time() -> None:
            path = (
                self.status_chain
                / "revisions/0002"
                / "public-release-status-set.v0.1.json"
            )
            status = load_json(path)
            status["generated_at"] = "2026-08-01T00:00:00Z"
            for entry in status["key_statuses"] + status["release_statuses"]:
                entry["effective_at"] = "2026-08-01T00:00:00Z"
                entry["status_entry_digest"] = detached_digest(
                    "private-match-public-release-status-entry/v0.1",
                    entry,
                    "status_entry_digest",
                )
            write_json(path, status)
            self.resign_status_revision(2)
            self.redigest_status_chain()

        run("non-increasing-generated-at", "withdrawn", nonincreasing_time)

        for case_id, field, value in (
            ("wrong-status-signing-key", "keyid", "sha256:" + "33" * 32),
            ("release-key-signs-status", "keyid", RELEASE_KEY_ID),
            ("unknown-algorithm", "algorithm", "future-signature"),
        ):

            def mutate_envelope(field=field, value=value) -> None:
                path = self.status_chain / STATUS_ENVELOPE_PATH
                envelope = load_json(path)
                if field == "keyid":
                    envelope["signatures"][0][field] = value
                else:
                    envelope["signingProfile"][field] = value
                write_json(path, envelope)
                self.redigest_status_chain()

            run(case_id, "active", mutate_envelope)

        def wrong_trust_domain() -> None:
            chain = load_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH)
            chain["trust_domain_id"] = "different-trust-domain"
            write_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH, chain)
            self.redigest_chain_manifest_only()

        run("wrong-trust-domain", "active", wrong_trust_domain)

        for case_id in (
            "invalid-intermediate-signature",
            "valid-latest-after-invalid-earlier",
        ):

            def mutate_intermediate() -> None:
                path = self.status_chain / STATUS_ENVELOPE_PATH
                envelope = load_json(path)
                raw = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
                raw[0] ^= 1
                envelope["signatures"][0]["sig"] = base64.b64encode(raw).decode()
                write_json(path, envelope)
                self.redigest_status_chain()

            run(case_id, "withdrawn", mutate_intermediate)

        def extra_revision() -> None:
            write_json(
                self.status_chain / "revisions/0003/unlisted.json", {"extra": True}
            )

        run("extra-unlisted-revision", "active", extra_revision)

        def missing_revision() -> None:
            (self.status_chain / STATUS_ENVELOPE_PATH).unlink()

        run("missing-listed-revision", "active", missing_revision)

        def changed_status_bytes() -> None:
            path = self.status_chain / STATUS_SET_PATH
            path.write_bytes(path.read_bytes() + b"\n")

        run("changed-status-bytes", "active", changed_status_bytes)

        def changed_envelope_bytes() -> None:
            path = self.status_chain / STATUS_ENVELOPE_PATH
            path.write_bytes(path.read_bytes() + b"\n")

        run("changed-envelope-bytes", "active", changed_envelope_bytes)

        def manifest_digest_mismatch() -> None:
            chain = load_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH)
            chain["chain_manifest_digest"] = "sha256:" + "41" * 32
            write_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH, chain)
            self.refresh_status_chain_output_set()

        run("chain-manifest-digest-mismatch", "active", manifest_digest_mismatch)

        def tree_digest_mismatch() -> None:
            chain = load_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH)
            chain["chain_tree_digest"] = "sha256:" + "42" * 32
            write_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH, chain)
            self.redigest_chain_manifest_only()

        run("chain-tree-digest-mismatch", "active", tree_digest_mismatch)

        def output_set_mismatch() -> None:
            output = load_json(self.status_chain / STATUS_CHAIN_OUTPUT_SET_PATH)
            output["latest_status_set_digest"] = "sha256:" + "43" * 32
            output["output_set_digest"] = detached_digest(
                "private-match-public-release-status-chain-output-set/v0.1",
                output,
                "output_set_digest",
            )
            write_json(self.status_chain / STATUS_CHAIN_OUTPUT_SET_PATH, output)

        run("chain-output-set-mismatch", "active", output_set_mismatch)

        def latest_revision_mismatch() -> None:
            chain = load_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH)
            chain["latest_revision"] = 1
            write_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH, chain)
            self.redigest_chain_manifest_only()

        run("latest-revision-mismatch", "withdrawn", latest_revision_mismatch)

        def different_release_manifest() -> None:
            path = self.status_chain / STATUS_SET_PATH
            status = load_json(path)
            entry = status["release_statuses"][0]
            entry["bundle_manifest_digest"] = "sha256:" + "44" * 32
            entry["status_entry_digest"] = detached_digest(
                "private-match-public-release-status-entry/v0.1",
                entry,
                "status_entry_digest",
            )
            write_json(path, status)
            self.resign_status_revision(1)
            self.redigest_status_chain()

        run("different-release-manifest", "active", different_release_manifest)

        def status_key_self_authority() -> None:
            path = self.status_chain / STATUS_SET_PATH
            status = load_json(path)
            entry = dict(status["key_statuses"][0])
            entry.update(
                {
                    "key_id": STATUS_KEY_ID,
                    "usage": "release-status-signing",
                    "reason_code": "self-authority",
                }
            )
            entry["status_entry_digest"] = detached_digest(
                "private-match-public-release-status-entry/v0.1",
                entry,
                "status_entry_digest",
            )
            status["key_statuses"].append(entry)
            write_json(path, status)
            self.resign_status_revision(1)
            self.redigest_status_chain()

        run("status-key-self-authority", "active", status_key_self_authority)

        def active_after_revoked() -> None:
            manifest = load_json(self.bundle / MANIFEST_PATH)
            revision_two = load_json(
                self.status_chain / "revisions/0002/public-release-status-set.v0.1.json"
            )
            status = finalize_status_set(
                build_status_set(
                    revision=3,
                    generated_at="2026-08-04T00:00:00Z",
                    previous_status_set_digest=revision_two["status_set_digest"],
                ),
                manifest["manifest_digest"],
            )
            set_path = (
                self.status_chain
                / "revisions/0003"
                / "public-release-status-set.v0.1.json"
            )
            sig_path = (
                self.status_chain
                / "revisions/0003"
                / "public-release-status-set.dsse.v0.1.json"
            )
            write_json(set_path, status)
            write_json(
                sig_path,
                sign_fixture_dsse(
                    ROOT,
                    "application/vnd.itdo.private-match.assurance-release-status-set.v0.1+json",
                    canonicalize(status),
                    "release-status-signing",
                ),
            )
            chain = load_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH)
            chain["revisions"].append(
                {
                    "revision": 3,
                    "generated_at": status["generated_at"],
                    "status_set_path": set_path.relative_to(
                        self.status_chain
                    ).as_posix(),
                    "status_set_digest": status["status_set_digest"],
                    "status_set_file_digest": file_digest(set_path.read_bytes()),
                    "status_signature_path": sig_path.relative_to(
                        self.status_chain
                    ).as_posix(),
                    "status_signature_digest": file_digest(sig_path.read_bytes()),
                    "previous_status_set_digest": status["previous_status_set_digest"],
                }
            )
            write_json(self.status_chain / STATUS_CHAIN_MANIFEST_PATH, chain)
            self.redigest_status_chain()

        run("active-after-revoked", "revoked", active_after_revoked)
        self.assertEqual(len(cases), 24)

    def test_duplicate_and_non_jcs_inputs_fail(self) -> None:
        invalid = [
            b'{"a":1,"a":2}',
            b'{"z":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":Infinity}',
            b'{"a":-0}',
            b'{"a":9007199254740992}',
            b'{"a":"\xed\xa0\x80"}',
            b'{"a":1} trailing',
        ]
        for raw in invalid:
            with self.subTest(raw=raw):
                with self.assertRaises((CanonicalJSONError, UnicodeDecodeError)):
                    value = strict_loads(raw, max_bytes=1024)
                    if raw != canonicalize(value):
                        raise CanonicalJSONError("noncanonical")

    def test_manifest_byte_mutation_fails_signature(self) -> None:
        raw = (self.bundle / MANIFEST_PATH).read_bytes()
        mutated = raw.replace(b'"bundle_revision":1', b'"bundle_revision":2', 1)
        self.assertNotEqual(mutated, raw)
        (self.bundle / MANIFEST_PATH).write_bytes(mutated)
        self.refresh_output_set()
        result, code = self.verify()
        self.assertEqual((result["overall"]["status"], code), ("invalid-signature", 1))

    def test_signature_mutations_fail(self) -> None:
        for mutation in ("truncate", "change", "extra"):
            with self.subTest(mutation=mutation):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                envelope = load_json(self.bundle / RELEASE_ENVELOPE_PATH)
                raw = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
                if mutation == "truncate":
                    raw = raw[:-1]
                elif mutation == "extra":
                    raw.append(0)
                else:
                    raw[0] ^= 1
                envelope["signatures"][0]["sig"] = base64.b64encode(raw).decode()
                write_json(self.bundle / RELEASE_ENVELOPE_PATH, envelope)
                self.refresh_output_set()
                result, code = self.verify()
                self.assertEqual(
                    (result["overall"]["status"], code), ("invalid-signature", 1)
                )

        shutil.rmtree(self.bundle)
        shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
        envelope = load_json(self.bundle / RELEASE_ENVELOPE_PATH)
        envelope["signatures"].append(dict(envelope["signatures"][0]))
        write_json(self.bundle / RELEASE_ENVELOPE_PATH, envelope)
        self.refresh_output_set()
        _, code = self.verify()
        self.assertEqual(code, 1)

    def test_payload_type_and_unknown_algorithm_fail_closed(self) -> None:
        for field, value in (
            ("payloadType", "application/json"),
            ("algorithm", "future-signature"),
        ):
            with self.subTest(field=field):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                envelope = load_json(self.bundle / RELEASE_ENVELOPE_PATH)
                if field == "algorithm":
                    envelope["signingProfile"][field] = value
                else:
                    envelope[field] = value
                write_json(self.bundle / RELEASE_ENVELOPE_PATH, envelope)
                self.refresh_output_set()
                result, code = self.verify()
                self.assertEqual(code, 2)
                self.assertEqual(result["overall"]["status"], "unsupported-algorithm")

    def test_unknown_and_embedded_keys_are_not_trusted(self) -> None:
        envelope = load_json(self.bundle / RELEASE_ENVELOPE_PATH)
        envelope["signatures"][0]["keyid"] = "sha256:" + "55" * 32
        write_json(self.bundle / RELEASE_ENVELOPE_PATH, envelope)
        self.refresh_output_set()
        result, code = self.verify()
        self.assertEqual((result["overall"]["status"], code), ("untrusted-key", 3))

    def test_key_usage_swap_fails_closed(self) -> None:
        trust = load_json(self.trust)
        trust["keys"][0]["usage"] = "release-status-signing"
        trust["trust_root_digest"] = detached_digest(
            "private-match-public-release-trust-root/v0.1", trust, "trust_root_digest"
        )
        write_json(self.trust, trust)
        result, code = self.verify()
        self.assertEqual((result["overall"]["status"], code), ("untrusted-key", 3))

    def test_malformed_spki_and_public_key_digest_fail(self) -> None:
        for mutation in ("spki", "digest"):
            with self.subTest(mutation=mutation):
                shutil.copy2(ROOT / TRUST_ROOT_PATH, self.trust)
                trust = load_json(self.trust)
                if mutation == "spki":
                    trust["keys"][0]["public_key"] = base64.b64encode(b"bad").decode()
                else:
                    trust["keys"][0]["public_key_digest"] = "sha256:" + "44" * 32
                trust["trust_root_digest"] = detached_digest(
                    "private-match-public-release-trust-root/v0.1",
                    trust,
                    "trust_root_digest",
                )
                write_json(self.trust, trust)
                result, code = self.verify()
                self.assertEqual(
                    (result["overall"]["status"], code), ("untrusted-key", 3)
                )

    def test_revoked_key_is_conservative_even_for_earlier_signed_at(self) -> None:
        self.set_status(key_status="revoked")
        result, code = self.verify()
        self.assertEqual((result["overall"]["status"], code), ("revoked-key", 3))

    def test_expired_and_not_yet_valid_trust_keys_fail(self) -> None:
        for field, value in (
            ("valid_until", "2026-08-01T00:00:00Z"),
            ("valid_from", "2026-08-05T00:00:00Z"),
        ):
            with self.subTest(field=field):
                shutil.copy2(ROOT / TRUST_ROOT_PATH, self.trust)
                trust = load_json(self.trust)
                trust["keys"][0][field] = value
                trust["trust_root_digest"] = detached_digest(
                    "private-match-public-release-trust-root/v0.1",
                    trust,
                    "trust_root_digest",
                )
                write_json(self.trust, trust)
                result, code = self.verify()
                self.assertEqual(code, 3)

    def test_invalid_status_signature_fails(self) -> None:
        envelope = load_json(self.status_chain / STATUS_ENVELOPE_PATH)
        sig = bytearray(base64.b64decode(envelope["signatures"][0]["sig"]))
        sig[0] ^= 1
        envelope["signatures"][0]["sig"] = base64.b64encode(sig).decode()
        write_json(self.status_chain / STATUS_ENVELOPE_PATH, envelope)
        self.redigest_status_chain()
        result, code = self.verify()
        self.assertEqual((result["overall"]["status"], code), ("invalid-signature", 1))

    def test_release_key_cannot_sign_status(self) -> None:
        status = load_json(self.status_chain / STATUS_SET_PATH)
        with self.assertRaisesRegex(PublicReleaseError, "key usage"):
            sign_fixture_dsse(
                ROOT,
                "application/vnd.itdo.private-match.assurance-release-status-set.v0.1+json",
                canonicalize(status),
                "release-signing",
            )
        manifest = load_json(self.bundle / MANIFEST_PATH)
        with self.assertRaisesRegex(PublicReleaseError, "key usage"):
            sign_fixture_dsse(
                ROOT,
                RELEASE_PAYLOAD_TYPE,
                canonicalize(manifest),
                "release-status-signing",
            )

    def test_status_chain_and_revision_rollback_fail(self) -> None:
        for revision, previous in ((1, "sha256:" + "11" * 32), (2, None), (0, None)):
            with self.subTest(revision=revision, previous=previous):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                shutil.rmtree(self.status_chain)
                shutil.copytree(
                    ROOT / EXPECTED_STATUS_CHAINS_PATH / "active", self.status_chain
                )
                status = load_json(self.status_chain / STATUS_SET_PATH)
                status["revision"] = revision
                status["previous_status_set_digest"] = previous
                status["status_set_digest"] = detached_digest(
                    STATUS_SET_DOMAIN, status, "status_set_digest"
                )
                write_json(self.status_chain / STATUS_SET_PATH, status)
                write_json(
                    self.status_chain / STATUS_ENVELOPE_PATH,
                    sign_fixture_dsse(
                        ROOT,
                        "application/vnd.itdo.private-match.assurance-release-status-set.v0.1+json",
                        canonicalize(status),
                        "release-status-signing",
                    ),
                )
                self.redigest_status_chain()
                result, code = self.verify()
                self.assertEqual(code, 1)

    def test_status_entry_set_is_closed_and_effective(self) -> None:
        for mutation in ("extra-key", "extra-release", "future-effective"):
            with self.subTest(mutation=mutation):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                shutil.rmtree(self.status_chain)
                shutil.copytree(
                    ROOT / EXPECTED_STATUS_CHAINS_PATH / "active", self.status_chain
                )
                status = load_json(self.status_chain / STATUS_SET_PATH)
                if mutation == "extra-key":
                    extra = dict(status["key_statuses"][0])
                    extra["key_id"] = "sha256:" + "73" * 32
                    extra["status_entry_digest"] = detached_digest(
                        "private-match-public-release-status-entry/v0.1",
                        extra,
                        "status_entry_digest",
                    )
                    status["key_statuses"].append(extra)
                elif mutation == "extra-release":
                    status["release_statuses"].append(
                        dict(status["release_statuses"][0])
                    )
                else:
                    entry = status["release_statuses"][0]
                    entry["effective_at"] = "2026-08-05T00:00:00Z"
                    entry["status_entry_digest"] = detached_digest(
                        "private-match-public-release-status-entry/v0.1",
                        entry,
                        "status_entry_digest",
                    )
                entries = status["key_statuses"] + status["release_statuses"]
                status["entry_set_digest"] = domain_digest(
                    "private-match-public-release-status-entry-set/v0.1", entries
                )
                status["status_set_digest"] = detached_digest(
                    STATUS_SET_DOMAIN, status, "status_set_digest"
                )
                write_json(self.status_chain / STATUS_SET_PATH, status)
                write_json(
                    self.status_chain / STATUS_ENVELOPE_PATH,
                    sign_fixture_dsse(
                        ROOT,
                        "application/vnd.itdo.private-match.assurance-release-status-set.v0.1+json",
                        canonicalize(status),
                        "release-status-signing",
                    ),
                )
                self.redigest_status_chain()
                _, code = self.verify()
                self.assertIn(code, {1, 3})

    def test_lifecycle_states_use_stable_exit_code(self) -> None:
        cases = [
            ("withdrawn", False, True, "withdrawn-release"),
            ("superseded", True, False, "superseded-release"),
            ("corrected", True, False, "corrected-release"),
            ("expired", False, False, "expired-release"),
        ]
        for state, replacement, notice, overall in cases:
            with self.subTest(state=state):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                self.set_status(state, replacement=replacement, notice=notice)
                result, code = self.verify()
                self.assertEqual((result["overall"]["status"], code), (overall, 4))

    def test_expired_manifest_fails_even_with_valid_signature(self) -> None:
        self.mutate_manifest_and_resign(
            lambda manifest: manifest.__setitem__("valid_until", "2026-08-01T00:00:00Z")
        )
        result, code = self.verify()
        self.assertEqual((result["overall"]["status"], code), ("invalid-structure", 1))

    def test_replacement_and_withdrawal_bindings_are_required(self) -> None:
        for state in ("superseded", "corrected", "withdrawn"):
            with self.subTest(state=state):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                self.set_status(state)
                result, code = self.verify()
                self.assertEqual(code, 1)

        for state in ("superseded", "corrected"):
            with self.subTest(state=state, mutation="circular"):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                manifest = load_json(self.bundle / MANIFEST_PATH)
                status = finalize_status_set(
                    build_status_set(
                        release_state=state,
                        replacement_release_id=manifest["release"]["release_id"],
                        replacement_bundle_digest=manifest["manifest_digest"],
                    ),
                    manifest["manifest_digest"],
                )
                write_json(self.status_chain / STATUS_SET_PATH, status)
                write_json(
                    self.status_chain / STATUS_ENVELOPE_PATH,
                    sign_fixture_dsse(
                        ROOT,
                        "application/vnd.itdo.private-match.assurance-release-status-set.v0.1+json",
                        canonicalize(status),
                        "release-status-signing",
                    ),
                )
                self.redigest_status_chain()
                _, code = self.verify()
                self.assertEqual(code, 1)

    def test_missing_and_extra_artifacts_fail_exact_path_closure(self) -> None:
        for mode in ("missing", "extra"):
            with self.subTest(mode=mode):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                if mode == "missing":
                    (self.bundle / "artifacts/sbom.cdx.json").unlink()
                else:
                    write_json(self.bundle / "artifacts/extra.json", {"fixture": True})
                result, code = self.verify()
                self.assertEqual(
                    (result["overall"]["status"], code), ("incomplete-bundle", 1)
                )

        shutil.rmtree(self.bundle)
        shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
        write_json(self.bundle / "records/unlisted.json", {"fixture": True})
        self.refresh_output_set()
        result, code = self.verify()
        self.assertEqual((result["overall"]["status"], code), ("incomplete-bundle", 1))

    def test_manifest_content_paths_fail_closed(self) -> None:
        invalid_paths = (
            "/absolute.json",
            "C:/drive.json",
            "records\\evidence\\bad.json",
            "../escape.json",
            "records/./bad.json",
            "records//bad.json",
        )
        for invalid in invalid_paths:
            with self.subTest(path=invalid):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                manifest = load_json(self.bundle / MANIFEST_PATH)
                manifest["content_files"][0]["path"] = invalid
                self.write_resigned_manifest_only(manifest)
                _, code = self.verify()
                self.assertEqual(code, 1)

        shutil.rmtree(self.bundle)
        shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
        manifest = load_json(self.bundle / MANIFEST_PATH)
        manifest["content_files"][1]["path"] = manifest["content_files"][0]["path"]
        self.write_resigned_manifest_only(manifest)
        _, code = self.verify()
        self.assertEqual(code, 1)

    def test_changed_file_with_redigested_output_set_still_fails(self) -> None:
        artifact = load_json(self.bundle / "artifacts/fixture-release-artifact.json")
        artifact["content"]["fixture"] = False
        write_json(self.bundle / "artifacts/fixture-release-artifact.json", artifact)
        self.refresh_output_set()
        result, code = self.verify()
        self.assertEqual(code, 1)

    def test_fixture_artifacts_fail_after_complete_resigning(self) -> None:
        mutations = (
            (
                "artifacts/sbom.cdx.json",
                lambda value: value.__setitem__("specVersion", "1.5"),
            ),
            (
                "artifacts/build-provenance.v0.1.json",
                lambda value: value["predicate"]["buildDefinition"][
                    "internalParameters"
                ].__setitem__("signed", True),
            ),
            (
                "artifacts/fixture-release-artifact.json",
                lambda value: value["content"].__setitem__("production_data", True),
            ),
        )
        for relative, mutation in mutations:
            with self.subTest(relative=relative):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                path = self.bundle / relative
                value = load_json(path)
                mutation(value)
                write_json(path, value)
                self.regenerate_from_content()
                _, code = self.verify()
                self.assertEqual(code, 1)

    def test_duplicate_record_id_and_subject_mismatch_fail(self) -> None:
        for mutation in ("duplicate-id", "subject"):
            with self.subTest(mutation=mutation):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                if mutation == "duplicate-id":
                    path = self.bundle / "records/claims/pm-claim-6002.json"
                    value = load_json(path)
                    value["id"] = "PM-CLAIM-6001"
                else:
                    path = self.bundle / "records/evidence/pm-evidence-6001.json"
                    value = load_json(path)
                    value["subject"]["digest"] = "sha256:" + "79" * 32
                write_json(path, value)
                self.regenerate_from_content()
                _, code = self.verify()
                self.assertEqual(code, 1)

    def test_manifest_summary_mutations_fail_after_complete_resigning(self) -> None:
        mutations = {
            "protocol": lambda m: m["protocol"].__setitem__(
                "semantic_digest", "sha256:" + "31" * 32
            ),
            "conformance": lambda m: m["conformance"].__setitem__(
                "semantic_digest", "sha256:" + "32" * 32
            ),
            "suite-tree": lambda m: m["conformance"].__setitem__(
                "complete_suite_tree_digest", "sha256:" + "33" * 32
            ),
            "claim-set": lambda m: m["record_sets"].__setitem__(
                "claim_set_digest", "sha256:" + "34" * 32
            ),
            "assumption-set": lambda m: m["record_sets"].__setitem__(
                "assumption_set_digest", "sha256:" + "35" * 32
            ),
            "evidence-set": lambda m: m["record_sets"].__setitem__(
                "evidence_set_digest", "sha256:" + "36" * 32
            ),
            "limitation-set": lambda m: m["record_sets"].__setitem__(
                "limitation_set_digest", "sha256:" + "37" * 32
            ),
            "sbom": lambda m: m["artifacts"]["sbom"].__setitem__(
                "digest", "sha256:" + "38" * 32
            ),
            "provenance": lambda m: m["artifacts"]["build_provenance"].__setitem__(
                "digest", "sha256:" + "39" * 32
            ),
            "report-model": lambda m: m["reports"]["json"].__setitem__(
                "report_model_digest", "sha256:" + "3a" * 32
            ),
            "source": lambda m: m.__setitem__(
                "source_revision_digest", "sha256:" + "3b" * 32
            ),
            "artifact": lambda m: m.__setitem__(
                "release_artifact_digest", "sha256:" + "3c" * 32
            ),
            "export-profile": lambda m: m["export_profile"].__setitem__(
                "digest", "sha256:" + "3d" * 32
            ),
            "assurance-profile": lambda m: m["assurance_profile"].__setitem__(
                "digest", "sha256:" + "3e" * 32
            ),
            "ae-framework": lambda m: m["ae_framework"].__setitem__(
                "pin_digest", "sha256:" + "3f" * 32
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                self.mutate_manifest_and_resign(mutation)
                result, code = self.verify()
                self.assertEqual(code, 1)

    def test_missing_evidence_reference_is_invalid_even_after_full_regeneration(
        self,
    ) -> None:
        claim_path = self.bundle / "records/claims/pm-claim-6001.json"
        claim = load_json(claim_path)
        claim["evidence"] = ["PM-EVIDENCE-6999"]
        write_json(claim_path, claim)
        self.regenerate_from_content()
        result, code = self.verify()
        self.assertEqual(
            (result["overall"]["status"], code), ("claims-not-supported", 5)
        )

    def test_missing_assumption_and_limitation_references_are_invalid(self) -> None:
        cases = (
            ("assumptions", "PM-ASSUMPTION-6999"),
            ("limitations", "PM-LIMITATION-6999"),
        )
        for field, identifier in cases:
            with self.subTest(field=field):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                claim_path = self.bundle / "records/claims/pm-claim-6003.json"
                claim = load_json(claim_path)
                claim[field] = [identifier]
                write_json(claim_path, claim)
                self.regenerate_from_content()
                result, code = self.verify()
                self.assertEqual(
                    (result["overall"]["status"], code),
                    ("claims-not-supported", 5),
                )

    def test_fail_and_unavailable_evidence_do_not_become_supported(self) -> None:
        for status, expected in (
            ("fail", "claims-not-supported"),
            ("unsupported", "not-evaluated"),
            ("skip", "not-evaluated"),
            ("timeout", "not-evaluated"),
            ("tool-error", "not-evaluated"),
        ):
            with self.subTest(status=status):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                path = self.bundle / "records/evidence/pm-evidence-6001.json"
                record = load_json(path)
                record["status"] = status
                if status in {"skip", "unsupported"}:
                    record["execution"] = {
                        "ran": False,
                        "required": True,
                        "reason": "fixture-unavailable",
                    }
                    record["output_digest"] = None
                write_json(path, record)
                self.regenerate_from_content()
                result, code = self.verify()
                self.assertEqual((result["overall"]["status"], code), (expected, 5))

    def test_report_json_and_markdown_mutations_fail_after_output_redigest(
        self,
    ) -> None:
        for relative in (REPORT_JSON_PATH, REPORT_MD_PATH):
            with self.subTest(relative=relative):
                shutil.rmtree(self.bundle)
                shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, self.bundle)
                path = self.bundle / relative
                if relative.endswith(".json"):
                    report = load_json(path)
                    report["limitations"][0] = "Changed fixture limitation."
                    write_json(path, report)
                else:
                    path.write_bytes(path.read_bytes() + b"changed\n")
                self.refresh_output_set()
                result, code = self.verify()
                self.assertEqual(
                    (result["overall"]["status"], code), ("invalid-report-linkage", 1)
                )

    def test_output_set_mutations_fail(self) -> None:
        output = load_json(self.bundle / OUTPUT_SET_PATH)
        output["files"][0]["file_digest"] = "sha256:" + "77" * 32
        output["output_set_digest"] = detached_digest(
            OUTPUT_SET_DOMAIN, output, "output_set_digest"
        )
        write_json(self.bundle / OUTPUT_SET_PATH, output)
        result, code = self.verify()
        self.assertEqual(code, 1)

    def test_symlinked_file_and_directory_fail(self) -> None:
        outside = self.temp_root / "outside.json"
        outside.write_text("{}", encoding="utf-8")
        target = self.bundle / "artifacts/sbom.cdx.json"
        target.unlink()
        target.symlink_to(outside)
        result, code = self.verify()
        self.assertEqual(code, 1)
        self.assertEqual(outside.read_text(encoding="utf-8"), "{}")

        linked_bundle = self.temp_root / "linked-bundle"
        linked_bundle.symlink_to(self.bundle, target_is_directory=True)
        result, code = verify_public_release_bundle(
            ROOT,
            linked_bundle,
            self.trust,
            self.status_chain,
            VERIFICATION_TIME,
        )
        self.assertEqual((result["overall"]["status"], code), ("invalid-structure", 1))

        linked_chain = self.temp_root / "linked-chain"
        linked_chain.symlink_to(self.status_chain, target_is_directory=True)
        result, code = verify_public_release_bundle(
            ROOT, self.bundle, self.trust, linked_chain, VERIFICATION_TIME
        )
        self.assertEqual((result["overall"]["status"], code), ("invalid-structure", 1))

        outside_status = self.temp_root / "outside-status.json"
        original = (self.status_chain / STATUS_SET_PATH).read_bytes()
        outside_status.write_bytes(original)
        status_path = self.status_chain / STATUS_SET_PATH
        status_path.unlink()
        status_path.symlink_to(outside_status)
        result, code = self.verify()
        self.assertEqual((result["overall"]["status"], code), ("invalid-structure", 1))
        self.assertEqual(outside_status.read_bytes(), original)

        real_parent = self.temp_root / "real-parent"
        real_parent.mkdir()
        shutil.copytree(ROOT / EXPECTED_BUNDLE_PATH, real_parent / "bundle")
        linked_parent = self.temp_root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        result, code = verify_public_release_bundle(
            ROOT,
            linked_parent / "bundle",
            self.trust,
            self.status_chain,
            VERIFICATION_TIME,
        )
        self.assertEqual((result["overall"]["status"], code), ("invalid-structure", 1))

    def test_process_scratch_parent_symlinks_fail_without_external_side_effect(
        self,
    ) -> None:
        for symlink_level in ("local", "tmp"):
            with self.subTest(symlink_level=symlink_level):
                fake_root = self.temp_root / f"repo-{symlink_level}"
                outside = self.temp_root / f"outside-{symlink_level}"
                fake_root.mkdir()
                outside.mkdir()
                sentinel = outside / "sentinel"
                sentinel.write_text("unchanged", encoding="utf-8")
                if symlink_level == "local":
                    (fake_root / ".codex-local").symlink_to(
                        outside, target_is_directory=True
                    )
                else:
                    local = fake_root / ".codex-local"
                    local.mkdir()
                    (local / "tmp").symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(
                    PublicReleaseError, "scratch hierarchy is not trusted"
                ):
                    create_public_release_process_scratch(fake_root)
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")
                self.assertEqual(
                    sorted(path.name for path in outside.iterdir()), ["sentinel"]
                )

    def test_process_scratch_is_unique_private_and_always_removed(self) -> None:
        fake_root = self.temp_root / "scratch-repo"
        fake_root.mkdir()
        first = create_public_release_process_scratch(fake_root)
        second = create_public_release_process_scratch(fake_root)
        self.assertNotEqual(first, second)
        if sys.platform != "win32":
            self.assertEqual(first.stat().st_mode & 0o777, 0o700)
            self.assertEqual(second.stat().st_mode & 0o777, 0o700)
        shutil.rmtree(first)
        shutil.rmtree(second)
        success_path = None
        with public_release_process_scratch(fake_root) as process:
            success_path = process
            self.assertTrue(process.is_dir())
        self.assertFalse(success_path.exists())
        failure_path = None
        with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
            with public_release_process_scratch(fake_root) as process:
                failure_path = process
                raise RuntimeError("synthetic failure")
        self.assertFalse(failure_path.exists())

    def test_generator_rejects_existing_target_and_cleans_partial(self) -> None:
        existing = self.temp_root / "existing"
        existing.mkdir()
        with self.assertRaises(Exception):
            generate_fixture_bundle(ROOT, self.temp_root, "existing")
        self.assertFalse((self.temp_root / "existing.partial").exists())

    def test_crypto_timeout_and_process_failure_are_bounded(self) -> None:
        with (
            mock.patch(
                "scripts.public_release._node_executable", return_value="/usr/bin/node"
            ),
            mock.patch(
                "scripts.public_release.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["node"], 1),
            ),
        ):
            with self.assertRaisesRegex(
                PublicReleaseError, "fixture crypto operation failed"
            ):
                _run_crypto(ROOT, "rfc8032-test")
        failure = subprocess.CompletedProcess(
            ["node"], 1, stdout=b"private-value", stderr=b"private-error"
        )
        with (
            mock.patch(
                "scripts.public_release._node_executable", return_value="/usr/bin/node"
            ),
            mock.patch("scripts.public_release.subprocess.run", return_value=failure),
        ):
            with self.assertRaises(PublicReleaseError) as captured:
                _run_crypto(ROOT, "rfc8032-test")
        self.assertEqual(str(captured.exception), "fixture crypto operation failed")
        self.assertNotIn("private-value", str(captured.exception))

    def test_no_private_key_or_private_path_appears_in_bundle(self) -> None:
        combined = b"\n".join(
            p.read_bytes() for p in self.bundle.rglob("*") if p.is_file()
        )
        self.assertNotIn(b"BEGIN PRIVATE KEY", combined)
        self.assertNotIn(str(ROOT).encode(), combined)
        self.assertNotIn(b"private-match-product", combined)
        self.assertNotIn(b"customer", combined.lower())

    def test_cli_requires_explicit_verification_time_and_outputs(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                "scripts/verify_public_release_bundle.py",
                "--bundle-root",
                str(self.bundle),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_cli_valid_fixture_outputs_are_deterministic(self) -> None:
        outputs = []
        for index in range(2):
            output_json = self.temp_root / f"result-{index}.json"
            output_md = self.temp_root / f"result-{index}.md"
            result = subprocess.run(
                [
                    sys.executable,
                    "scripts/verify_public_release_bundle.py",
                    "--bundle-root",
                    str(self.bundle),
                    "--trust-root",
                    str(self.trust),
                    "--status-chain-root",
                    str(self.status_chain),
                    "--verification-time",
                    VERIFICATION_TIME,
                    "--output-json",
                    str(output_json),
                    "--output-md",
                    str(output_md),
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            outputs.append((output_json.read_bytes(), output_md.read_bytes()))
        self.assertEqual(outputs[0], outputs[1])

    def test_cli_output_symlink_failure_has_no_external_side_effect(self) -> None:
        outside = self.temp_root / "outside-output"
        outside.mkdir()
        sentinel = outside / "sentinel"
        sentinel.write_text("unchanged", encoding="utf-8")
        linked_parent = self.temp_root / "linked-output"
        linked_parent.symlink_to(outside, target_is_directory=True)
        output_json = self.temp_root / "result.json"
        result = subprocess.run(
            [
                sys.executable,
                "scripts/verify_public_release_bundle.py",
                "--bundle-root",
                str(self.bundle),
                "--trust-root",
                str(self.trust),
                "--status-chain-root",
                str(self.status_chain),
                "--verification-time",
                VERIFICATION_TIME,
                "--output-json",
                str(output_json),
                "--output-md",
                str(linked_parent / "result.md"),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output_json.exists())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")
        self.assertEqual(sorted(path.name for path in outside.iterdir()), ["sentinel"])
        self.assertNotIn(str(outside), result.stderr.decode("utf-8"))

    def test_fixture_signer_rejects_arbitrary_input(self) -> None:
        output = self.temp_root / "signature.json"
        result = subprocess.run(
            [
                sys.executable,
                "scripts/sign_public_release_fixture.py",
                "--usage",
                "release-signing",
                "--input",
                "README.md",
                "--output",
                str(output),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
