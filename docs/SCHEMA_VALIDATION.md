# Assurance Schema Validation

## Scope

The schema-validation lane defines machine-readable structure and consistency checks for six public assurance record classes:

- claim
- assumption
- evidence item
- evidence manifest
- known limitation
- correction or withdrawal notice

The lane verifies representation and linkage. It does not determine whether a security, privacy, correctness, market, or legal claim is scientifically true.

## Commands

Install the hash-locked build backend and validation dependencies:

```bash
python -m pip install --require-hashes -r requirements-build.txt
python -m pip install --require-hashes --no-build-isolation -r requirements-dev.txt
```

The supported public CI target is CPython 3.12 on GitHub-hosted Ubuntu x86-64.
`requirements-build.txt` includes the build backend; `requirements-dev.txt`
contains direct and transitive validation dependencies with hashes. Regenerate
the development lock from `requirements-dev.in` with the reviewed `uv` release:

```console
uv pip compile \
  --python-version 3.12 \
  --python-platform x86_64-unknown-linux-gnu \
  --generate-hashes \
  requirements-dev.in \
  --output-file requirements-dev.txt
```

Run the command twice and require byte-identical output before review. A lock
renewal must recheck dependency versions, licenses, hashes, Python support, and
RFC 8785 vectors. Other Python versions and platforms are not claimed by this
lock; create and review a separate platform lock rather than weakening
`--require-hashes`.

Run regression tests:

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

Install the exact Node runtime dependencies and validate the ae-framework
integration closure and deterministic fixtures:

```bash
corepack enable
corepack prepare pnpm@10.34.5 --activate
pnpm install --frozen-lockfile
python scripts/ae_framework_manifest.py --check
python scripts/ae_assurance_implementation.py --check
python scripts/validate_ae_assurance.py
python scripts/generate_ae_assurance_fixtures.py --check
```

The supported target is Node.js 22.22.2. The lock contains the exact Ajv,
Ajv-formats, and YAML dependencies required by the unmodified reviewed
ae-framework command. Fixture checks execute every catalog entry twice and
compare exact JSON, Markdown, and detached output-set bytes. Output-set
validation binds the renderer and requires the exact three-file directory.
Private-candidate contract tests use only ephemeral synthetic digest metadata
under an existing trusted output root. They do not run the public exporter or
use live/private Product input.

Stored Assurance-package validation first revalidates the exact embedded
producer package and its detached digest, then rederives Evidence records and
references, inventories, validation provenance, gates, status counts, producer
judgment, and the native manifest through the same mapping used by generation.
It reruns the exact pinned ae-framework command in a process-owned, private
system temporary directory; it never creates or follows repository-local
`.codex-local/tmp`, and cleanup occurs on every success and failure path. A
self-declared Evidence or native projection is not accepted as authority.
Validation also requires the closed Protocol/conformance authority
for every producer record and the suite digest at index 0 of every exact
five-element Evidence input-digest surface, the proof-check-only
formal mapping, and exact timestamp ordering
`started_at <= completed_at <= created_at <= validated_at`. This is explicitly
a producer-supplied, digest-bound assertion, not the current runner execution
time. The native CLI receives it only as a deterministic reference required by
the pinned interface. Runner validation is separately recorded as performed
with no wall-clock timestamp in deterministic output; neither timestamp
surface is external attestation.

Previously generated Draft 0.1 Assurance packages without
`input_producer_package` intentionally fail the corrected closed Schema. They
must be regenerated from the original producer package. The embedded object is
safe metadata under the existing producer Schema; it is not proof that the
producer-supplied metadata is externally authentic.

Validate the signed public fixture authorities, exact implementation manifest,
RFC 8032 vector, key allowlist, deterministic bytes, DSSE signatures, external
trust root, immutable content report, external revisioned status chains, claim
policy, dynamic verifier results, and both output-set closures:

```bash
python scripts/public_release_implementation.py --check
python scripts/generate_public_release_fixture.py --check
python scripts/validate_public_release.py
python -m unittest tests.test_public_release
```

All signed-bundle JSON is strict UTF-8 and exact RFC 8785 JCS. The offline
verifier requires a caller-supplied canonical UTC time, explicit trust root,
and one closed external status-chain root. It rejects duplicate keys,
noncanonical bytes, symlinks, extra/missing
paths, stale digests, unsupported algorithms, untrusted or revoked keys,
invalid lifecycle state, inconsistent reports, and unsupported claim
references. The JSON verification result is authoritative; bounded stderr is
not Evidence.

Validate repository assurance records:

```bash
python scripts/validate_assurance.py \
  --root . \
  --report-dir artifacts
```

Generated reports:

- `artifacts/assurance-schema-report.json`
- `artifacts/assurance-schema-report.md`

## Record locations

Published or publication-candidate records should be stored under:

```text
assurance/claims/
assurance/assumptions/
assurance/evidence/
assurance/manifests/
assurance/limitations/
assurance/notices/
```

Validation selects the schema from `record_type`, not only the directory name.

## Evidence status

Evidence status is one of:

```text
pass
fail
skip
unsupported
timeout
tool-error
```

The states are not interchangeable.

- `pass` and `fail` require that the check ran and produced an output digest.
- `skip` and `unsupported` require `execution.ran: false` and a reason.
- `timeout` and `tool-error` remain visible and must not be rewritten as pass.

Evidence lifecycle is a separate field:

```text
collected
validated
sanitized
published
superseded
withdrawn
```

`lifecycle_history` is a non-empty, append-only transition log. It starts at
`collected`, ends at the current `lifecycle`, uses ordered timestamps, and records a
review digest for every transition after collection. Lifecycle changes never rewrite
the historical check-result `status`. Superseded or withdrawn evidence cannot support
an active claim.

## Type-specific evidence

Conformance evidence must name both the protocol identifier/version and conformance-suite
identifier/version in `configuration`.

Model-check evidence must provide typed `model_check` data containing:

- checked properties
- non-empty integer-range or finite-set state-space parameters
- constraints and configured depth/state limits
- generated and distinct state counts
- explored maximum depth
- whether exploration completed within the declared bounds

Evidence of every other type uses `model_check: null`.

The public export profile adds a separate closed configuration contract for
the exportable `test`, `conformance`, `model-check`, `provenance`, and `review`
types. The profile binds each type to the configuration contract ID, version,
and Schema digest. Nested unknown fields, wrong scalar types, malformed
identifier/version objects, and unlisted Evidence types are rejected. This
does not change the open `configuration` field in the general Evidence Schema
0.1 or reinterpret existing repository records.

Evidence offered to the public exporter must already be `validated`, or be
`sanitized` with an exact matching final sanitization event. General Evidence
may still exist at `collected`, but the exporter returns
`lifecycle-not-validated` and never synthesizes the missing validation event.

`private_source_metadata` is either null or a digest-bound allowlisted object. It cannot contain
repository names or URLs, hostnames, account identifiers, filesystem paths, or other private
locators.

## Manifest publication and digests

Manifest `evidence_record_digests` identify canonical complete Evidence records.
`evidence_output_digests` separately identify the output artifacts referenced by those records.
The validator checks the record-digest count and exact output-digest set for available records.

A manifest with `publication.status: published` requires an explicit approved human
`publication` review entry. CI cannot create or infer that approval.

## Claim status

Claim status is one of:

```text
draft
supported
supported-with-assumptions
not-supported
expired
withdrawn
```

Schema conditions require:

- `supported` and `supported-with-assumptions` to reference evidence
- `supported` to reference zero assumptions
- `supported-with-assumptions` to reference at least one assumption
- `expired` and `withdrawn` to include a non-empty status reason

`supported` is unconditional only within the signed Claim's declared scope.
`supported-with-assumptions` is the only positive state that may reference an
Assumption. The validator does not rewrite either state to repair an
inconsistent reference list; such a signed record fails structure validation,
even if its enclosing manifest and DSSE signature are otherwise valid.

## Semantic validation

The validator adds checks that are difficult or undesirable to express only in JSON Schema:

- evidence `completed_at` must not precede `started_at`
- claim `valid_until` must not precede `valid_from`
- assumption and limitation review dates must be ordered
- IDs must be unique within the validated record set
- claim, manifest, limitation, and notice references must resolve to records of the correct type
- invalid lifecycle transitions and unordered lifecycle history fail
- model-check range, state-count, and depth relationships are bounded
- active claims cannot rely on superseded or withdrawn Evidence records
- manifest Evidence-record digest counts and output-digest sets must match references
- published manifests require explicit human publication approval

## Fixtures

`tests/fixtures/valid/minimum.json` contains minimum valid examples for every record class.

`tests/fixtures/valid/complete.json` contains a linked fixture set with:

- one claim
- one assumption
- one conformance evidence item
- one bounded model-check evidence item
- one known limitation
- one notice
- one evidence manifest

`tests/fixtures/invalid/cases.json` covers:

- missing provenance
- invalid evidence status
- missing subject version
- inconsistent time range
- pass without output digest
- skipped execution represented as pass
- expired claim without reason
- withdrawn claim without reason
- model-check evidence without typed bounds/results
- conformance evidence without protocol/suite versions
- invalid lifecycle transitions
- unsafe private-source locator fields
- a published manifest without human publication approval

## Schema compatibility

Schema version `0.1` is experimental.

The positive Claim/Assumption invariant is corrected within `0.1` because the
signed public-release work remains under the Draft PR #11/#12 review sequence,
there is no stable external compatibility commitment, and all committed valid
Claims already satisfy the invariant. Previously constructed inconsistent
Draft records must be rejected rather than migrated or normalized.

Before introducing `0.2`, define:

- whether the change is additive or breaking
- migration rules for published records
- validator support window
- how existing signed manifests retain their original schema interpretation

A schema update must not reinterpret an already published evidence status or claim meaning without a new version.

## CI behavior

CI fails on:

- invalid schema definitions
- invalid JSON records
- schema violations
- time-order violations
- duplicate IDs
- unresolved typed references
- invalid lifecycle, model-check, or evidence-digest semantics
- missing human approval for a manifest claiming publication
- missing validation reports
- incomplete REUSE licensing metadata

No private repository or secret is required for normal pull-request validation.

## Non-goals

This lane does not:

- establish cryptographic security
- validate the truth of a vendor or product claim
- certify a product release
- inspect private source or raw evidence
- sign an evidence manifest
- approve publication

## Public Evidence export validation

The export contracts are strict JSON Schema Draft 2020-12 documents. The
exporter performs additional status, lifecycle, digest, allowlist, path,
sensitivity, and review-marker checks before constructing a bundle. A generated
bundle can be checked together with the existing repository records:

```console
python scripts/export_public_evidence.py \
  --mode test-fixture \
  --staging-root tests/fixtures/export/input \
  --input protocol-conformance.json \
  --output-dir .codex-local/tmp/export
python scripts/validate_assurance.py \
  --root . \
  --report-dir .codex-local/tmp/report \
  --export-profile profiles/public-evidence-export.v0.1.json \
  --export-mode test-fixture \
  --export-bundle .codex-local/tmp/export/public-evidence-export.v0.1.json
```

Supplying any `--export-bundle` makes `--export-profile` semantically
mandatory. The profile must be a repository-contained regular non-symlink file
whose strict JSON, Schema, ID/version, self-digest, and manifest binding all
validate. Missing or malformed profiles fail closed with stable
`export-profile-*` findings; ordinary Assurance-record validation without an
export bundle remains unchanged.

Default validation treats a bundle as a real `export-candidate`. Synthetic
validation requires explicit `test-fixture` mode, the exact committed staging
root, one unique catalogued fixture ID whose candidate digest matches the
bundle, the manifest-bound catalog digest, and test-only review/publication
markers. The expected bundle remains a separate byte-for-byte CI oracle so that
the fixture catalog does not create a catalog/manifest/bundle digest cycle.
Validation also requires exact review-status parity across provenance,
requirements, and sanitization-report markers, plus equality of the visible,
digest-bound, and current export-profile digests. Both public validators use
the same semantic binding helper. They also recompute the embedded Evidence
subject/output/exported-record bindings and compare every Protocol digest with
the reviewed profile pin. The check report must exactly equal the profile's
closed check set for the declared mode and programmatic or staged-file
interface. Real candidate identifiers use the closed opaque 128-bit form, and
all candidate-controlled public strings receive the same defense-in-depth
scan. Only committed synthetic fixtures are used by
public CI. Generated bundles are not uploaded as workflow artifacts. See
[`EVIDENCE_EXPORT.md`](EVIDENCE_EXPORT.md) for the trust and publication
boundary.
