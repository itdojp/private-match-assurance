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
- `supported-with-assumptions` to reference at least one assumption
- `expired` and `withdrawn` to include a non-empty status reason

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
  --export-mode test-fixture \
  --export-bundle .codex-local/tmp/export/public-evidence-export.v0.1.json
```

Default validation treats a bundle as a real `export-candidate`. Synthetic
validation requires explicit `test-fixture` mode, the exact committed staging
root, catalogued candidate and expected-bundle digests, and test-only review and
publication markers. Validation also recomputes the complete review-subject and
exporter implementation bindings. Only committed synthetic fixtures are used by
public CI. Generated bundles are not uploaded as workflow artifacts. See
[`EVIDENCE_EXPORT.md`](EVIDENCE_EXPORT.md) for the trust and publication
boundary.
