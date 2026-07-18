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

Install the pinned validation dependency:

```bash
python -m pip install -r requirements-dev.txt
```

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

## Fixtures

`tests/fixtures/valid/minimum.json` contains minimum valid examples for every record class.

`tests/fixtures/valid/complete.json` contains a linked fixture set with:

- one claim
- one assumption
- one conformance evidence item
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
- missing validation reports

No private repository or secret is required for normal pull-request validation.

## Non-goals

This lane does not:

- establish cryptographic security
- validate the truth of a vendor or product claim
- certify a product release
- inspect private source or raw evidence
- sign an evidence manifest
- approve publication
