# ae-framework integration profile

## Status and authority

This document describes the Draft profile `private-match-ae-assurance/0.1`.
The only reviewed ae-framework authority is:

- repository: `itdojp/ae-framework`
- commit: `bba9b6846608359b87ed5393cb208e321f3ba8af`
- package identity: `ae-framework@1.0.0`
- license: Apache-2.0
- native command: `node scripts/assurance/aggregate-lanes.mjs`
- invocation strategy: `vendored-reviewed-subset`

The published package surface at the reviewed commit does not include the
native Assurance script as a package CLI. The integration therefore vendors
only the complete reviewed source and runtime-Schema closure listed by
`vendor/ae-framework/source-manifest.v0.1.json`. Runtime checkout, GitHub API
access, a floating branch, and caller-selected executables or arguments are
not permitted.

The vendored command is unmodified. Its raw native output is validated in a
controlled staging directory, reduced to a path-free deterministic safe
projection, and then removed. The raw output contains native execution
metadata and absolute staging paths and is not an Assurance package surface.
The exact runtime dependencies are Ajv 8.20.0, Ajv-formats 2.1.1, and YAML
2.8.3. YAML 2.8.3 is the patched exact release within the reviewed
ae-framework `^2.8.1` range; it avoids GHSA-48c2-rrv3-qjmp without changing the
reviewed ae-framework source commit.

## Claim boundary

ae-framework can organize supplied Evidence, validate supplied artifact
contracts, aggregate reviewed lanes, apply the reviewed automated policy, and
produce a deterministic summary. It cannot create facts absent from the
Evidence.

Neither ae-framework nor this adapter establishes any of the following:

- security proof or cryptographic correctness;
- certification, Product correctness, or Protocol correctness;
- legal compliance, pilot readiness, or production readiness;
- reviewer identity, reviewer authority, or absence of undiscovered defects;
- human approval or publication approval.

ae-framework is not an oracle of truth, a security proof oracle, or a
certification authority. Automated satisfaction is not human approval and is
not publication approval.

## Producer and status contract

The closed producer types are `ci`, `formal-tool`, `test-runner`,
`security-tool`, and `human-review`. A profile or Schema change is required to
add another type.

Each external record preserves exactly one of the Evidence Schema 0.1
statuses:

| Raw producer status | Evidence status | Meaning |
|---|---|---|
| `pass` | `pass` | Reviewed execution matched its expected contract. |
| `fail` | `fail` | Reviewed execution completed with a mismatch or failed assertion. |
| `skip` | `skip` | A reviewed condition intentionally prevented execution. |
| `unsupported` | `unsupported` | A required capability or selected implementation is unavailable. |
| `timeout` | `timeout` | A reviewed deterministic execution bound was exceeded. |
| `tool-error` | `tool-error` | Producer, adapter, parser, or tool processing failed. |

There is no status collapse or promotion. In particular, `skip` and
`unsupported` do not become `pass`, while `timeout` and `tool-error` do not
become `fail`. Unknown status values fail closed.

The exact tool inventory contains two required checks (synthetic CI and
conformance-runner records) and three optional checks (formal, security, and
human-review contract records). A required non-pass status blocks the
automated judgment. Optional `skip` or `unsupported` records remain visible
and are non-blocking under this Draft profile. They never disappear or become
`pass`.

## Automated judgment and human approval

Automated judgment is one of `satisfied`, `blocked`, or `not-evaluated`.
`satisfied` requires every required check to be `pass`; any required non-pass
status yields `blocked`. Invalid input or an adapter/native-tool processing
failure produces no successful package and therefore cannot be promoted.

Human approval is a separate contract with states `approved`, `rejected`,
`required-not-provided`, `not-applicable`, and
`not-applicable-test-only`. The approval subject is the exact
`assurance_content_digest`. CI, agents, ae-framework, and fixture execution
cannot create a live approval. Public fixtures use `synthetic-reviewer` and
`not-applicable-test-only`. Private candidates remain
`required-not-provided`.

Reviewer identity and authority verification remain human/process controls.
Automated `satisfied` never overrides `required-not-provided`, and a human
approval cannot overwrite an automated `blocked` judgment.

## Offline invocation

The future private Product invocation contract is:

```text
python scripts/run_ae_assurance.py \
  --profile profiles/private-match-ae-assurance.v0.1.json \
  --input-root <explicit-staging-root> \
  --input <one-relative-json-file> \
  --output-root <explicit-private-output-root> \
  --mode fixture-test|private-candidate
```

The runner accepts one explicit regular UTF-8 strict-JSON input. Absolute
input paths, Windows paths, backslashes, empty/dot/dot-dot segments, root
escape, intermediate/final symlinks, directories, oversized inputs,
duplicate JSON keys, recursive scans, shell commands, caller-supplied
executables, caller-supplied native arguments, network endpoints, and
environment-derived profile/timestamp values are rejected.

The native command uses a fixed argument array with `shell=False`, a bounded
timeout, bounded stdout/stderr, a controlled working directory, and an
allowlisted environment. Native stderr is not copied to reports. JSON and
Markdown are staged and committed by one directory rename; failure removes
the staging tree and leaves no final partial package.
Node's permission model allowlists only the reviewed source/dependency inputs
and the staging output. Child-process permission is not granted, so the
vendored metadata helper cannot fall back to its Git subprocess path; the
digest-bound synthetic revision metadata comes from the fixed environment.

Fixture mode accepts only catalogued input path/digest pairs. An arbitrary
candidate cannot self-select fixture mode.

## Report authority and reproducibility

JSON is the machine authority. Markdown is generated only from the validated
JSON package and escapes producer-controlled labels. The package retains:

- every independently Schema-valid Evidence record;
- exact producer and external-tool identities, versions, and digests;
- all six status counts;
- required and optional gate results;
- the safe native ae-framework projection;
- automated judgment and the separate human-approval boundary;
- limitations and private/public lifecycle boundary;
- content, report-semantic, and package digests.

Report semantic digests are domain-separated digests over the report content
before self-referential digest fields are attached. The fixture catalog binds
the exact final JSON and Markdown file bytes separately.

The same profile, producer package, exact ae-framework pin, dependency locks,
and implementation produce byte-identical JSON and Markdown. The runner does
not add current time, random IDs, hostnames, usernames, local paths,
environment values, network metadata, or floating tool versions. Any required
timestamp is supplied and digest-bound by the producer package.

## Private/public boundary

The generated package is private/internal Assurance Evidence. It is not a
public export bundle. The ae-framework runner never invokes
`scripts/export_public_evidence.py`, never sets Evidence lifecycle to
`published`, never creates publication approval, and always sets public export
eligibility to false.

The Issue #4 public-export process remains separate and later. It still
requires an export candidate, sanitization, privacy review,
security-boundary review, IP review, vulnerability review, and a final human
publication decision.
