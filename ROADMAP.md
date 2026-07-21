# Assurance Roadmap

## A0 — Repository baseline

- evidence and claim terminology
- public/private boundary
- publication governance
- agent rules
- initial Epic and child issues

## A1 — Machine-readable schemas

Create schemas for:

- claims
- assumptions
- evidence items
- evidence manifests
- known limitations
- correction and withdrawal notices

Exit criteria:

- invalid status, missing provenance, or missing subject scope fails validation
- evidence lifecycle validates independently from check-result status
- model-check evidence requires typed state-space bounds and explored-state counts
- private-source metadata rejects repository, hostname, account, and path locators
- manifests distinguish canonical evidence-record digests from output digests
- example valid and invalid fixtures exist

## A2 — Private-to-public evidence export contract

Define the package produced by `private-match-product` and consumed here.

Required controls:

- allowlisted fields
- digest binding
- redaction log
- secret and identifier scanning
- private path and hostname detection
- pass/fail/skip status preservation
- human publication approval

Exit criteria:

- a fixture-backed export can be validated without private repository access
- unsafe fields are rejected

Draft v0.1 artifacts are defined in
[`docs/EVIDENCE_EXPORT.md`](docs/EVIDENCE_EXPORT.md). Publication, release
signing, and private-side production integration remain outside A2.

## A3 — ae-framework integration profile

Define how `itdojp/ae-framework` is invoked and recorded:

- framework version and commit
- policy profile
- evidence producers
- external tool versions
- automated versus human judgments
- JSON and Markdown report generation

Exit criteria:

- a deterministic fixture report is generated
- missing tools and skipped checks remain visible

## A4 — Signed assurance release bundle

- manifest signing
- artifact and source revision digests
- protocol and conformance version binding
- SBOM and provenance references
- public verification instructions
- supersession and withdrawal support

Exit criteria:

- a third party can verify signature, digests, schema, and report linkage
- signature verification is not described as security certification

## A5 — First experimental release report

Publish evidence for an experimental, non-production product slice.

Required sections:

- subject and version
- claims and assumptions
- evidence summary
- failures, skips, unsupported checks, and exceptions
- reproducibility classification
- known limitations
- publication approval

No release becomes public automatically from CI success.
