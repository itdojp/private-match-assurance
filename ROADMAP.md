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

Draft v0.1 artifacts are defined in
[`docs/AE_FRAMEWORK_INTEGRATION.md`](docs/AE_FRAMEWORK_INTEGRATION.md). They
pin ae-framework commit `bba9b6846608359b87ed5393cb208e321f3ba8af`, preserve
all six Evidence statuses, and separate automated judgment from human
approval. The Draft also separates producer/native judgment, binds exact
JSON/Markdown bytes through a deterministic output set, and confines offline
outputs to a trusted root. Policy roles are distinct from mode-specific tool
bindings, and each producer package is single-source-revision. Stored native
claims are recomputed from bound Evidence, Protocol/conformance labels are
exact-authority-bound, current formal output is proof-check-only, and validation
time is a digest-bound ordered event. Live Product Evidence, approval
ingestion, bounded model-check producer authority, publication, and
production-readiness claims remain outside A3.

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

Draft v0.1 artifacts are defined in
[`docs/SIGNED_PUBLIC_RELEASE.md`](docs/SIGNED_PUBLIC_RELEASE.md),
[`docs/OFFLINE_PUBLIC_VERIFICATION.md`](docs/OFFLINE_PUBLIC_VERIFICATION.md),
and [`docs/KEY_AND_REVOCATION_BOUNDARY.md`](docs/KEY_AND_REVOCATION_BOUNDARY.md).
The committed bundle is entirely synthetic and `test-only`. It uses RFC 8785,
DSSE v1.0.2, and Ed25519 fixture keys, requires an external fixture trust root,
separates release/status signing, and applies conservative compromise
revocation without trusted timestamps. Production signing, key custody,
Product release publication, GitHub Release creation, and automatic publication
remain outside A4.

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
