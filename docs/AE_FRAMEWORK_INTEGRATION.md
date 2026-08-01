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
Package validation does not trust that stored projection or the stored Evidence
as an independent authority. The internal Assurance package embeds the exact
strictly validated safe-metadata producer package whose detached digest it
names. Generation and stored-package validation share one pure derivation for
Evidence records and references, producer and external-tool inventories,
validation provenance, gate results, status counts, producer judgment, and the
native input manifest. Validation revalidates the embedded producer package,
rederives every surface, reruns the same exact vendored command in an ephemeral
process-owned system temporary directory, and requires exact equality. The
package also binds the domain-separated native input-manifest digest. Changing
any derived Evidence field, native claim, warning, lane, Evidence-kind set, or
counter while leaving the embedded producer package unchanged therefore fails
even if every downstream digest and output-set byte binding is recomputed.
Stored-package validation neither creates nor follows
`.codex-local/tmp`; the process-owned directory has a private final component,
is passed to Node's read/write permission allowlist, is absent from every report
surface and bounded error, and is removed on success or failure.
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

The exact policy-role inventory contains two required checks (CI and
conformance-runner records) and three optional checks (formal, security, and
human-review contract records). It defines requirement, absence, timeout,
input/output, Evidence requirement, and six-status semantics, but it does not
claim an execution implementation. Each producer package separately binds one
mode-specific execution identity, version, implementation digest, and contract
pair to every policy role. A required non-pass status blocks the producer gate.
Optional `skip` or `unsupported` records remain visible and are non-blocking
under this Draft profile. They never disappear or become `pass`.

Fixture mode accepts only the five reviewed `private-match-synthetic-*`
bindings and their exact fixture digests. Private-candidate mode accepts only
the five closed `private-match-product-*` execution role identities and rejects
fixture identities, fixture digests, missing/extra/duplicate roles, and any
record/binding mismatch. Candidate versions and SHA-256 implementation digests
are supplied by the private Product, digest-bound into every report surface,
and deliberately not independently authenticated by this runner.

Policy-role ID, execution identity, and native implementation lineage are
separate surfaces. Policy-role ID controls requirement and status semantics;
execution identity remains visible in Evidence and tool inventories. Only the
validated implementation digest is projected into the pinned ae-framework as
`generatorLineage`, using the deterministic form
`implementation/sha256:<64 lowercase hexadecimal digits>`. A caller cannot
supply a separate lineage. Equal supplied implementation digests therefore
produce one native lineage even when their policy roles and execution
identities differ. Distinct supplied digests remain distinct native lineages,
but do not prove independent development, organizational independence, or
independent execution.

Fixture input uses the closed subject `synthetic-private-match-product`,
`test_only=true`, and `synthetic-public-fixture`. Private-candidate input uses
the closed non-customer subject `private-match-product`, `test_only=false`, and
`private-assurance-retained`. In both modes the subject digest must equal the
producer package's sole source-revision digest. Draft 0.1 is a strict
single-source-revision package: record-level revision fields are forbidden and
every emitted Evidence subject is copied from that validated package subject.
Producer identities are closed role IDs; customer, tenant, account,
organization, user, repository, host, path, credential, email, and telephone
identifiers are rejected.

The complete validated producer object is embedded only because its closed
contract already excludes raw Product input, source, logs, identifiers, and
credentials. The JSON package is therefore independently reconstructible from
its named input without adding a fourth output file. Embedding proves internal
producer-to-Assurance consistency; it does not externally authenticate supplied
source, case, input, Product, tool, output, or timestamp metadata. A wholly new
private-candidate producer package remains acceptable only when it satisfies
the closed contract and the runner regenerates every downstream surface.

## Protocol and conformance authority

`config/private-match-protocol-authorities.v0.1.json` is the closed authority
for Protocol and conformance labels. Draft 0.1 pins public Protocol commit
`9bb59d3b5e1435885fdea60280d6602f937305c9`, the `private-match-core/0.1`
state-machine semantic digest, and the `private-match-core/0.1` conformance
suite semantic/tree and reviewed-oracle digests. The profile, producer package,
Assurance package, conformance record, implementation manifest, and generated
report all bind the same authority.

The adapter does not invent identifiers or versions and does not fetch the
Protocol repository at runtime. Draft 0.1 is a strict one-package/one-suite
contract: all five producer records must carry the bound reviewed suite digest,
and every generated Evidence `input_digests` array has exactly five entries with
that suite digest at index 0. Only conformance Evidence additionally carries the
reviewed Protocol/suite identifier and version configuration. Unknown, stale,
floating, mixed, or internally inconsistent authority metadata fails closed.
The remaining four input digests are supplied case, input, Product
implementation, and Product artifact metadata; the runner structurally binds
but does not independently attest them. This metadata binding identifies the
reviewed public authority; it is not runtime attestation and does not prove
Protocol or Product correctness.

## Formal Evidence boundary

The current `formal-tool` producer contract emits Evidence type `proof-check`
and native lane/kind `proof`/`proof-check`. `sourceKind` remains
`model-derived` only as a source classification. The adapter does not emit a
`model-check` claim because Draft 0.1 does not accept the checked-property,
state-space, constraint, depth/state-count, or completeness-within-bounds
surface required by the existing Evidence Schema `model_check` contract.
Adding bounded model-check Evidence requires a future reviewed producer
contract; synthetic bounds are not inferred.

## Automated judgment and human approval

The producer-gate judgment is separately `satisfied`, `blocked`, or
`not-evaluated`. The native ae-framework judgment is separately `satisfied`,
`warning`, `blocked`, or `not-evaluated`. The combined automated judgment is
`satisfied`, `satisfied-with-warnings`, `blocked`, or `not-evaluated`.

The exact native warning vocabulary at the pinned commit is closed in the
profile. `missing-spec-derived-evidence` is the only reviewed
visible-nonblocking warning in Draft 0.1; all other native warning codes are
blocking. Missing required lanes or Evidence kinds are also blocking, and an
unknown warning fails closed. Therefore the current success fixture is
`satisfied-with-warnings`, not plain `satisfied`. JSON and Markdown both show
every native claim, required/observed/missing lane and Evidence-kind set,
warning code, and policy treatment. Producer Evidence statuses are never
rewritten by native judgment.

The pinned framework emits `same-generator-lineage` when more than one
observed Evidence entry for a claim has one distinct implementation-derived
lineage. The Draft profile classifies that warning as blocking. Optional
non-pass entries with other digests do not change the pinned framework's
observed-Evidence calculation; the adapter does not invent a stronger
independence rule.

The current runner-generated human boundary has only
`required-not-provided` and `not-applicable-test-only`. It cannot accept or
emit `approved` or `rejected`; no authorized human-approval ingestion process
exists in Draft 0.1. The approval subject is the exact
`assurance_content_digest`. The boundary truthfully records that the boundary
artifact was generated by automation, while no approval decision is present
or generated by automation. Public fixtures use `synthetic-reviewer` and
`not-applicable-test-only`. Private candidates have no reviewer role and remain
`required-not-provided`.

Reviewer identity and authority verification remain future human/process
controls. A future approval artifact requires a separately reviewed authority,
scope, content-digest binding, timestamp, expiry/revocation, and ingestion
contract. Combined automated judgment never creates or overrides approval.

## Offline invocation

The future private Product invocation contract is:

```text
python scripts/run_ae_assurance.py \
  --profile profiles/private-match-ae-assurance.v0.1.json \
  --input-root <explicit-staging-root> \
  --input <one-relative-json-file> \
  --output-root <existing-trusted-private-output-root> \
  --output <one-relative-new-directory> \
  --mode fixture-test|private-candidate
```

The runner accepts one explicit regular UTF-8 strict-JSON input. The trusted
output root must already exist, be a directory, and have no symlink component.
The output is one POSIX-relative new directory below that root; every
intermediate directory must already exist and the final directory must not
exist. Staging and atomic rename remain inside the same trusted root. Absolute
input paths, Windows paths, backslashes, empty/dot/dot-dot segments, root
escape, intermediate/final symlinks, directories, oversized inputs,
duplicate JSON keys, recursive scans, shell commands, caller-supplied
executables, caller-supplied native arguments, network endpoints, and
environment-derived profile/timestamp values are rejected.

The native command uses a fixed argument array with `shell=False`, a bounded
timeout, bounded stdout/stderr, a controlled working directory, and an
allowlisted environment. Native stderr is not copied to reports. JSON,
Markdown, and the output-set manifest are staged and committed by one directory
rename; failure removes the staging tree and leaves no final partial package.
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
- exact policy roles and mode-specific producer/external-tool identities,
  versions, implementation digests, binding digests, and input/output
  contracts;
- all six status counts;
- required and optional gate results;
- the safe native ae-framework projection;
- automated judgment and the separate human-approval boundary;
- limitations and private/public lifecycle boundary;
- content, report-model, package, and exact output-set digests.

Report model digests are domain-separated digests over the report content
before self-referential digest fields are attached; they are not file hashes.
Every fixture-test and private-candidate run also emits a detached output-set
manifest. It binds the exact canonical JSON bytes, exact rendered Markdown
bytes, package digest, renderer implementation digest, adapter digest, profile
digest, and ae-framework pin digest. Validation requires exactly these three
regular files and rejects changed, missing, renamed, extra, symlinked, or stale
outputs. The fixture catalog binds all six expected output-set manifests.

The same profile, producer package, exact ae-framework pin, dependency locks,
and implementation produce byte-identical JSON, Markdown, and output-set
manifest. The runner does
not add current time, random IDs, hostnames, usernames, local paths,
environment values, network metadata, or floating tool versions. The producer
package supplies a closed `validation_event.validated_at` after every record
completion and package creation, together with the fixed source
`producer-supplied-digest-bound`. It is a producer assertion included in the
producer-package digest, copied to every producer-side Evidence `validated`
lifecycle transition, and supplied to the pinned ae-framework only as its
deterministic reference for the required `generated-at` argument.
Chronology is enforced as `started_at <= completed_at <= created_at <=
validated_at`. It is not represented as the Assurance runner's execution time.
The package records runner validation as performed while setting its runner
timestamp to null with status
`not-recorded-for-deterministic-offline-execution`. This explicit separation
preserves byte-identical offline output without inventing a clock fact. The
producer assertion is digest-bound but not externally timestamp-attested;
fixture values are synthetic, while private-candidate timestamp authority and
external runner-time attestation remain private process responsibilities.

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
