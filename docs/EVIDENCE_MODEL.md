# Evidence Model

## Objective

Provide a machine-readable and reviewable link between a scoped claim and the evidence produced by private product builds, public protocol assets, external tools, and human review.

## Core objects

### Claim

A claim states a bounded proposition about a named subject.

Minimum fields:

```yaml
id: PM-CLAIM-0001
statement: string
subject:
  type: protocol | source-revision | build-artifact | deployment-profile | process
  identifier: string
  version: string
scope: string
status: draft | supported | supported-with-assumptions | not-supported | expired | withdrawn
assumptions: []
evidence: []
limitations: []
valid_from: date-time
valid_until: date-time | null
supersedes: string | null
owner: string
reviewers: []
```

### Assumption

An assumption is a condition not established by the evidence set but required for interpreting a claim.

Examples:

- signing keys were not compromised during the evidence period
- the tested cryptographic library matches the referenced source and build
- private input data was supplied as declared by the participating party
- model checking covered only the published configuration and bounds

Assumptions must be stable identifiers so reports can show which claims depend on them.

### Evidence item

Minimum fields:

```yaml
id: PM-EVIDENCE-0001
type: test | conformance | model-check | proof-check | security-scan | provenance | review | sbom | benchmark
status: pass | fail | skip | unsupported | timeout | tool-error
lifecycle: collected | validated | sanitized | published | superseded | withdrawn
lifecycle_history:
  - state: collected | validated | sanitized | published | superseded | withdrawn
    recorded_at: date-time
    review_digest: sha256:... | null
subject_digest: sha256:...
input_digests: []
output_digest: sha256:...
producer:
  type: github-actions | local-runner | external-lab | human-review
  identity: string
tool:
  name: string
  version: string
  source: string
started_at: date-time
completed_at: date-time
configuration: {}
model_check: null
summary: string
private_source_metadata: null
public_artifacts: []
limitations: []
```

`status` is the check result. `lifecycle` is the separate validation and
publication stage defined by `GOVERNANCE.md`; changing lifecycle must not rewrite
the result. `lifecycle_history` is a non-empty, append-only transition log. Its
first entry is `collected`, its last entry matches `lifecycle`, and each
validation, sanitization, publication, supersession, or withdrawal decision
records the applicable review digest.

`output_digest` identifies the output or result artifact produced by the check.
It is not the digest of the Evidence item record itself.

For `type: model-check`, `model_check` is required and has this typed structure:

```yaml
model_check:
  properties: [string]
  state_space_bounds:
    parameters:
      - name: string
        kind: integer-range | finite-set
        minimum: integer | null
        maximum: integer | null
        values: []
    constraints: []
    max_depth: integer | null
    max_states: integer | null
  explored_state_space:
    generated_states: integer
    distinct_states: integer
    maximum_depth: integer | null
    complete_within_bounds: boolean
```

`properties` and `state_space_bounds.parameters` must be non-empty. An
`integer-range` parameter requires integer `minimum` and `maximum` values and an
empty `values` list. A `finite-set` parameter requires a non-empty `values` list
and null range fields. State and depth counts are non-negative. Evidence for
other types uses `model_check: null`.

For `type: conformance`, `configuration` must identify both the protocol and the
conformance suite, including each identifier and version. An empty or implied
conformance scope is invalid.

When private material contributed to an Evidence item,
`private_source_metadata` replaces any public locator and has this structure:

```yaml
private_source_metadata:
  revision_digest: sha256:...
  source_class: private-product-source | private-evidence-set | external-private-source
  reproducibility: privately-reproducible | not-publicly-reproducible
  publication_review_digest: sha256:...
```

The public record must not contain a private repository URL or name, internal
hostname, account identifier, filesystem path, or other private locator. The
private lookup remains outside the public package and is bound only by the
revision and publication-review digests. Evidence with no private source uses
`private_source_metadata: null`.

### Evidence manifest

The manifest groups evidence for a release and binds:

- source revision digest
- build artifact digest
- protocol version
- conformance-suite version
- ae-framework version and policy profile
- `evidence_record_digests`, computed over each canonicalized complete Evidence
  item record using the manifest version's canonicalization rules
- `evidence_output_digests`, containing the output artifact digests referenced
  by those records, including each `output_digest`
- claim-set digest
- assumption-set digest
- known limitations
- release approver
- publication signature

A manifest that declares `publication.status: published` must include an explicit
human publication approval with `type: publication` and `status: approved`. Schema
or CI success does not create that approval.

## Status semantics

- `pass`: the named check executed and its defined success condition held
- `fail`: the check executed and its defined success condition did not hold
- `skip`: a policy or conditional rule intentionally did not run the check
- `unsupported`: the subject or environment cannot run the check
- `timeout`: execution exceeded the declared limit
- `tool-error`: the tool failed to produce a valid result

Only `pass` supports a positive statement about that specific check. Other statuses remain visible.

## Lifecycle semantics

- `collected`: the result exists in a private or controlled system
- `validated`: structure, provenance, and integrity have been checked
- `sanitized`: the public export passed redaction and privacy review
- `published`: the record is included in a public signed manifest or report
- `superseded`: newer evidence replaced the record
- `withdrawn`: the record is invalid, unsafe to publish, or no longer relied upon

Lifecycle is orthogonal to check status. A superseded or withdrawn `pass` record
retains `status: pass` as historical execution evidence but cannot support an
active claim. The append-only lifecycle history preserves the review path without
overloading or rewriting the result status.

## Evidence strength

Evidence strength is contextual, not a universal score. A model check supports bounded state-machine properties; it does not establish cryptographic hardness. A provenance attestation supports origin; it does not establish safety. A test supports the tested cases; it does not establish absence of other failures.

## Private evidence export

The private product repository should export a sanitized package containing:

- digests and version identifiers
- normalized result summaries
- tool and runner metadata
- public-safe configuration
- explicit redaction log
- reviewer approvals

Raw logs and private source remain outside the public package.

The versioned input, output, profile, status/lifecycle preservation, digest,
omission, and review rules are specified in
[`EVIDENCE_EXPORT.md`](EVIDENCE_EXPORT.md). Export success means only that a
synthetic or human-reviewed metadata candidate reached lifecycle `sanitized`;
it is not publication approval and does not change the Evidence result status.
Synthetic processing is a caller-selected, committed-catalog-only test mode;
candidate input cannot self-select it. Every review scope binds the complete
reviewable candidate subject, and the public bundle retains safe scope, role,
status, review-artifact digest, and reviewed-subject digest. Export bundles also
bind the complete reviewed exporter implementation manifest rather than one
source file.

## Reproducibility

Publicly reproducible evidence should include inputs, commands, tool versions, and expected results. Evidence dependent on private data or infrastructure must be labeled `privately reproducible` or `not publicly reproducible`, with the reason stated.
