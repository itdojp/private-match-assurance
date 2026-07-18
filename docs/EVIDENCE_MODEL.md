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
summary: string
private_source_reference: string | null
public_artifacts: []
limitations: []
```

### Evidence manifest

The manifest groups evidence for a release and binds:

- source revision digest
- build artifact digest
- protocol version
- conformance-suite version
- ae-framework version and policy profile
- evidence item digests
- claim-set digest
- assumption-set digest
- known limitations
- release approver
- publication signature

## Status semantics

- `pass`: the named check executed and its defined success condition held
- `fail`: the check executed and its defined success condition did not hold
- `skip`: a policy or conditional rule intentionally did not run the check
- `unsupported`: the subject or environment cannot run the check
- `timeout`: execution exceeded the declared limit
- `tool-error`: the tool failed to produce a valid result

Only `pass` supports a positive statement about that specific check. Other statuses remain visible.

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

## Reproducibility

Publicly reproducible evidence should include inputs, commands, tool versions, and expected results. Evidence dependent on private data or infrastructure must be labeled `privately reproducible` or `not publicly reproducible`, with the reason stated.
