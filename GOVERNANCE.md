# Assurance Governance

## Authority and scope

ITDO Inc. maintains this repository. Reports are company-published assurance evidence unless an explicitly identified independent party produced or reviewed the evidence.

## Evidence lifecycle

Evidence items use these states:

- `collected` — raw result exists in a private or controlled system
- `validated` — structure, provenance, and integrity have been checked
- `sanitized` — public export has passed redaction and privacy review
- `published` — included in a public signed manifest or report
- `superseded` — replaced by newer evidence
- `withdrawn` — invalid, unsafe to publish, or no longer relied upon

Claims use these states:

- `draft`
- `supported`
- `supported-with-assumptions`
- `not-supported`
- `expired`
- `withdrawn`

## Release scope

Each assurance release must identify:

- product or artifact subject
- private source revision digest
- build artifact digest
- protocol version
- conformance-suite version
- ae-framework version and profile
- external tool versions
- evidence collection time
- assumptions
- exceptions
- known limitations
- superseded report, if any

## Publication gate

A release requires:

- provenance validation
- schema validation
- redaction and privacy review
- security review
- claims review
- IP and patent review when evidence may expose an invention
- explicit human approval

A green CI run is necessary but not sufficient for publication.

## Independence language

Use precise terms:

- `ITDO internal verification`
- `tool-generated evidence`
- `third-party tool result`
- `independent external review`, only when the reviewer is organizationally independent and identified

Do not use `certified`, `formally proven`, or `independently verified` unless the exact scope and authority justify it.

## Corrections and withdrawal

If evidence or a claim is later found invalid:

1. freeze further reliance on the affected report
2. publish a withdrawal or correction notice
3. identify affected versions and claims
4. retain an auditable history where safe
5. issue replacement evidence or mark the claim unsupported

## Private evidence references

Public manifests may refer to private evidence by digest and approved metadata. They must not create an inference that the public can independently inspect private content.

## Security disclosure

Suspected vulnerabilities must be reported privately. Security evidence may be delayed, redacted, or summarized to avoid enabling exploitation. The report must disclose that relevant detail was withheld and why.
