# Assurance Governance

## Authority and scope

ITDO Inc. maintains this repository. Reports are company-published assurance evidence unless an explicitly identified independent party produced or reviewed the evidence.

## Evidence lifecycle

Evidence items use these lifecycle states in their `lifecycle` field. Lifecycle
records the evidence's validation and publication stage; it is distinct from the
check-result `status` such as `pass`, `fail`, or `skip`.

- `collected` — raw result exists in a private or controlled system
- `validated` — structure, provenance, and integrity have been checked
- `sanitized` — public export has passed redaction and privacy review
- `published` — included in a public signed manifest or report
- `superseded` — replaced by newer evidence
- `withdrawn` — invalid, unsafe to publish, or no longer relied upon

A lifecycle transition must not rewrite the recorded check result. For example,
evidence that originally had `status: pass` and is later withdrawn retains that
result with `lifecycle: withdrawn`, and active claims must no longer rely on it.

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

Signed Draft 0.1 bundles are immutable. Correction or supersession requires a
new release and bundle revision with an explicit predecessor reference, plus a
status-authority-signed entry for the old release. Withdrawal is also a
status-authority decision and never requires the affected release key to revoke
itself. Without trusted timestamps, compromise revocation applies
conservatively to every signature under the affected key.

The committed release and status keys are separate synthetic fixture keys.
Neither is a production authority. Trust-root authenticity, status-set
distribution, production key custody, signing, and publication approval remain
external human-governed decisions.

## Private evidence references

Public manifests may refer to private evidence by digest and approved metadata. They must not create an inference that the public can independently inspect private content.

## Security disclosure

Suspected vulnerabilities must be reported privately. Security evidence may be delayed, redacted, or summarized to avoid enabling exploitation. The report must disclose that relevant detail was withheld and why.
