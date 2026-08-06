# Claims Policy

## Purpose

Prevent evidence from being converted into broader public claims than it supports.

## Required structure

Every public assurance statement must answer:

1. What exact subject is covered?
2. Which version, revision, build, or deployment profile is covered?
3. What property is asserted?
4. Under which assumptions?
5. Which evidence supports it?
6. Which relevant properties are not asserted?
7. When does the claim expire or require re-evaluation?

## Permitted claim patterns

Examples:

- `Build X passed conformance suite Y under configuration Z.`
- `The TLA+ model for protocol version X was checked with TLC configuration Y
  and typed state-space bounds B; no invariant violation was found among N
  distinct states, with completeness within those bounds reported as C.`
- `Artifact digest X was produced by workflow Y from source revision Z.`
- `The reference verifier rejected the published tamper and replay vectors for suite version X.`

## Restricted language

The following words require explicit scope, assumptions, and reviewer approval:

- secure
- safe
- private
- anonymous
- proven
- verified
- certified
- compliant
- zero leakage
- impossible
- complete
- production ready
- independently reviewed

## Prohibited transformations

Do not transform:

- `tests passed` into `the product is correct`
- `model check passed` into `the implementation is formally proven`
- `artifact attested` into `the artifact is secure`
- `no issue found` into `no vulnerability exists`
- `vendor reports property X` into `ITDO independently established property X`
- `no direct competitor identified` into `no competitor exists`
- `ae-framework automated judgment satisfied` into `the Product is secure,
  certified, human-approved, publication-approved, pilot-ready, or
  production-ready`

ae-framework may organize supplied Evidence and apply the reviewed automated
policy. Native warnings and their reviewed blocking/nonblocking treatment must
remain visible; `satisfied-with-warnings` is not plain satisfaction. The
stored native projection is recomputed from the exact embedded producer package
with the exact pinned command and cannot strengthen that Evidence.
Protocol/conformance labels
identify one reviewed authority but do not attest execution. A generic formal
record is `proof-check`, not a bounded `model-check`, unless the required bounds
and explored-state result are supplied under a future reviewed contract. The
framework cannot create facts absent from Evidence, establish the absence of
undiscovered defects, verify reviewer identity or authority, create human
approval, or authorize publication.

## Cryptographic claims

A cryptographic claim must identify:

- primitive or protocol and version
- security model
- adversary capabilities
- implementation and library version
- key and setup assumptions
- side-channel and deployment exclusions
- external analysis or standard relied upon
- local evidence and what it does not establish

Local tests alone do not establish cryptographic security.

## Privacy claims

A privacy claim must identify:

- protected data
- each actor and collusion assumption
- intended output
- metadata and residual leakage
- repeated-query controls
- minimum set and small-intersection behavior
- input-completeness assumptions
- operational controls outside the protocol

## Independence claims

A review is independent only when the reviewer is external to the producing organization and the scope is documented. Use `internal review` for ITDO review and `third-party tool output` for external tools executed by ITDO.

## Claim expiry

Claims should expire when any of the following changes materially:

- protocol version
- conformance suite
- source revision or build configuration
- cryptographic library or parameters
- assurance policy
- threat model
- deployment profile
- identified vulnerability or invalid evidence

## Known limitations

Every release report must include a prominent limitations section. Absence of a limitation entry is not evidence that the limitation does not exist.

## Signed fixture evaluation

The public release verifier evaluates claims after signature, trust,
structure, digest, lifecycle, and report checks. Signature validity is only a
mechanical origin/integrity result relative to the supplied trust input.

The closed result vocabulary is `supported`,
`supported-with-assumptions`, `not-supported`, `not-evaluated`, and
`invalid-reference`. All referenced Evidence, Assumptions, and Limitations must
exist and share the reviewed subject where applicable. Only `pass` Evidence can
support a positive result. Unsupported or unavailable Evidence remains visible
and never becomes `pass`. A `pass` record whose lifecycle is `superseded` or
`withdrawn` cannot support a positive claim. Every referenced Assumption must be
`active`: `invalidated` produces `not-supported`, while `expired` produces
`not-evaluated`.

The two positive signed Claim states have a closed Assumption contract.
`supported` is unconditional within its declared scope and therefore requires
an empty Assumption list. `supported-with-assumptions` is the only positive
state that may reference Assumptions and requires at least one. Other,
non-positive states may retain Assumption references for review context. The
verifier never promotes, downgrades, or rewrites a signed declaration to repair
an inconsistent positive classification: Schema validation fails closed, and
the evaluator's defense in depth returns `invalid-reference` if called directly.
A valid signature cannot repair that policy inconsistency.

The caller-supplied verification time is applied to each Claim's inclusive
`valid_from`/`valid_until` interval independently of the release's validity
window. A Claim outside its own window is `not-evaluated`; a valid release
signature cannot promote it to supported. Dynamic verifier output records the
Claim window, the current validity result, each referenced Assumption status,
and each referenced Evidence status/lifecycle. The fixture claims only
mechanical properties and do not state Product security, correctness,
certification, or readiness.
