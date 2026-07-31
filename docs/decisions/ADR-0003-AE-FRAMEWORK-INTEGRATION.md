# ADR-0003: exact-pinned ae-framework Assurance integration

- Status: proposed
- Date: 2026-07-29

## Context

Private Match needs a reproducible way to organize Product-style producer
Evidence with ae-framework while preserving the existing Evidence Schema 0.1
and Issue #4 private-to-public export boundary. The integration must not make
ae-framework an oracle, fabricate human approval, collapse unavailable tool
states, retrieve a private repository, or publish Evidence.

The reviewed authority is `itdojp/ae-framework` commit
`bba9b6846608359b87ed5393cb208e321f3ba8af`, package identity
`ae-framework@1.0.0`, Apache-2.0. The native command is
`node scripts/assurance/aggregate-lanes.mjs`.

## Options considered

### Package API/package CLI versus fixed CLI versus vendored subset

The package/API option is preferred when the reviewed package publishes the
required surface. At this commit the package file list and `bin` entries do not
publish the native Assurance command. A fixed external CLI would require a
separately installed executable whose source closure could drift.

The selected option is an unmodified vendored reviewed subset: the native
entrypoint, its two transitive local source dependencies, its runtime Schemas,
and exact Node dependencies. A closed manifest binds original paths, per-file
digests, source commit, package identity, and license.

The exact YAML runtime is 2.8.3. It is within the reviewed ae-framework
`^2.8.1` dependency range and fixes GHSA-48c2-rrv3-qjmp. This is a locked
runtime dependency correction, not a change to the reviewed ae-framework
commit or Assurance command source.

### Live checkout versus pinned offline dependency

Live checkout, floating Git branch, runtime GitHub API, and network retrieval
were rejected. The reviewed subset and dependency locks are committed and
validated offline.

### Raw producer output versus normalized Evidence package

Raw Product output could contain private state or implementation-specific
values. It is rejected. The selected producer package contains only synthetic
or private-retained metadata/digests and closed producer/tool/status records.
Policy roles define requirement and status semantics independently from the
mode-specific execution-tool bindings carried by the producer package.
Fixture bindings are exact reviewed synthetic authorities. Private-candidate
bindings use closed non-identifying Product role identities while the Product
supplies their version and implementation digest; those supplied values are
digest-bound but not independently authenticated by this runner.
Policy-role identity and mode-specific execution identity remain reportable
contract surfaces, but neither is used as native implementation lineage. The
adapter deterministically derives ae-framework `generatorLineage` as
`implementation/<implementation_digest>` after binding validation. Equal
supplied digests are therefore one lineage even across different roles, while
distinct supplied digests do not prove actual organizational, development, or
execution independence.
Every normalized Evidence record independently validates against Evidence
Schema 0.1. Fixture and private-candidate modes have distinct closed subjects,
producer role IDs, test-only markers, retention classes, and human-approval
states. Draft 0.1 is strictly single-source-revision: the package subject digest
equals the sole reviewed source-revision digest, redundant record-level
revision fields are forbidden, and all emitted Evidence subjects are identical.
Arbitrary customer or repository identity is not accepted.

### Automated gate versus human approval

A single approval field would allow automated results to be confused with a
human decision. Separate Schemas are selected. Producer-gate and native
ae-framework judgments remain distinct, and the combined judgment adds
`satisfied-with-warnings` so a reviewed native warning cannot be hidden behind
plain satisfaction. The current machine-generated human boundary permits only
`not-applicable-test-only` or `required-not-provided`, binds the exact Assurance
content digest, and truthfully identifies the boundary artifact as automated.
There is no live `approved` or `rejected` ingestion contract in Draft 0.1. CI,
agents, fixtures, and ae-framework cannot produce a live approval.

### Native warning policy

Ignoring the native ae-framework claim status would reduce invocation to an
informational side effect. The selected profile closes the exact warning-code
vocabulary from the pinned source. `missing-spec-derived-evidence` is reviewed
as visible-nonblocking for the current synthetic lane scope; every other known
warning is blocking, missing required lanes or Evidence kinds are blocking,
and unknown warning codes fail closed. Native claims and treatment are visible
in JSON and generated Markdown without rewriting producer statuses.
The pinned `same-generator-lineage` rule is evaluated over observed Evidence
using the implementation-derived lineage. It blocks the combined judgment when
multiple observed entries share one lineage. The adapter does not strengthen
that upstream rule for non-observed optional entries.

### Stored native projection versus Evidence-derived recomputation

Trusting the stored native projection would let a package author strengthen a
claim or remove a warning and then recompute the package/output digests without
changing the Evidence. The selected validator instead reconstructs the native
manifest from the stored Evidence records and the validated external-tool
inventory, reruns the exact pinned vendored command, and requires the safe
projection and derived judgments to match exactly. Generation and validation
share the same fixed invocation implementation. A domain-separated native
input-manifest digest records the exact reconstructed input. A Python
approximation of ae-framework was rejected because it would create a second,
unreviewed judgment implementation.

### Adapter constants versus reviewed Protocol authority

Hard-coded Protocol and suite labels in adapter code were rejected because a
producer previously supplied only a suite digest. Draft 0.1 now uses one closed
authority artifact pinned to public Protocol commit
`9bb59d3b5e1435885fdea60280d6602f937305c9`. It binds the Protocol and suite
identifiers, versions, semantic/tree digests, and reviewed oracle artifacts.
The profile, producer package, conformance Evidence, report, and runner
implementation manifest must agree with that authority. No runtime Protocol
checkout or network lookup is introduced.

### Proof-check metadata versus bounded model-check Evidence

Calling the existing generic formal-tool record a `model-check` was rejected
because its `model_check` surface is null and it carries no checked properties,
state-space parameters, constraints, depth/state bounds, explored counts, or
completeness-within-bounds result. Draft 0.1 maps this role to Evidence type and
native kind `proof-check`; `model-derived` remains only a source classification.
A future `model-check` producer contract must validate the existing typed
bounded model-check surface rather than invent synthetic bounds.

### Completion timestamp versus digest-bound validation event

Using record completion as the validation time allowed a lifecycle to claim
that a later producer-package digest had already been reviewed. Draft 0.1
therefore requires a producer-supplied, digest-bound validation event and
enforces `started_at <= completed_at <= package.created_at <= validated_at`.
The same `validated_at` is used in Evidence lifecycle history, package
validation provenance, generated Markdown, and the pinned native command's
`generated-at` argument. This timestamp is deterministic and bound, but it is
not externally timestamp-attested; private-candidate timestamp authority is a
private process concern.

### Required versus optional tool absence

Silently omitting unavailable tools or promoting them to `pass` was rejected.
Required unavailable tools remain `unsupported` or `tool-error` and block.
Optional absent tools remain visible as `skip` or `unsupported` and follow the
reviewed non-blocking policy.

### JSON authority versus separately authored Markdown

Separately authored Markdown can diverge from machine judgment. JSON is the
authority; Markdown is rendered only from validated JSON. A detached output-set
manifest binds the exact JSON and Markdown bytes, renderer implementation,
adapter, profile, ae-framework pin, and package digest for both fixture and
private-candidate modes. Exact fixture directories contain only the JSON,
Markdown, and output-set manifest.

### Arbitrary destination versus trusted output root

Allowing one unrestricted output directory would let a caller select any
writable filesystem location. The selected interface accepts an existing,
symlink-free trusted output root plus one validated POSIX-relative new
directory. All intermediate directories exist under the root; staging and
atomic rename remain in the same root, and failure leaves no partial output.

### Private Assurance package versus public export bundle

Reusing the public exporter automatically was rejected. The ae package is
internal, is not publication-approved, and is public-export-ineligible. The
Issue #4 export process remains an explicit later human-reviewed boundary.

### Product runtime invocation versus public fixture CI

Runtime checkout or live Product inputs in public CI were rejected. The CLI
defines an offline one-file staging contract for future private invocation.
Public CI executes only committed synthetic, catalogued fixtures.

## Decision

Adopt:

- the exact ae-framework pin and vendored reviewed subset;
- deterministic offline fixed-array subprocess execution with no shell;
- Node permission-model isolation without child-process permission;
- exact preservation of `pass`, `fail`, `skip`, `unsupported`, `timeout`, and
  `tool-error`;
- a closed required/optional tool inventory;
- separate policy-role semantics and exact mode-specific execution-tool
  bindings;
- JSON as authority and generated Markdown;
- exact output-set binding and trusted-root confinement;
- separate producer/native/combined automated judgment and human-approval
  provenance;
- Evidence-derived execution of the exact pinned native command during both
  generation and stored-package validation;
- a closed exact Protocol/conformance authority rather than adapter-invented
  labels;
- proof-check-only formal metadata until a bounded model-check producer
  contract exists;
- digest-bound validation-event chronology shared by Evidence lifecycle and
  native execution;
- synthetic fixture mode that cannot create live approval;
- no automatic public export or proof/certification claim.

The native command's raw output is validated but not retained because it
contains implementation/runtime paths and metadata. The package stores a
closed path-free safe projection and its domain-separated digest, but validation
recomputes that projection from the bound Evidence instead of trusting it.

## Consequences

The repository adds Node 22.22.2 execution and exact Ajv/YAML dependencies for
the reviewed native command. Fixture outputs and implementation/source
manifests must be regenerated after behavior-affecting changes. This increases
review surface but closes dependency, tool, status, and provenance ambiguity.

No production authentication, PET/matching algorithm, private Product
execution, human approval, security proof, certification, publication
approval, pilot readiness, or production readiness is established.
