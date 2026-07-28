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
Every normalized Evidence record independently validates against Evidence
Schema 0.1.

### Automated gate versus human approval

A single approval field would allow automated results to be confused with a
human decision. Separate Schemas are selected. Automated judgment can be
`satisfied`, `blocked`, or `not-evaluated`; human approval is independently
bound to the exact Assurance content digest. CI, agents, fixtures, and
ae-framework cannot produce a live approval.

### Required versus optional tool absence

Silently omitting unavailable tools or promoting them to `pass` was rejected.
Required unavailable tools remain `unsupported` or `tool-error` and block.
Optional absent tools remain visible as `skip` or `unsupported` and follow the
reviewed non-blocking policy.

### JSON authority versus separately authored Markdown

Separately authored Markdown can diverge from machine judgment. JSON is the
authority; Markdown is rendered only from validated JSON and compared against
byte-exact expected fixtures.

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
- JSON as authority and generated Markdown;
- separate automated judgment and human-approval provenance;
- synthetic fixture mode that cannot create live approval;
- no automatic public export or proof/certification claim.

The native command's raw output is validated but not retained because it
contains implementation/runtime paths and metadata. The package stores a
closed path-free safe projection and its domain-separated digest.

## Consequences

The repository adds Node 22.22.2 execution and exact Ajv/YAML dependencies for
the reviewed native command. Fixture outputs and implementation/source
manifests must be regenerated after behavior-affecting changes. This increases
review surface but closes dependency, tool, status, and provenance ambiguity.

No production authentication, PET/matching algorithm, private Product
execution, human approval, security proof, certification, publication
approval, pilot readiness, or production readiness is established.
