# ADR-0002: Public Evidence Export Boundary

- Status: proposed
- Owner: ITDO Inc. / 株式会社アイティードゥ
- Decision date: 2026-07-21
- Review date: 2026-10-21
- Related issue: `itdojp/private-match-assurance#4`

## Context

Public assurance needs traceable metadata from future private product evidence
without copying private source, raw logs, customer data, infrastructure detail,
credentials, vulnerability detail, or unpublished IP into a public repository.
An export success must not be confused with publication approval or with a
positive test result.

## Decision

Use a closed candidate envelope, a versioned public bundle, and a separately
digested export profile. The exporter:

- accepts one repository-local staged metadata file;
- applies strict schemas and closed type-specific configuration contracts;
- rejects secrets and private or ambiguous data rather than heuristically
  redacting it;
- permits only explicitly reviewed omission of optional fields;
- preserves all Evidence result statuses exactly;
- appends at most a `sanitized` lifecycle entry;
- emits a deterministic RFC 8785 bundle with digest bindings; and
- separates default human-reviewed candidate mode from a caller-selected,
  catalog-bound synthetic fixture mode;
- binds every review scope to the complete reviewed candidate material and
  retains safe review provenance publicly;
- binds the complete behavior-affecting exporter implementation manifest; and
- always leaves final publication approval absent. Real output remains a
  `candidate`; synthetic output remains machine-readable `test-only`.

The existing Evidence Schema 0.1 is unchanged. Export-specific metadata lives
in the enclosing bundle.

The 2026-07-22 review hardening additionally requires private-side Evidence to
be `validated` before export, replaces first-level configuration key lists with
closed type-specific contracts, and binds the synthetic fixture trust catalog
plus enforced runtime requirements into the implementation manifest.

## Alternatives considered

### Strict allowlist versus denylist

A denylist cannot anticipate all private field names and makes an open
`configuration` object unsafe. A strict candidate schema and per-Evidence-type
configuration contracts are selected. Each exportable type has a closed,
digest-bound complete shape. Pattern scanning remains supplementary.

### Reject versus redact

Free-form redaction can hide status changes, retain identifying fragments, or
leak a low-entropy value through a digest. Secrets, customer/personal data,
private locators, vulnerability details, and IP candidates are rejected. Only
profile-enumerated optional omission is allowed.

### Metadata candidate versus raw-log ingestion

Raw-log ingestion would require complex parsers and create a broad disclosure
surface. A private-side producer must create a closed metadata candidate. The
public exporter never scans a private repository or accepts raw evidence.

### Existing Evidence input versus enclosing export bundle

Mutating the Evidence Schema to contain exporter and review metadata would
reinterpret existing 0.1 records. The selected bundle preserves the current
Evidence Schema while adding export-specific provenance and gate status around
it.

### Deterministic JSON strategy

Plain `json.dumps(sort_keys=True)` is not RFC 8785 and is not cross-language
canonicalization. The reviewed Apache-2.0 `rfc8785` package version 0.1.4 is
hash locked for CPython 3.12 on Ubuntu x86-64. Official Protocol vectors and
local adversarial tests established the same parsing boundary; Assurance adds
its own deterministic fixture comparison. A custom JCS-like implementation was
rejected.

### Sanitized versus published lifecycle

CI and an exporter cannot make a publication judgment. Output is capped at
`sanitized`, the bundle is a `candidate`, and final approval is recorded as
required but not provided. Publication, withdrawal, and supersession remain
human-governed later processes.

Collected input is not exported. Automatically appending only `sanitized`
would skip the required `collected -> validated` transition and falsely imply
that validation occurred. The private-side producer must supply validated
Evidence; already sanitized Evidence is accepted only when its last event
exactly matches the reviewed sanitization event. Future collected support would
need distinct validation and sanitization events, timestamps, and review
digests.

### Private revision locator versus digest-only binding

A locator reveals repository or infrastructure identity. The candidate and
bundle retain only a SHA-256 binding. Private lookup stays in a private system.

### Value digest in omission log versus no value derivative

An unsalted digest of a low-entropy identifier is dictionary-attackable. The
log contains a path, rule, action, category, and review digest only. It contains
no original value or derivative of that value.

### Scanner as gate versus scanner as supplemental control

Pattern scanners have unavoidable false negatives and false positives. Closed
schemas and allowlists are primary. The scanner catches common bypasses and
produces only a value-free path/category error; human review remains mandatory.

### Candidate-controlled fixture marker versus trusted execution mode

Allowing input `artifact_status` to select synthetic review would make the
review gate self-authorizing. The caller therefore selects the mode independently.
Normal mode accepts only `export-candidate` plus `authorized-human` markers.
Fixture mode accepts only the exact committed staging root and catalogued input,
candidate digest, `test-only` status, and `synthetic-reviewer` markers. The
public bundle retains the fixture ID and catalog digest. Expected bytes are
compared separately by CI rather than stored in the catalog, avoiding a cycle
through catalog digest -> implementation digest -> bundle digest.
Public validation resolves that ID to exactly one entry in the strict,
manifest-bound catalog and requires its `test-only` status and candidate digest
to match the bundle. Neither the ID, whole-catalog digest, nor candidate digest
is sufficient by itself.

### Opaque review digest versus complete review-subject binding

An approval-artifact digest alone does not state what was reviewed. Each closed
review scope now binds a domain-separated digest over every reviewable candidate
field except the review markers and digest itself. Safe scope, role, status,
approval digest, and subject digest remain in the public bundle. Human authority
and approval authorship are still reviewed manually.
The retained status must equal the corresponding review requirement and
sanitization-report marker. Privacy and security-boundary cannot be
`not-applicable`; IP and vulnerability retain their reviewed
`approved|not-applicable` choice.

### Visible profile label versus three-way digest parity

A detached bundle digest is an integrity checksum, not an authorization. The
visible export-profile digest could otherwise diverge from the digest-binding
copy. Both public validators therefore require the visible digest, binding
copy, and current reviewed profile digest to be identical while preserving the
closed profile ID/version.

The profile is a required trust input, not an optional validation aid. Public
bundle validation fails before success if the repository-contained profile is
missing, symlinked, malformed, digest-invalid, unsupported, or inconsistent
with the implementation manifest. Structure-only validation remains internal
and is not used by the CLI, CI, exporter, or repository validator.

### Semantic candidate labels versus opaque identifiers

A free-form candidate ID can leak customer, tenant, account, repository, or
personal context even when the Evidence record is clean. Real candidates
therefore carry a producer-supplied opaque 128-bit hexadecimal identifier.
Synthetic IDs remain deterministic only under fixture mode and exact catalog
binding. The supplemental scanner covers the entire candidate-controlled public
surface; the closed Schemas and review process remain the primary defenses.

### Claimed checks versus trusted execution context

A caller-provided check list can falsely claim file-boundary work during an
in-memory transform. The profile now defines a closed common, file-interface,
and fixture check catalog. The exporter derives the sorted exact set from a
trusted programmatic or staged-file execution context after each interface
check succeeds, and both public validators recompute the expected set. Unknown,
missing, duplicated, or inapplicable checks fail closed.

### Reported digest success versus complete recomputation

The sanitization report is not accepted as proof of binding. Both validators
recompute the Evidence subject, output, and exported-record relationships and
compare every Protocol binding against the current profile. Only then may the
closed report retain `digest_binding_result: pass`.

### Single source-file digest versus implementation manifest

Digesting only the CLI omits helper code, validators, Schemas, the Evidence
Schema, and dependency locks that change accepted inputs or output bytes. A
closed, deterministic manifest binds all of those files, the configuration
Schema, fixture authorization catalog, enforced CPython/JCS requirements, and
expected export-profile digest. The profile remains independently versioned.
Fixture authorization affects both fixture mode and rejection of synthetic
review digests in normal mode, so it is a behavior-affecting trust root rather
than separate metadata.

Ubuntu 24.04 x86-64 is retained only as a tested target, not execution
provenance. CPython major/minor and the installed `rfc8785` version are checked
at runtime. Actual runner/platform provenance must be supplied by future
producer Evidence and is not inferred by the exporter.

## Consequences

- Future private producers must transform raw evidence into the candidate
  contract and complete the `validated` lifecycle transition before transfer.
- Unknown Evidence types and configuration fields require an explicit profile
  revision.
- Equal semantic input is reproducible without a runtime Protocol dependency.
- Any reviewable material change requires renewed scope-specific review
  bindings, and any listed implementation change produces a new implementation
  digest.
- Private evidence is intentionally not publicly reproducible; the public
  bundle states this limitation and binds the source by digest.
- A successful export establishes neither security nor publication approval.

## Compatibility

This is an additive draft 0.1 contract with no stable compatibility commitment.
It does not change existing Assurance records or their interpretation. The
review hardening changes draft candidate and bundle shapes, so earlier draft
fixtures must be regenerated. Profile or implementation changes alter their
separate digests and require candidate review or bundle regeneration. No
production exporter is declared.

## Human decisions retained

- whether a reviewer has the required authority;
- whether IP or vulnerability material may be disclosed;
- final publication approval;
- release signing and distribution; and
- future profile expansion for additional Evidence types.
