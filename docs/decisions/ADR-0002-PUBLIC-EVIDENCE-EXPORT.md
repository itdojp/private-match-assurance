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
- applies strict schemas and type-specific field allowlists;
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

## Alternatives considered

### Strict allowlist versus denylist

A denylist cannot anticipate all private field names and makes an open
`configuration` object unsafe. A strict candidate schema and per-Evidence-type
configuration allowlist are selected. Pattern scanning remains supplementary.

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
candidate digest, expected bundle digest, `test-only` status, and
`synthetic-reviewer` markers. The public bundle retains that distinction.

### Opaque review digest versus complete review-subject binding

An approval-artifact digest alone does not state what was reviewed. Each closed
review scope now binds a domain-separated digest over every reviewable candidate
field except the review markers and digest itself. Safe scope, role, status,
approval digest, and subject digest remain in the public bundle. Human authority
and approval authorship are still reviewed manually.

### Single source-file digest versus implementation manifest

Digesting only the CLI omits helper code, validators, Schemas, the Evidence
Schema, and dependency locks that change accepted inputs or output bytes. A
closed, deterministic manifest binds all of those files plus the runtime
profile and expected export-profile digest. The profile remains independently
versioned. The fixture catalog remains separate conformance authority to avoid
making test expectations part of the production implementation identity.

## Consequences

- Future private producers must transform raw evidence into the candidate
  contract before transfer.
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
