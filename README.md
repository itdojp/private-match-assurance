# Private Match Assurance

Public assurance evidence repository for named Private Match protocol and product releases.

This repository publishes reviewable claims, assumptions, evidence manifests, verification summaries, provenance, and known limitations. It does not publish the private commercial source code or claim independent certification by ITDO Inc.

## Repository role

This repository is the public system of record for:

- release-scoped assurance claims
- explicit assumptions and non-goals
- signed evidence manifests
- protocol, conformance-suite, source-revision, and artifact digests
- sanitized test, model-checking, security, and interoperability summaries
- software bills of materials and provenance references where publishable
- known limitations, exceptions, withdrawals, and supersession notices
- the exact ae-framework version and policy profile used to organize evidence

## Claim boundary

An assurance report may support statements such as:

- a named build was tested against a named conformance-suite version
- a named formal model was checked under a published bounded configuration
- specified tests passed, failed, skipped, timed out, or were unsupported
- a release artifact was produced by an identified build workflow

It does not by itself establish:

- absence of vulnerabilities or side channels
- cryptographic security beyond the cited assumptions and external analyses
- correctness or completeness of private input data
- legal or regulatory compliance
- safe operation of every deployment
- independent certification

## Public / private boundary

Never publish:

- customer data or identifiers
- private source code
- raw production logs
- secrets or internal topology
- exploitable vulnerability details before remediation
- abuse-detection thresholds
- unpublished inventions or patent candidates
- evidence whose origin or redaction cannot be established

The draft [public Evidence export contract](docs/EVIDENCE_EXPORT.md) is the only
defined metadata transfer boundary. It accepts one closed, staged candidate,
requires private-side lifecycle `validated` or an exactly matching existing
`sanitized` event, preserves result status, and emits at most a `sanitized`
publication candidate.
Its default human-reviewed mode is separate from the explicit, catalog-bound
synthetic fixture mode; review scopes bind the complete candidate subject, and
bundles bind the complete exporter implementation manifest. It does not read
private repositories or grant publication approval. Exportable configuration
shapes are closed per Evidence type, and the implementation binding covers the
fixture trust catalog plus enforced CPython/JCS requirements; the listed OS
target is not execution provenance.

The Draft [ae-framework integration profile](docs/AE_FRAMEWORK_INTEGRATION.md)
is a separate, private/internal Assurance processing boundary. It pins an
unmodified reviewed ae-framework source closure, preserves all six Evidence
statuses, generates deterministic JSON-authority/Markdown reports from public
synthetic fixtures, and keeps automated judgment structurally separate from
human approval. Exact output-set manifests bind emitted JSON/Markdown bytes;
private-candidate provenance uses a separate closed subject and trusted output
root. Policy roles are separate from mode-specific execution-tool bindings,
and one producer package is bound to one source revision. The exact validated
safe-metadata producer package is embedded so stored Evidence, inventories,
provenance, gates, counts, and the native input can be independently rederived.
Stored native claims are recomputed with the exact pinned command, Protocol and
conformance labels come from one closed reviewed authority, and every producer
and Evidence record places that authority's suite digest in one closed position.
Stored-package native validation uses a process-owned system temporary directory
rather than an ignored repository-local path. The current
formal-tool contract is proof-check-only rather than an unbounded model-check.
A digest-bound validation event orders record completion, package creation,
Evidence validation, and native generation, while native ae warnings remain
policy-visible. The current runner cannot
generate a live approval. It does not invoke the public exporter, process live
Product Evidence in this repository, certify the Product, or authorize
publication.

The Draft [signed public release profile](docs/SIGNED_PUBLIC_RELEASE.md) is a
third, separate boundary. It creates only a catalogued synthetic `test-only`
fixture bundle, signs exact RFC 8785 manifest bytes through DSSE v1 with a
fixture Ed25519 key, and verifies it offline against an explicit external
fixture trust root and a separately signed status set. Release signing and
status/revocation signing use different keys. Claim support remains distinct
from signature validity. The reference verifier uses an explicit verification
time and stable structured results; it performs no network lookup, Product
checkout, publication, artifact upload, or production signing. See
[offline verification](docs/OFFLINE_PUBLIC_VERIFICATION.md) and the
[key/revocation boundary](docs/KEY_AND_REVOCATION_BOUNDARY.md).

## Related repositories

- `itdojp/private-match-protocol` — public protocol specifications and conformance assets
- `itdojp/private-match-research` — public research
- `itdojp/private-match-product` — private implementation and raw evidence production
- `itdojp/private-match-strategy` — private publication, IP, and business decisions
- `itdojp/ae-framework` — assurance control plane

## Maturity

The repository is in bootstrap. The committed signed release bundle is
synthetic test data. No public assurance report for a production Private Match
release exists yet.

## License

Repository content uses an explicit dual-license structure:

- Narrative assurance documentation, research text, tables, and diagrams are licensed under
  [Creative Commons Attribution 4.0 International](LICENSES/CC-BY-4.0.txt).
- Python code, JSON Schemas, validators, tests, fixtures, conformance vectors, GitHub Actions,
  and build inputs are licensed under the [Apache License 2.0](LICENSES/Apache-2.0.txt).

[`REUSE.toml`](REUSE.toml) provides the machine-readable SPDX file mapping and takes precedence
over this summary for individual files. The explicit human approval, alternatives, and
publication boundary are recorded in
[ADR-0001](docs/decisions/ADR-0001-PUBLIC-LICENSING.md).

Patent-sensitive and trade-secret candidate material remains private or embargoed until human
IP and publication approval. These licenses do not authorize publication of private evidence or
constitute approval of an assurance report.
