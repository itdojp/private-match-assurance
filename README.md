# Private Match Assurance

Public assurance contracts, Evidence validation tools, and reviewable claims for
Private Match. Maintained by ITDO Inc.

This repository defines how a named claim is linked to its subject, assumptions,
test results, provenance, and known limitations. It does not publish the
commercial Product source code or provide independent certification.

> **Status: Draft contracts and synthetic fixtures.** The committed signed
> release bundle is test data. No production Private Match assurance report
> exists here. A valid Schema, signature, or automated judgment is not human
> approval, publication approval, cryptographic security, or production
> readiness.

## Start here

| Goal | Read |
| --- | --- |
| Understand Claim, Assumption, Evidence, and lifecycle | [Evidence model](docs/EVIDENCE_MODEL.md) |
| Interpret a result without overstating it | [Claims policy](docs/CLAIMS_POLICY.md) |
| Validate records and run repository checks | [Schema validation](docs/SCHEMA_VALIDATION.md) |
| Prepare reviewed public-safe metadata | [Evidence export contract](docs/EVIDENCE_EXPORT.md) |
| Integrate private/internal producer results | [ae-framework integration](docs/AE_FRAMEWORK_INTEGRATION.md) |
| Inspect a signed test bundle offline | [Signed release profile](docs/SIGNED_PUBLIC_RELEASE.md) · [Offline verification](docs/OFFLINE_PUBLIC_VERIFICATION.md) |
| Understand signing and revocation boundaries | [Key and revocation boundary](docs/KEY_AND_REVOCATION_BOUNDARY.md) |

## Three separate processing boundaries

| Boundary | What it does | What it does not authorize |
| --- | --- | --- |
| Public Evidence export | Validates a closed staged metadata candidate, review bindings, redaction, and status-preserving sanitization | Reading private repositories or publishing the sanitized candidate |
| Private/internal ae-framework integration | Validates producer metadata and generates deterministic JSON/Markdown and output-set manifests using pinned framework authority | Public export, live human approval, Product certification, or stronger claims than the input Evidence |
| Signed public release fixtures | Creates and verifies catalogued synthetic bundles using separate fixture release/status keys and explicit trust, status-chain, and time inputs | Production signing, trust-root distribution, publication, or reliance on a signature as proof of claim support |

These paths remain separate: an internal Assurance package does not
automatically become public Evidence, and an exported candidate does not
automatically become a published report. Normal review authority and explicit
synthetic test mode are not interchangeable. Detailed contracts and
compatibility rules live in the guides above.

## Result and claim semantics

Evidence preserves six distinct check results:

`pass` · `fail` · `skip` · `unsupported` · `timeout` · `tool-error`

Lifecycle separately records whether Evidence is collected, validated,
sanitized, published, superseded, or withdrawn. Withdrawal does not rewrite a
historical check result, and a skipped or unavailable capability must not become
`pass`.

Every public claim must identify its subject and version, scope, assumptions,
supporting Evidence, limitations, and validity or review period. A scoped report
may describe a named conformance run or bounded model check; it does not
establish absence of vulnerabilities, side channels, input omissions, legal
risk, or deployment defects. Provenance establishes origin, not safety. See
[GOVERNANCE](GOVERNANCE.md).

## Local validation

Use **CPython 3.12**. The complete integration/test environment additionally
requires **Node.js 22.22.2** and **pnpm 10.34.5**. These are repository pins,
not a recommendation to substitute whatever runtime is globally installed.

From the repository root, start with record validation:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements-build.txt
python -m pip install --require-hashes --no-build-isolation -r requirements-dev.txt
python scripts/validate_assurance.py --root . --report-dir artifacts
reuse lint
```

With the pinned Node runtime active, install the exact integration dependencies
and run the regression and pinned-source checks:

```bash
corepack enable
corepack prepare pnpm@10.34.5 --activate
pnpm install --frozen-lockfile
python -m unittest discover -s tests -p 'test_*.py'
python scripts/ae_framework_manifest.py --check
python scripts/ae_assurance_implementation.py --check
```

Package installation needs network access. The reviewed fixture/integration
checks use committed synthetic inputs and a pinned local framework closure; they
do not fetch live Product Evidence or publish a release. Follow
[SCHEMA_VALIDATION](docs/SCHEMA_VALIDATION.md) and the [CI
workflow](.github/workflows/assurance-schema.yml) for the full deterministic
fixture, output-set, signature, and offline-verification checks. Do not
substitute production keys or real private data for fixture inputs.

## Repository layout

| Path | Purpose |
| --- | --- |
| `schema/` | Closed Claim, Evidence, manifest, export, and integration Schemas |
| `assurance/` | Scoped records and notices |
| `profiles/` · `config/` | Reviewed policy and integration authority |
| `manifests/` | Source and implementation inventories |
| `scripts/` · `tests/` | Validators, transformations, offline verification, and synthetic regressions |
| `docs/` | Semantics, operational boundaries, and validation instructions |

## Contribution and publication boundary

Work from an Issue and submit a scoped PR with source/revision provenance,
validation, limitations, and public/private checks. CI success is necessary but
not sufficient for a public report. Human review controls claims, IP, security,
privacy, licensing, publication, corrections, and withdrawal.

Never include customer identifiers, private source, raw production logs,
credentials, internal topology, unpublished inventions, or unremediated
vulnerability details. Private-source references use only the reviewed digest
and safe-metadata contract; do not copy private locators into public Evidence.
Follow [SECURITY.md](SECURITY.md) for security reports and
[AGENTS.md](AGENTS.md) for repository instructions. [ROADMAP](ROADMAP.md)
describes planned work, not implemented assurance capabilities.

## Related repositories

| Repository | Role |
| --- | --- |
| [private-match-protocol](https://github.com/itdojp/private-match-protocol) | Public Protocol meaning, Schemas, and conformance |
| [private-match-research](https://github.com/itdojp/private-match-research) | Public research and technology comparisons |
| `private-match-product` (private) | Implementation and private Evidence production |
| `private-match-strategy` (private) | Business, IP, legal, and publication decisions |
| [ae-framework](https://github.com/itdojp/ae-framework) | Pinned Evidence organization and automated policy judgments |

## License

Narrative documentation, tables, and diagrams use
[CC-BY-4.0](LICENSES/CC-BY-4.0.txt). Code, Schemas, validators, tests, fixtures,
workflows, and build inputs use [Apache-2.0](LICENSES/Apache-2.0.txt).
[REUSE.toml](REUSE.toml) governs individual files; see
[ADR-0001](docs/decisions/ADR-0001-PUBLIC-LICENSING.md). These licenses neither
authorize disclosure of private material nor approve an assurance report.
Internal ITDO review must not be called independent certification.
