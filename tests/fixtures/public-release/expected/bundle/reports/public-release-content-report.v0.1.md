# Private Match synthetic release content

> Immutable synthetic test-only content. This is not a verification result or Product release approval.

## Release content

- Release ID: `private-match-assurance-fixture-release-0.1.0`
- Version: `0.1.0`
- Channel: `fixture`
- Bundle revision: `1`
- Source revision digest: `sha256:d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1`
- Release artifact digest: `sha256:dd105fded85a3242a4300bd23b309d123bf152c69ab210b653834a268fc8484b`
- SBOM digest: `sha256:84b97ef07a8c89f2432027934db77533dccd372d7ff94d0e19fd4315f5737d0e`
- Build provenance digest: `sha256:df3f8b457f066a1ff19f27105901c8aecd69d32625a1cdf691e7dabf2fe321a9`

## Declared authorities

- Protocol: `private-match-core` `0.1`
- Protocol digest: `sha256:32e514a61a83aeb1593623eb1144f323d1115dc8c812b5fd72af93a3ae06ba16`
- Conformance digest: `sha256:83787c69ec1128eb9ba4b8dcdfcb4ae218674b6158cd8c6c573d898a6f72ceba`

## Evidence status counts

- `pass`: 3
- `fail`: 0
- `skip`: 0
- `unsupported`: 1
- `timeout`: 0
- `tool-error`: 0

## Declared claim support

- `PM-CLAIM-6001`: `supported` (required-evidence-pass)
  - Signed validity: `2026-08-01T00:00:00Z` through `2027-08-01T00:00:00Z`
  - Assumptions: none
  - Evidence: `PM-EVIDENCE-6001=pass/sanitized`
- `PM-CLAIM-6002`: `supported` (required-evidence-pass)
  - Signed validity: `2026-08-01T00:00:00Z` through `2027-08-01T00:00:00Z`
  - Assumptions: none
  - Evidence: `PM-EVIDENCE-6001=pass/sanitized`, `PM-EVIDENCE-6003=pass/sanitized`
- `PM-CLAIM-6003`: `supported-with-assumptions` (evidence-pass-assumptions-visible)
  - Signed validity: `2026-08-01T00:00:00Z` through `2027-08-01T00:00:00Z`
  - Assumptions: `PM-ASSUMPTION-6001=active`
  - Evidence: `PM-EVIDENCE-6002=pass/sanitized`
- `PM-CLAIM-6004`: `supported` (required-evidence-pass)
  - Signed validity: `2026-08-01T00:00:00Z` through `2027-08-01T00:00:00Z`
  - Assumptions: none
  - Evidence: `PM-EVIDENCE-6003=pass/sanitized`

## Known limitations

- Synthetic fixture data and fixture keys do not establish a Product release.
- Signature validity establishes origin and integrity only relative to the supplied trust root; it is not security certification.
- The supplied fixture trust root is an external verifier input whose authenticity is not established by the bundle.
- No trusted timestamp or transparency log is used; compromise revocation applies conservatively to all signatures under the affected key.
- The verifier validates the complete supplied status chain but cannot prove that it is the globally latest distributed revision.
- Production signing, key custody, publication approval, and automated publication are unsupported in Draft 0.1.

Current signature validity, trust, key status, release lifecycle, verification time, and overall verification classification are intentionally absent.
