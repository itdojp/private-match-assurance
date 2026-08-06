# Private Match public release verification

> Synthetic test-only fixture. This is not a Product release or publication approval.

## Release

- Release ID: `private-match-assurance-fixture-release-0.1.0`
- Version: `0.1.0`
- Channel: `fixture`
- Bundle revision: `1`
- Manifest digest: `sha256:c76653233aadae34f895349545d41b499a0e8f37474436642f2cafaf51473d4c`
- Overall: `revoked-key`
- Verification time: `2026-08-04T00:00:00Z`

## Signature and trust

- Algorithm: `ed25519-rfc8032`
- Signing key ID: `sha256:06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9`
- Signature valid: `true`
- Trust domain valid: `true`
- Key status: `revoked`
- Release lifecycle: `active`
- Selected status revision: `2`
- Status-chain manifest digest: `sha256:bbdd1b47bea1bcb0b4177ea84fa2e00ce3e0f1a51a2615b0300783bf98b267b2`

## Authorities and artifacts

- Protocol: `private-match-core` `0.1`
- Protocol digest: `sha256:32e514a61a83aeb1593623eb1144f323d1115dc8c812b5fd72af93a3ae06ba16`
- Conformance digest: `sha256:83787c69ec1128eb9ba4b8dcdfcb4ae218674b6158cd8c6c573d898a6f72ceba`
- Source revision digest: `sha256:d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1d1`
- Release artifact digest: `sha256:dd105fded85a3242a4300bd23b309d123bf152c69ab210b653834a268fc8484b`
- SBOM digest: `sha256:84b97ef07a8c89f2432027934db77533dccd372d7ff94d0e19fd4315f5737d0e`
- Build provenance digest: `sha256:df3f8b457f066a1ff19f27105901c8aecd69d32625a1cdf691e7dabf2fe321a9`

## Verification stages

- Structure valid: `true`
- Digest closure valid: `true`
- Report linkage valid: `true`

## Evidence status counts

- `pass`: 3
- `fail`: 0
- `skip`: 0
- `unsupported`: 1
- `timeout`: 0
- `tool-error`: 0

## Claim support

- `PM-CLAIM-6001`: `supported` (required-evidence-pass)
- `PM-CLAIM-6002`: `supported` (required-evidence-pass)
- `PM-CLAIM-6003`: `supported-with-assumptions` (evidence-pass-assumptions-visible)
- `PM-CLAIM-6004`: `supported` (required-evidence-pass)

## Known limitations

- Synthetic fixture data and fixture keys do not establish a Product release.
- Signature validity establishes origin and integrity only relative to the supplied trust root; it is not security certification.
- The supplied fixture trust root is an external verifier input whose authenticity is not established by the bundle.
- No trusted timestamp or transparency log is used; compromise revocation applies conservatively to all signatures under the affected key.
- The verifier validates the complete supplied status chain but cannot prove that it is the globally latest distributed revision.
- Production signing, key custody, publication approval, and automated publication are unsupported in Draft 0.1.

## Interpretation boundary

- Signature verification proves origin and integrity only relative to the supplied trust input.
- Signature validity is not security certification or proof of Product correctness.
- Fixture verification is not Product release or publication approval.
