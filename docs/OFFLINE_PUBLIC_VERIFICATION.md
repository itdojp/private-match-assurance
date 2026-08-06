# Offline public release verification Draft 0.1

## Command

The verifier accepts one immutable bundle, one external trust root, one closed
external status-chain root, and one explicit canonical UTC time:

    python scripts/verify_public_release_bundle.py \
      --bundle-root tests/fixtures/public-release/expected/bundle \
      --trust-root tests/fixtures/public-release/trust/fixture-trust-root.v0.1.json \
      --status-chain-root tests/fixtures/public-release/expected/status-chains/active \
      --verification-time 2026-08-04T00:00:00Z \
      --output-json .codex-local/tmp/public-release-verification.json \
      --output-md .codex-local/tmp/public-release-verification.md

Dynamic output paths are caller-selected and outside the immutable bundle.
Output parents must be trusted non-symlink directories and outputs must not
exist. No wall-clock default exists.

The command performs no network, DNS, GitHub API, registry,
private-repository, or private-key access. Node.js 22.22.2 performs only the
bounded DSSE PAE Ed25519 primitive. Python performs strict JCS parsing, Schema,
path/digest closure, trust, status-chain, lifecycle, claim, static-report, and
result derivation.

## Ordered verification

1. Validate immutable bundle output-set path and byte closure.
2. Validate the caller-supplied external trust root and SPKI-derived key IDs.
3. Verify the release DSSE signature over exact stored manifest bytes.
4. Reconstruct manifest content, artifacts, record sets, and immutable static
   report.
5. Validate the external status-chain output set and chain manifest.
6. Validate every status revision in exact order, including its DSSE signature,
   previous digest, strictly increasing generation time, unchanging trust
   domain/profile/status signer, and exact file closure.
7. Apply the declared final revision's release-key and release state.
8. Evaluate A1 claim support independently from signature validity.
9. Emit deterministic dynamic JSON authority and derived Markdown.

No status file is loaded from the bundle by implication.

Claim evaluation uses the explicit `--verification-time` for each signed
Claim's inclusive validity interval. It requires supporting Evidence to retain
a lifecycle other than `superseded` or `withdrawn`, and every referenced
Assumption to be `active`. Invalidated Assumptions and non-supporting Evidence
lifecycles produce `not-supported`; expired Assumptions or Claims outside their
own validity window produce `not-evaluated`. The JSON result exposes those
status, lifecycle, and validity inputs independently from signature validity.

## Dynamic result and exit codes

The dynamic result includes the explicit verification time, release signature,
trust result, selected status-chain manifest/output digests and latest revision,
current release-key status, lifecycle, claim support, and overall
classification. It is not signed release content.

| Code | Class |
| ---: | --- |
| 0 | mechanically verified fixture |
| 1 | invalid signature, digest, structure, path set, or static-report linkage |
| 2 | unsupported algorithm/profile/version |
| 3 | untrusted, invalid, expired, or revoked key |
| 4 | withdrawn, superseded, corrected, expired, or not-yet-valid release |
| 5 | mechanically valid bundle with unsupported/not-evaluated required claims |

JSON is authoritative. Stderr is bounded and value-free.

## Same-bundle lifecycle behavior

One byte-identical immutable fixture bundle produces:

- active chain revision 1: verified-fixture-with-limitations, exit 0;
- compromised release key at revision 2: revoked-key, exit 3;
- withdrawn at revision 2: withdrawn-release, exit 4;
- superseded at revision 2: superseded-release, exit 4;
- corrected at revision 2: corrected-release, exit 4;
- expired at revision 2: expired-release, exit 4.

Changing current status never regenerates the release manifest, release
signature, records, artifacts, static report, or immutable output set.

## Limitations

The verifier proves the supplied chain's internal signature and revision
closure. It cannot prove that this offline chain is the globally latest
distributed revision. Trust-root authenticity and status-chain distribution
freshness are external decisions. There is no trusted timestamp or transparency
log. Verification is not certification, a security proof, Product release
approval, or production readiness.
