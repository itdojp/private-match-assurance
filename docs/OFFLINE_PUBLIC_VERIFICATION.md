# Offline public release verification Draft 0.1

## Command

The reference verifier uses only explicit local inputs:

```bash
python scripts/verify_public_release_bundle.py \
  --bundle-root tests/fixtures/public-release/expected/active \
  --trust-root tests/fixtures/public-release/trust/fixture-trust-root.v0.1.json \
  --status-set tests/fixtures/public-release/expected/active/status/public-release-status-set.v0.1.json \
  --status-signature tests/fixtures/public-release/expected/active/status/public-release-status-set.dsse.v0.1.json \
  --verification-time 2026-08-02T00:00:00Z \
  --output-json .codex-local/tmp/public-release-verification.json \
  --output-md .codex-local/tmp/public-release-verification.md
```

Output parents must already be trusted, non-symlink directories and output
files must not exist. `verification-time` is mandatory and canonical UTC; the
fixture profile does not use the wall clock.

The command performs no network, DNS, GitHub API, registry, private-repository,
or private-key access. It invokes only the resolved exact Node.js 22.22.2
executable with a fixed argument array, `shell=false`, a controlled environment,
a bounded timeout, and bounded standard streams. Node performs only DSSE PAE
Ed25519 sign/verify primitives. Python performs strict parsing, JCS,
Schema/digest/path validation, trust and lifecycle policy, report derivation,
and verifier orchestration.

## Ordered verification stages

1. **Output-set structure** — validate the exact path set, regular-file and
   symlink boundary, byte digests, sizes, roles, tree digest, and output-set
   semantic digest.
2. **External trust** — validate the caller-supplied trust-root Schema/digest,
   trust domain, key identity derived from SPKI DER, algorithm, encoding,
   usage, validity interval, and status. A key appearing only inside a bundle is
   never trusted.
3. **Release signature** — validate the DSSE profile and payload type and verify
   Ed25519 over exact DSSE PAE of the exact stored manifest bytes.
4. **Manifest** — require exact RFC 8785 bytes, Schema validity, detached
   manifest digest, fixed fixture authority, exact content path/digest closure,
   and deterministic reconstruction from independently loaded content.
5. **Status signature and lifecycle** — verify the distinct status key, signed
   status-set digest and entries, chain/revision constraints, key/release
   binding, and effective time. Release-key status cannot be self-authorized.
6. **Records and claims** — validate A1 records, unique IDs, subjects, record-set
   digests, references, all six Evidence statuses, and claim-support policy.
7. **Artifacts and reports** — reconstruct the synthetic artifact, SBOM, and
   unsigned provenance; reconstruct the JSON report; generate Markdown only
   from that JSON; require exact report linkage.
8. **Overall result** — preserve signature, trust, structure, digest, report,
   lifecycle, and claim results as distinct fields.

The JSON result is authoritative. Stderr contains only bounded reason-class
text and never includes input values, paths, keys, or subprocess output.

## Stable overall statuses

Draft 0.1 recognizes:

- `verified-fixture`
- `verified-fixture-with-limitations`
- `invalid-signature`
- `untrusted-key`
- `revoked-key`
- `unsupported-algorithm`
- `invalid-structure`
- `incomplete-bundle`
- `invalid-report-linkage`
- `withdrawn-release`
- `superseded-release`
- `corrected-release`
- `expired-release`
- `claims-not-supported`
- `not-evaluated`

The result retains separate signature, trust, structure, digest closure,
report linkage, lifecycle, Evidence-status counts, and per-claim fields. A
single boolean is intentionally insufficient.

## Stable exit codes

| Code | Class |
| ---: | --- |
| 0 | mechanically verified fixture; structure, digests, signature, and supplied trust are valid |
| 1 | invalid signature, digest, structure, exact path set, or report linkage |
| 2 | unsupported algorithm, profile, or version |
| 3 | untrusted, invalid, expired, or revoked key |
| 4 | withdrawn, superseded, corrected, expired, or not-yet-valid release |
| 5 | mechanically valid bundle whose required claims are unsupported or not evaluated |

Consumers must inspect the JSON result and must not infer claim support,
publication approval, or Product readiness from exit code 0 alone.

## Verification limitations

A valid fixture signature establishes origin and integrity only relative to the
supplied fixture trust root. The bundle cannot authenticate that trust root.
There is no trusted timestamp or transparency log. The status set is an
explicit external input whose authentic and current distribution remains a
verifier trust decision. Verification is not certification, a security proof,
Product release approval, or production readiness.
