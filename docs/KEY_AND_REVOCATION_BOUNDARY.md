# Release key, status key, and revocation boundary

## Separate fixture authorities

Draft 0.1 uses two distinct synthetic Ed25519 fixture key pairs. The
release-signing key signs only the immutable release-manifest DSSE payload. The
release-status-signing key signs only external status-set revisions.

Key IDs are SHA-256 of exact SPKI DER. Envelope key ID, trust-root key ID,
public-key digest, and recomputed SPKI digest must agree. Cross-usage is
rejected.

Fixture private PEM files are catalogued test material only. No private key,
private-key digest, arbitrary key loader, environment-selected key, KMS/HSM URI,
CI secret, cloud credential, or production signer appears in a bundle,
status-chain package, report, or verifier output.

## External trust root is authoritative

The caller supplies the trust root separately. It alone authorizes the status
signer's trust domain, profile, usage, algorithm, validity interval, and status.
A bundle or status set cannot make a key trusted by embedding or self-asserting
it.

Status sets contain status for release-signing keys and releases. They do not
contain a status-key entry. The status signing key therefore cannot establish
its own authority. The release key cannot sign status updates.

## Revisioned status authority

Revision 1 has a null previous_status_set_digest. Revision N must be N-1 plus
one, strictly later than the prior generation time, and bind the exact prior
status-set digest. Every intermediate signature must validate; a valid final
signature cannot hide an invalid earlier revision. Gaps, duplicates, rollback,
forks, changed trust domain/profile/signer, missing or extra files, and
key/release state rollback fail closed.

The latest declared revision determines current state only after complete-chain
validation. The verifier cannot establish that the caller supplied the globally
latest distributed chain; distribution freshness remains external.

## Conservative compromise rule

There is no trusted timestamp or transparency log. A current compromise
revocation therefore invalidates every signature under the affected release
key. Self-declared manifest or Evidence times do not prove pre-compromise
existence.

## Lifecycle

Correction and supersession require replacement release/bundle identities.
Withdrawal is status-authority signed and does not require the affected release
key. Expiry is determined by manifest validity plus explicit verification time,
or by an externally signed expired release status. No operation rewrites the
immutable release bundle.
