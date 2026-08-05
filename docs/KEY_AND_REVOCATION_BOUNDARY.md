# Release key, status key, and revocation boundary

## Separate fixture authorities

Draft 0.1 contains two distinct synthetic Ed25519 fixture key pairs:

- the **release-signing** key signs only the public release manifest DSSE
  payload;
- the **release-status-signing** key signs only the release/key status-set DSSE
  payload.

The key IDs are SHA-256 digests of exact SPKI DER bytes. The DSSE key ID, trust
root key ID, public-key digest, and recomputed SPKI digest must be identical.
The signer and Node primitive reject cross-usage: the release key cannot sign a
status payload and the status key cannot sign a release payload.

The fixture private PEM files exist only at:

```text
tests/fixtures/public-release/keys/release-private.pem
tests/fixtures/public-release/keys/status-private.pem
```

They are public synthetic test material, not secrets and not production trust
anchors. The signing profile catalogs the exact paths, and repository
validation treats only these two PEM headers as allowed fixture private-key
material. The implementation manifest deliberately binds only public key
files; no private-key bytes or private-key digest is emitted in the bundle,
report, catalog digest surfaces, logs, or verifier output. No arbitrary key
path, environment-selected key, KMS/HSM URI, CI secret, cloud credential, or
production signer interface exists.

## External trust root

The verifier requires an external `public signing trust root`. It binds a trust
domain and revision, permitted profile, key usages, algorithm and encoding,
SPKI public key, key ID/digest, validity interval, status, and limitations. A
bundle-embedded or attacker-supplied key is not promoted to trust.

The committed trust root is only a fixture. Its authenticity is an external
choice made by the verifier/caller and is not established by the signed
bundle. A production trust-root distribution or key-custody design remains
unselected.

## Signed status authority

Key and release lifecycle state is carried in a separate JCS status set signed
by the status key with payload type:

```text
application/vnd.itdo.private-match.assurance-release-status-set.v0.1+json
```

Each key entry binds key ID, usage, status, effective time, reason,
replacement, compromise indicator, and a detached entry digest. Each release
entry binds release ID, manifest digest, state, effective time, reason,
replacement release/digest, notice digest, and entry digest. The set binds its
revision, generation time, previous-set digest, ordered entry-set digest,
status signer, and detached set digest.

The release key does not authorize key status, revocation, withdrawal,
correction, or supersession. The status key cannot sign release manifests. An
immutable signed release bundle is never rewritten to change its lifecycle.

## Conservative compromise rule

Draft 0.1 has no trusted timestamp authority. Therefore a release key currently
revoked for compromise revokes every signature under that key. A manifest
`created_at`, Evidence timestamp, or self-declared signing time does not prove
that a signature predates compromise. Historical validation would require a
future reviewed trusted-timestamp or transparency-log policy.

## Lifecycle operations

- **Correction** creates a new signed release/bundle revision with a `corrects`
  reference, while the status authority marks the old release `corrected` and
  identifies the replacement.
- **Supersession** creates a new signed release and a status entry marking the
  previous release `superseded` with the replacement identity/digest.
- **Withdrawal** is a status-key-signed entry with a notice digest; it does not
  require the affected or compromised release key.
- **Expiry** uses the signed manifest validity interval plus the explicit
  verifier-supplied time. No wall-clock default exists.

The active fixture is immutable. Tests create ephemeral active, expired,
withdrawn, superseded, corrected, and revoked-key variants and assert stable
statuses and exit codes. They do not publish those variants as Product
releases.
