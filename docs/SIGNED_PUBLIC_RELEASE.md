# Signed public release bundle Draft 0.1

## Scope and three artifact classes

Draft 0.1 defines public synthetic test-only fixtures. It does not sign a
Product candidate, create a GitHub Release, grant publication approval, select a
production key service, or automate publication.

The architecture has three non-interchangeable classes:

1. **Immutable signed release bundle** — signed content and a closed bundle
   output set. Once signed, no byte is changed for status, time, or verification.
2. **External signed status chain** — independently distributed, revisioned
   release-key and release-lifecycle authority. It is not a bundle member.
3. **Dynamic offline verification result** — invocation output determined by
   one bundle, trust root, selected status chain, and explicit verification
   time. It is written outside the bundle.

## Canonical manifest and DSSE signature

The manifest is strict UTF-8 JSON serialized using RFC 8785 JCS. Parsing rejects
duplicate keys, trailing data, NaN, Infinity, negative zero, integers outside
the interoperable I-JSON range, invalid UTF-8, and unpaired surrogates. Stored
JSON must exactly equal JCS serialization.

manifest_digest is SHA-256 over the exact JCS object with only that detached
field absent. The DSSE v1 envelope signs PAE over the final complete manifest
bytes with the reviewed release-manifest payload type. Draft 0.1 accepts only
ed25519-rfc8032. Algorithm negotiation is absent.

## Immutable bundle closure

The manifest binds A1 claims, assumptions, Evidence, limitations, a synthetic
artifact, CycloneDX SBOM, unsigned provenance, Protocol/conformance authority,
ae-framework/export/Assurance profile authorities, and an immutable static
content-report model.

The immutable bundle layout is:

    manifest/public-release-bundle-manifest.v0.1.json
    signatures/public-release-manifest.dsse.v0.1.json
    records/{claims,assumptions,evidence,limitations}/...
    artifacts/fixture-release-artifact.json
    artifacts/sbom.cdx.json
    artifacts/build-provenance.v0.1.json
    reports/public-release-content-report.v0.1.json
    reports/public-release-content-report.v0.1.md
    public-release-output-set.v0.1.json

The output set binds the exact path set, stored byte digest, size, role,
release-manifest digest, release-envelope digest, immutable report-model digest,
and bundle-tree digest. It does not bind a status-set digest, status signature,
status revision, verification time, or verification-result digest.

Missing, extra, renamed, duplicate, oversized, non-regular, symlinked,
backslash, absolute, drive-qualified, traversal, or stale paths fail closed.

## Static content report

The bundle report contains only facts derived from immutable signed content:
release/subject identity, Protocol/conformance authority, source and
artifact/SBOM/provenance digests, record and Evidence-status counts, declared
claim support, publication boundary, and limitations.

It does not assert current signature validity, current trust, current key
status, current release lifecycle, current verification time, or an overall
verification classification. Those values belong only to a dynamic verifier
result.

The immutable signed Claim declarations use a closed positive-classification
contract: `supported` carries no Assumption reference, while
`supported-with-assumptions` carries at least one. Static reporting preserves
the signed declaration without converting between those states. The offline
verifier rejects an inconsistent positive Claim even when every enclosing
digest and the release signature have been regenerated correctly.

## External status chains

Each independently distributed chain has a closed chain manifest, ordered
revision directories, and a chain output set:

    chain-manifest/public-release-status-chain-manifest.v0.1.json
    revisions/0001/public-release-status-set.v0.1.json
    revisions/0001/public-release-status-set.dsse.v0.1.json
    revisions/0002/...  # when present
    public-release-status-chain-output-set.v0.1.json

Revision 1 has a null previous digest. Each later revision increments exactly
one, is generated strictly later, and binds the previous status-set digest.
Every revision has an exact DSSE signature. The chain and output manifests bind
every path and byte. The declared final revision alone determines current state
after the entire chain validates.

The same immutable bundle is committed once and verified against active,
release-key-revoked, withdrawn, superseded, corrected, and expired chains.
Only chain files and dynamic results differ.

## Fixture generation

The fixture uses committed public Assurance authorities, narrow synthetic A1
records, synthetic artifacts, fixed timestamps, and two synthetic fixture key
pairs. It never reads or clones the private Product repository.

Generate or check the complete suite:

    python scripts/generate_public_release_fixture.py --write
    python scripts/public_release_implementation.py --generate

    python scripts/generate_public_release_fixture.py --check
    python scripts/public_release_implementation.py --check
    python scripts/validate_public_release.py

Generation is deterministic, offline, path-confined, and uses process-owned
repository-local scratch cleaned on success and failure.

## Publication boundary

The fixture is public test data after merge, not a Product release. Artifact
status is test-only, release channel is fixture, publication approval is
not-applicable-test-only, and automation is forbidden. Production signing,
Product signing, key custody, GitHub Release creation, artifact upload, and
publication workflows remain unsupported or absent.
