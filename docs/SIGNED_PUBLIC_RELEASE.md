# Signed public release bundle Draft 0.1

## Scope

Draft 0.1 defines a fixture-first public Assurance release format. It signs only
catalogued, synthetic `test-only` content. It does not sign a Product candidate,
create a GitHub Release, grant publication approval, select a production key
service, or automate publication.

The release authority consists of:

- `config/public-release-signing-standards.v0.1.json`;
- `profiles/public-release-signing.v0.1.json`;
- `profiles/public-release-verification.v0.1.json`;
- the closed Schemas under `schema/public-release-*.v0.1.schema.json`;
- `manifests/public-release-verifier-implementation.v0.1.json`; and
- `tests/fixtures/public-release/fixture-catalog.v0.1.json`.

## Canonical manifest and signature

The unsigned manifest is strict UTF-8 JSON serialized with RFC 8785 JSON
Canonicalization Scheme (JCS). Parsing rejects duplicate keys, trailing data,
NaN, Infinity, negative zero, integers outside the interoperable I-JSON range,
invalid UTF-8, and unpaired surrogates. Stored JSON must equal the exact JCS
serialization of the parsed value.

`manifest_digest` is detached to avoid self-reference: it is SHA-256 over the
exact JCS manifest bytes with only `manifest_digest` absent. The final manifest,
including that digest, is serialized again with JCS. The release DSSE envelope
signs those complete final bytes, not a projection or the digest alone.

Draft 0.1 uses DSSE v1 pre-authentication encoding:

```text
DSSEv1 SP LEN(payload-type) SP payload-type SP LEN(payload) SP payload
```

The exact payload type is:

```text
application/vnd.itdo.private-match.assurance-release-manifest.v0.1+json
```

The envelope contains one signature and is itself deterministic JCS JSON. The
only accepted algorithm is `ed25519-rfc8032`. Algorithm negotiation is absent;
a new algorithm requires a new reviewed profile version.

## Immutable content and exact path closure

The manifest binds the immutable unsigned release content:

```text
records/claims/
records/assumptions/
records/evidence/
records/limitations/
artifacts/fixture-release-artifact.json
artifacts/sbom.cdx.json
artifacts/build-provenance.v0.1.json
```

Each entry binds its exact POSIX-relative path, SHA-256 of stored bytes, size,
and role. `content_tree_digest` binds the ordered content manifest. The release
manifest also binds the Protocol and conformance authority, the exact
ae-framework and export/Assurance profiles, the record-set digests, every
Evidence record digest, every non-null Evidence output digest, the report model,
and the release/status signing profile.

Reports, DSSE envelopes, and the separately signed status set are derived or
mutable-control surfaces rather than unsigned release content. The output-set
manifest binds all of them, plus the immutable content and release manifest. It
uses an exact path list, per-file roles/digests/sizes, and a complete bundle tree
digest. Its own semantic digest detaches only `output_set_digest`.

The committed active fixture has this closed layout:

```text
manifest/public-release-bundle-manifest.v0.1.json
signatures/public-release-manifest.dsse.v0.1.json
records/{claims,assumptions,evidence,limitations}/...
artifacts/fixture-release-artifact.json
artifacts/sbom.cdx.json
artifacts/build-provenance.v0.1.json
reports/public-release-report.v0.1.json
reports/public-release-report.v0.1.md
status/public-release-status-set.v0.1.json
status/public-release-status-set.dsse.v0.1.json
public-release-output-set.v0.1.json
```

Missing, extra, duplicate, renamed, oversized, non-regular, symlinked,
backslash, absolute, drive-qualified, traversal, or digest-stale paths fail
closed.

## Fixture content and claims

The fixture is constructed only from committed public Assurance authorities,
synthetic A1 records, a synthetic artifact, a synthetic CycloneDX 1.6 SBOM,
unsigned synthetic build provenance, fixed timestamps, and the exact two
fixture keys. It does not read or clone the private Product repository.

Claims are deliberately mechanical: signature verification relative to the
supplied fixture trust root, path/digest/report linkage, exact public authority
references, and `test-only` classification. They do not claim Product security,
privacy, correctness, compliance, certification, or readiness.

Signature validity and claim support are evaluated separately. A signature
never promotes a claim. Referenced `fail` Evidence produces `not-supported`;
`skip`, `unsupported`, `timeout`, or `tool-error` produces `not-evaluated`;
missing or inconsistent references produce `invalid-reference`.

## Fixture generation

Generate the committed fixture only through the reviewed generator:

```bash
python scripts/generate_public_release_fixture.py --write
python scripts/public_release_implementation.py --generate
```

Check committed bytes without changing them:

```bash
python scripts/generate_public_release_fixture.py --check
python scripts/public_release_implementation.py --check
python scripts/validate_public_release.py
```

Generation uses fixed timestamps, fixed synthetic keys, fixed identifiers, no
network, no environment-selected paths, and a process-owned repository-local
scratch directory. The scratch parent hierarchy is inspected without following
symlinks, the process directory is mode `0700` on POSIX, and it is removed on
success and failure.

## Publication boundary

The fixture bundle is public test data after merge, not a Product release.
`artifact_status` is `test-only`, the channel is `fixture`, final publication
approval is `not-applicable-test-only`, and automation is forbidden.
Production signing, Product signing, production key custody, GitHub Release
creation, CI artifact upload, and publication workflows are unsupported or
absent. A future real release requires a reviewed public export candidate,
explicit human publication approval, a reviewed production trust root and
signing authority, a separate signing operation, and a separate publication
operation.
