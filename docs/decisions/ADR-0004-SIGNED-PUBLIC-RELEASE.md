# ADR-0004: fixture-first signed public Assurance release

- Status: proposed
- Date: 2026-08-06

## Context

The Assurance repository needs a reviewable public release container whose
origin, byte integrity, public records, artifact references, reports, and
lifecycle can be checked offline. The current repository has only synthetic
public export and private/internal ae-framework fixtures. No production Product
release, production signing authority, trusted timestamp, publication
approval, or automated publication flow exists.

## Options considered

### Raw signature versus DSSE

A raw signature leaves payload-type separation and framing to every caller.
DSSE provides a reviewed pre-authentication encoding and a small envelope while
leaving trust policy explicitly out of band. Draft 0.1 selects DSSE v1.0.2 with
separate release-manifest and status-set payload types.

### JWS versus DSSE

JWS could carry algorithm and payload metadata but introduces a different
canonicalization/serialization and header policy surface. The existing design
needs one exact manifest byte sequence and explicit external trust. DSSE is
selected for its narrow payload-type binding and fixed PAE. JWS is not accepted
as an alternate encoding.

### Signing canonical manifest bytes versus signing only a digest

Signing only a digest would require an additional mapping from parsed manifest
to signed value and could hide byte-level ambiguity. Draft 0.1 signs the exact
complete RFC 8785 manifest bytes. `manifest_digest` is SHA-256 of the same JCS
object with only its self-referential digest field detached; the final complete
manifest bytes are the DSSE payload.

### Ed25519 versus algorithm agility

Algorithm agility in one version increases downgrade and negotiation risks.
Draft 0.1 accepts only `ed25519-rfc8032` and uses Node.js 22.22.2 built-in
`crypto`; RFC 8032 Section 7.1 vectors validate the primitive. Unknown
algorithms fail closed. Another algorithm requires a new reviewed profile.
No new cryptographic package is added. The existing Ajv graph is retained; a
narrow pnpm override resolves its affected `fast-uri` 3.x transitive dependency
to patched `3.1.5` for GHSA-7p8r-x3mc-p8w7 without suppressing audit findings.

### Bundle key versus external trust root

A key carried only by a bundle proves self-consistency, not trust. Draft 0.1
requires a separate explicit trust-root input. Key IDs are SHA-256 of SPKI DER,
and the envelope, trust entry, public-key digest, and recomputation must agree.
Trust-root authenticity remains external.

### One key versus separate release and status keys

Using one key would require a compromised release key to revoke itself and
would combine immutable release origin with mutable lifecycle authority. Draft
0.1 uses distinct fixed fixture key pairs and payload types. Release keys can
sign only manifests; status keys can sign only status sets.

### Mutable manifest versus immutable bundle plus signed status

Rewriting a signed manifest for withdrawal or correction destroys the original
byte authority. Draft 0.1 keeps each bundle immutable and applies expiry, withdrawal,
supersession, correction, and key status through an independently distributed,
revisioned signed status chain. The immutable output set binds neither status
bytes nor dynamic verifier output. Corrections and supersessions require new
release/bundle identities and explicit replacement references.

### Bundled status/current report versus external status chain/dynamic result

Binding mutable status and time-dependent verifier output into a release output
set would require rewriting otherwise unchanged release bytes. Draft 0.1 instead
commits one immutable static content report, distributes signed status revisions
under a separate closed chain manifest/output set, and writes dynamic verifier
JSON/Markdown outside the bundle. This permits a later compromise, withdrawal,
supersession, correction, or expiry revision to apply to the original signed
bundle. The verifier validates the supplied chain but cannot prove global
distribution freshness.

### Bundle timestamp versus trusted timestamp

A signed self-declared timestamp is not an external time attestation. No
trusted timestamp or transparency log is selected. A compromise revocation is
therefore conservative and invalidates all signatures under that key,
regardless of bundle time.

### Production KMS versus fixture-only key

Selecting KMS/HSM technology, custody roles, cloud credentials, or a production
private key is a production security decision outside Issue #6. Draft 0.1
implements only two exact catalogued synthetic fixture keys. There is no
production signer and no arbitrary key-loader interface.

### Automated publication versus explicit human publication

A valid signature and green CI do not supply IP, privacy, security, or release
approval. Draft 0.1 prohibits automatic publication, artifact upload, GitHub
Release creation, and Product signing. A future real publication remains a
separate human-approved export, signing, and publication sequence.

### Bundled verifier versus offline reference CLI

Embedding trust or network discovery in a bundle would let the subject choose
its own authority and would make results environment-dependent. Draft 0.1
provides a repository reference CLI that accepts one explicit immutable bundle,
trust root, closed status-chain root, and verification time. It performs no network or
private-repository access and emits deterministic JSON authority plus derived
Markdown.

## Decision

Adopt:

- strict UTF-8 and RFC 8785 JCS for manifest and bundle JSON;
- DSSE v1.0.2 PAE over the exact complete manifest/status bytes;
- Ed25519 only for Draft 0.1 through pinned Node.js 22.22.2 built-in crypto;
- separate release-signing and status-signing fixture keys;
- SHA-256 of SPKI DER as key identity;
- an external explicit trust root;
- immutable release content, an external revisioned signed status chain, and dynamic verifier outputs as three separate artifact classes;
- conservative compromise revocation without trusted time;
- separate exact path/digest/size/role closures for the immutable bundle and external status chain;
- A1 claim evaluation independent of signature validity;
- a closed positive Claim contract in which `supported` has no Assumption
  references and `supported-with-assumptions` has one or more;
- stable structured results and exit codes;
- a fixture-only signer and complete deterministic public fixture;
- no production KMS, production key, real Product Evidence, automatic
  publication, upload, GitHub Release, certification, or readiness claim.

## Consequences

The test key is intentionally public and proves implementation behavior only.
An attacker can reproduce fixture signatures, so fixture trust has no
production meaning. The external trust-root/status-chain freshness problem and historical
validation after compromise remain unsolved until separate
production key-custody and timestamp/transparency decisions are reviewed.

The repository gains additional Schemas, profiles, deterministic artifacts,
Node/Python orchestration, and mutation tests. Changes to a bound implementation
or fixture authority require regenerating the implementation manifest and
fixture catalog. The public report states that signature validity is origin and
integrity relative to the supplied trust input, not security certification,
Product correctness, publication approval, pilot readiness, or production
readiness.

The verifier does not reinterpret signed Claim classification. A positive
Claim whose Assumption references contradict its signed status is invalid
structure, including after complete redigesting and fixture re-signing. This
Draft 0.1 correction keeps the existing Schema version because PR #11/#12 form
one unmerged external compatibility surface and all previously committed valid
Claims already satisfy the narrower invariant.
