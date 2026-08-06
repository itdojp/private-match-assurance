# Security Policy

## Reporting

Do not disclose sensitive evidence, exploit details, secrets, customer information, private source, or internal infrastructure in a public Issue or pull request.

Use GitHub private vulnerability reporting for this repository when available. If unavailable, contact ITDO Inc. through an established private company channel.

## Relevant issues

Reports may concern:

- evidence manifest or digest substitution
- signature, revocation, or verification ambiguity
- provenance misbinding
- schema or validator behavior that accepts misleading evidence status
- sanitization or redaction bypass
- private data exposure through public evidence exports
- report generation that hides failures, skips, timeouts, or unsupported checks
- wording that materially misrepresents evidence as certification or proof

## Safe report content

Include the affected schema, report, verifier, or release version, impact, reproduction using synthetic data where possible, and suggested mitigation. Do not attach raw private evidence.

## Coordinated disclosure

Security-sensitive evidence may remain private or embargoed until remediation and publication approval. Public reports may state that details were withheld. Affected assurance reports may be corrected, superseded, or withdrawn.

## Claim boundary

A valid signature or manifest proves neither security nor correctness. Vulnerability handling must preserve that distinction.

## Signed fixture key boundary

Draft 0.1 contains two intentionally public synthetic fixture private keys only
under `tests/fixtures/public-release/keys/`. They must never be reused for a
Product or production release. The fixture signer accepts no arbitrary key
path, environment-selected key, KMS/HSM URI, cloud credential, or CI secret.
Repository validation allowlists the two exact PEM fixture paths and rejects
fixture private-key material elsewhere.

The public verifier trusts only its explicit external trust-root input; a key
embedded in or supplied solely by a bundle is untrusted. There is no trusted
timestamp or transparency log. Report unexpected key material, cross-usage of
release/status keys, status rollback, digest/path closure bypass, or verifier
network access as a security issue.
