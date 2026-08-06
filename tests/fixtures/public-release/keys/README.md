# Synthetic Ed25519 fixture keys

These keys are public, deterministic test material and are not secrets or
production trust anchors.

- `release-private.pem` / `release-public.pem` use the public Ed25519 test
  material from RFC 8032 Section 7.1, TEST 1.
- `status-private.pem` / `status-public.pem` use the public Ed25519 test
  material from RFC 8032 Section 7.1, TEST 2.

Source: <https://www.rfc-editor.org/rfc/rfc8032.html#section-7.1>.

The pairs are deliberately separate. The fixture signing profile permits the
release pair only for the release-manifest DSSE payload and the status pair
only for the release-status-set DSSE payload. Do not reuse either pair outside
the catalogued `fixture-test` mode.
