# ADR-0001: Public assurance repository licensing

- Status: Accepted
- Decision owner: ITDO Inc.
- Decision date: 2026-07-19
- Human approval: Explicitly approved by human direction for the public license review
- Review date: 2026-10-18

## Context

This public repository contains narrative assurance documentation and executable or
machine-consumable validation artifacts. `AGENTS.md` reserves license, patent, and publication
policy changes for explicit human approval. The human direction for this review supplied the
license allocation recorded here.

## Decision

- Narrative documentation, research text, tables, and diagrams use CC BY 4.0.
- Python code, JSON Schemas, validators, tests, fixtures, conformance vectors, GitHub Actions,
  and build inputs use Apache License 2.0.
- `REUSE.toml` is the machine-readable SPDX file mapping, and `LICENSES/` contains the full
  license texts.
- Patent-sensitive or trade-secret candidate material remains private or embargoed until a
  separate human IP and publication approval is recorded.

## Options considered

1. Retain the prior no-additional-license position.
2. Apply one license to all repository content.
3. Apply the approved license according to artifact type.

Option 3 was selected to distinguish software/reference artifacts from narrative material.

## Security, privacy, and claims assumptions

- Licensing does not establish evidence truth, protocol or product security, certification,
  production readiness, legal compliance, or publication approval for a report.
- Public-boundary review continues to exclude private source, raw evidence, customer data,
  credentials, private infrastructure, vulnerability details, inventions, and patent candidates.
- Apache-2.0 patent provisions do not replace the separate human patent/publication gate.

## Evidence

- The explicit human public-license decision supplied for this review.
- `REUSE.toml` and the complete texts in `LICENSES/`.
- `reuse lint` in the pull-request validation workflow.

## Rejected alternatives

- The no-license option was rejected because public validation/reference artifacts require an
  explicit license.
- A single license was rejected because it does not express the approved distinction between
  code/reference artifacts and narrative documentation.

## Compatibility impact

This decision changes the repository from no additional public license to an explicit mapping.
It does not alter evidence status, lifecycle, claim meaning, schema version, or publication
approval. New artifact categories require an explicit SPDX mapping before publication.
