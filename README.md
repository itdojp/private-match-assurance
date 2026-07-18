# Private Match Assurance

Public assurance evidence repository for named Private Match protocol and product releases.

This repository publishes reviewable claims, assumptions, evidence manifests, verification summaries, provenance, and known limitations. It does not publish the private commercial source code or claim independent certification by ITDO Inc.

## Repository role

This repository is the public system of record for:

- release-scoped assurance claims
- explicit assumptions and non-goals
- signed evidence manifests
- protocol, conformance-suite, source-revision, and artifact digests
- sanitized test, model-checking, security, and interoperability summaries
- software bills of materials and provenance references where publishable
- known limitations, exceptions, withdrawals, and supersession notices
- the exact ae-framework version and policy profile used to organize evidence

## Claim boundary

An assurance report may support statements such as:

- a named build was tested against a named conformance-suite version
- a named formal model was checked under a published bounded configuration
- specified tests passed, failed, skipped, timed out, or were unsupported
- a release artifact was produced by an identified build workflow

It does not by itself establish:

- absence of vulnerabilities or side channels
- cryptographic security beyond the cited assumptions and external analyses
- correctness or completeness of private input data
- legal or regulatory compliance
- safe operation of every deployment
- independent certification

## Public / private boundary

Never publish:

- customer data or identifiers
- private source code
- raw production logs
- secrets or internal topology
- exploitable vulnerability details before remediation
- abuse-detection thresholds
- unpublished inventions or patent candidates
- evidence whose origin or redaction cannot be established

## Related repositories

- `itdojp/private-match-protocol` — public protocol specifications and conformance assets
- `itdojp/private-match-research` — public research
- `itdojp/private-match-product` — private implementation and raw evidence production
- `itdojp/private-match-strategy` — private publication, IP, and business decisions
- `itdojp/ae-framework` — assurance control plane

## Maturity

The repository is in bootstrap. No public assurance report for a production Private Match release exists yet.
