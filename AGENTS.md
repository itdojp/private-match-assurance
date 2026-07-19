# AGENTS.md

## Purpose

This repository publishes sanitized, release-scoped assurance evidence for Private Match.

## Work model

- Work from a GitHub Issue.
- Use one branch and pull request per issue.
- Do not push directly to `main`.
- Do not merge pull requests.
- Do not create new issues unless a human explicitly requests it.
- Keep each change scoped to a named claim, schema, report, or publication process.

## Public boundary

Never publish:

- private service source code
- customer or interview data
- raw production logs or packet captures containing sensitive values
- secrets, internal account IDs, private hostnames, or internal topology
- exploit details before remediation approval
- abuse-detection rules or thresholds
- unpublished inventions or patent candidates
- evidence that cannot be traced to a reviewed source and revision

When raw evidence is needed, reference a digest and approved metadata rather than copying the evidence.

## Assurance rules

1. Every claim must name its scope, subject, version, assumptions, and evidence.
2. Every evidence item must record producer, tool, version, time, input digest,
   output digest, result status, and lifecycle.
3. `pass`, `fail`, `skip`, `unsupported`, `timeout`, and `tool-error` are distinct states.
4. A skipped or unavailable check must not be represented as passed.
5. Model-checking evidence must publish configuration and state-space bounds.
6. Conformance evidence must name the protocol and suite version.
7. Provenance evidence establishes origin, not safety.
8. Internal review by ITDO Inc. must not be called independent certification.
9. Claims must include known limitations and expiry or supersession where applicable.
10. Publication must be reproducible from a reviewed export contract.

## ae-framework boundary

`itdojp/ae-framework` organizes specifications, evidence, policy gates, and release judgments. It is not itself proof that Private Match is secure or correct.

Record:

- ae-framework version and commit
- policy/profile version
- invoked external tools and versions
- which judgments were automated and which were human

## Context conflicts

Inspect the issue, `README.md`, `GOVERNANCE.md`, `docs/EVIDENCE_MODEL.md`, and `docs/CLAIMS_POLICY.md`.

Report:

```text
Context Pack conflict: none
```

or

```text
Context Pack conflict: found
```

Do not silently resolve conflicts in claims, redaction, publication, provenance, or evidence status.

## Pull request body

Include:

- linked issue
- claim or evidence scope
- public/private boundary check
- source and revision provenance
- schemas or policies affected
- validation performed
- skipped or unavailable checks
- redaction and sanitization review
- known limitations
- `Context Pack conflict` result

## Human-only decisions

Require explicit human approval for:

- publishing a release assurance report
- accepting a material exception
- weakening a claim or evidence requirement
- describing evidence as independent or certified
- publishing vulnerability information
- changing the patent, license, or publication policy
- withdrawing or superseding a public report
