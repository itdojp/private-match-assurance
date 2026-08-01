# Private Match ae-framework Assurance report

## Authority and boundary

- artifact status: `test-only`
- integration profile: `private-match-ae-assurance/0.1`
- integration profile digest: `sha256:1ca9838e28a723fad7666aa187aeed77f19ae2b250b4dbc5958ec36e3e1276c5`
- ae-framework repository: `itdojp/ae-framework`
- ae-framework commit: `bba9b6846608359b87ed5393cb208e321f3ba8af`
- ae-framework package: `ae-framework@1.0.0`
- ae-framework source tree: `sha256:f9348a5f49d7c5d7e01e53914829434a3d43d9c048eaae56171ca67c93391729`
- native input manifest digest: `sha256:17320035e834b7543f7593905e69db9e57f5449936a96c33d26c5b6646fc5bb3`
- Protocol authority: `private-match-core-conformance/0.1`
- Protocol: `private-match-core/0.1`
- conformance suite: `private-match-core/0.1`
- conformance suite digest: `sha256:83787c69ec1128eb9ba4b8dcdfcb4ae218674b6158cd8c6c573d898a6f72ceba`
- producer package created at: `2030-01-01T00:01:00Z`
- producer validation asserted at: `2030-01-01T00:02:00Z`
- producer timestamp source: `producer-supplied-digest-bound`
- runner validation: `performed=True; timestamp not-recorded-for-deterministic-offline-execution`
- validation producer package digest: `sha256:de0c5030d7e9c2a512eca98929b174c58fafc432636e1670a662ba0fd1ea394b`
- package digest: `sha256:671d9e1157c4b95947ba2a0ff6e4141e78e660ada570b30aeda00482195c54fd`
- JSON report model digest: `sha256:a523636a317a8cae98f56f495087ecd39ca882939f8633b6304d21d029566be3`
- Markdown report model digest: `sha256:a486f4dc0638537767ce017b4b8b5ef3dc365560b28a84b98d3d355d85a6cdab`

ae-framework organizes supplied Evidence; it is not a security proof oracle.

ae-framework is not a certification authority.

Automated satisfaction is not human approval or publication approval.

## Embedded producer package

- package ID: `PMAE-PRODUCER-REQUIRED-FAIL-V0-1`
- mode: `fixture-test`
- artifact status: `test-only`
- subject: `synthetic-private-match-product/0.1`
- subject digest: `sha256:2b733c2320be302be09729ff4af5331798e2ac9c66ba83bd7dcb1e841241347b`
- producer package digest: `sha256:de0c5030d7e9c2a512eca98929b174c58fafc432636e1670a662ba0fd1ea394b`
- created at: `2030-01-01T00:01:00Z`
- producer validation asserted at: `2030-01-01T00:02:00Z`
- producer timestamp source: `producer-supplied-digest-bound`
- Protocol authority: `private-match-core-conformance/0.1`

## Producer Evidence

| Evidence ID | producer type | producer | tool role | execution tool | version | status |
|---|---|---|---|---|---|---|
| PM-EVIDENCE-0001 | ci | synthetic-ci-producer | PMAE-CI-PIPELINE-V0-1 | private-match-synthetic-ci | 1.0.0 | pass |
| PM-EVIDENCE-0002 | test-runner | synthetic-test-runner-producer | PMAE-CONFORMANCE-RUNNER-V0-1 | private-match-synthetic-conformance-runner | 1.0.0 | fail |
| PM-EVIDENCE-0003 | formal-tool | synthetic-formal-tool-producer | PMAE-FORMAL-TOOL-V0-1 | private-match-synthetic-formal-tool | 1.0.0 | skip |
| PM-EVIDENCE-0004 | security-tool | synthetic-security-tool-producer | PMAE-SECURITY-TOOL-V0-1 | private-match-synthetic-security-tool | 1.0.0 | unsupported |
| PM-EVIDENCE-0005 | human-review | synthetic-human-review-producer | PMAE-HUMAN-REVIEW-V0-1 | private-match-synthetic-review-contract | 1.0.0 | skip |

## External tool inventory

| tool role | producer type | requirement | identity | version | implementation digest |
|---|---|---|---|---|---|
| PMAE-CI-PIPELINE-V0-1 | ci | required | private-match-synthetic-ci | 1.0.0 | sha256:5a0d72c03773a0fc9fc274f1cad6cbe1cf8010a376d37814bbc7344a8863d066 |
| PMAE-CONFORMANCE-RUNNER-V0-1 | test-runner | required | private-match-synthetic-conformance-runner | 1.0.0 | sha256:6be73d5936f68483eb035c61bc2d2d051e02181f1d6466686fbba55cf599bde2 |
| PMAE-FORMAL-TOOL-V0-1 | formal-tool | optional | private-match-synthetic-formal-tool | 1.0.0 | sha256:9090107bc871011530c4283043f4dfafa0bdea91e3e4520daf73386db13749e7 |
| PMAE-SECURITY-TOOL-V0-1 | security-tool | optional | private-match-synthetic-security-tool | 1.0.0 | sha256:2e18e6bc8a77b167a92ecd08e2526d3500a5dea153511f7c1d0b1747db2db7b0 |
| PMAE-HUMAN-REVIEW-V0-1 | human-review | optional | private-match-synthetic-review-contract | 1.0.0 | sha256:98b4f3965b9bca87a07ab6af51a5bcfb698fcfaca0d01d799ff47401bc58b85c |

## Status counts

| status | count |
|---|---|
| pass | 1 |
| fail | 1 |
| skip | 2 |
| unsupported | 1 |
| timeout | 0 |
| tool-error | 0 |

## Required gates

| tool | status | gate | limitation |
|---|---|---|---|
| PMAE-CI-PIPELINE-V0-1 | pass | satisfied | Pass is limited to the stated reviewed check and does not prove Product correctness. |
| PMAE-CONFORMANCE-RUNNER-V0-1 | fail | blocked | Failure remains visible and blocks a required gate. |

## Optional gates

| tool | status | gate | limitation |
|---|---|---|---|
| PMAE-FORMAL-TOOL-V0-1 | skip | visible-nonblocking | Skipped work is not evidence of successful execution. |
| PMAE-SECURITY-TOOL-V0-1 | unsupported | visible-nonblocking | Unsupported capability is not converted to pass. |
| PMAE-HUMAN-REVIEW-V0-1 | skip | visible-nonblocking | Skipped work is not evidence of successful execution. |

## Judgment and human approval boundary

- automated judgment: `blocked`
- producer gate judgment: `blocked`
- native ae judgment: `blocked`
- native warning treatment: `blocking`
- human approval: `not-applicable-test-only`
- reviewer role: `synthetic-reviewer`
- approval subject: `sha256:f5bd2033ef740e00b26baef826bb72246f2838554312123307c024c9581eee32`
- boundary generated by automation: `True`
- approval decision present: `False`

## Native ae-framework judgment

| claim | native status | required lanes | observed lanes | missing lanes | required Evidence kinds | observed Evidence kinds | missing Evidence kinds | warning codes | policy treatment |
|---|---|---|---|---|---|---|---|---|---|
| supplied-evidence-contract | warning | behavior, runtime | runtime | behavior | integration, runtime-control | runtime-control | integration | insufficient-independent-lanes, missing-spec-derived-evidence | blocking |

## Limitations

- ae-framework organizes supplied Evidence and is not an oracle of truth.
- This package is neither a security proof nor certification.
- Automated satisfaction is not human approval or publication approval.
- Synthetic fixtures do not establish Product or Protocol correctness.
- No live Product Evidence, private input, or public export is included.
- Native ae-framework warnings remain visible and do not rewrite producer statuses.
- Embedding proves internal producer-to-Assurance consistency but does not independently authenticate producer metadata.
- Producer validation time is a supplied digest-bound assertion, not runner execution time.
- Runner validation is performed but its wall-clock time is not recorded in deterministic output.
