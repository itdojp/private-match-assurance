# Private Match ae-framework Assurance report

## Authority and boundary

- artifact status: `test-only`
- integration profile: `private-match-ae-assurance/0.1`
- integration profile digest: `sha256:d74800c7963c2b6864d912cdc4764bb295d1442dff8ddcb9933a8c79a5b2ba28`
- ae-framework repository: `itdojp/ae-framework`
- ae-framework commit: `bba9b6846608359b87ed5393cb208e321f3ba8af`
- ae-framework package: `ae-framework@1.0.0`
- ae-framework source tree: `sha256:f9348a5f49d7c5d7e01e53914829434a3d43d9c048eaae56171ca67c93391729`
- native input manifest digest: `sha256:58521825cec943203057dea81589656013593d4ad0c098a67fa326680b8b25e7`
- Protocol authority: `private-match-core-conformance/0.1`
- Protocol: `private-match-core/0.1`
- conformance suite: `private-match-core/0.1`
- conformance suite digest: `sha256:83787c69ec1128eb9ba4b8dcdfcb4ae218674b6158cd8c6c573d898a6f72ceba`
- producer package created at: `2030-01-01T00:01:00Z`
- validation recorded at: `2030-01-01T00:02:00Z`
- validation producer package digest: `sha256:d60c30af2bfd8e20a7ed0343c87fd6290672bf2c7cb1c3c4f598bb4697679081`
- package digest: `sha256:8d308c5cfbfd96f433d17a8df4f8548395e4c1ef9ce18b0847f3b6e47f456bca`
- JSON report model digest: `sha256:f6306f54c55c7f7623dd760de1141bd9bc729426c3e6c212e259e783e47becaa`
- Markdown report model digest: `sha256:167e216a65f7bbafa4ebe9016bd2175cd32ff1c4334052489e5734fb6ceb526e`

ae-framework organizes supplied Evidence; it is not a security proof oracle.

ae-framework is not a certification authority.

Automated satisfaction is not human approval or publication approval.

## Embedded producer package

- package ID: `PMAE-PRODUCER-REQUIRED-TIMEOUT-V0-1`
- mode: `fixture-test`
- artifact status: `test-only`
- subject: `synthetic-private-match-product/0.1`
- subject digest: `sha256:7ade5b2504d5a6e612552b73faec151935b4495bceeb0092115f1203f1fd8a56`
- producer package digest: `sha256:d60c30af2bfd8e20a7ed0343c87fd6290672bf2c7cb1c3c4f598bb4697679081`
- created at: `2030-01-01T00:01:00Z`
- validated at: `2030-01-01T00:02:00Z`
- Protocol authority: `private-match-core-conformance/0.1`

## Producer Evidence

| Evidence ID | producer type | producer | tool role | execution tool | version | status |
|---|---|---|---|---|---|---|
| PM-EVIDENCE-0001 | ci | synthetic-ci-producer | PMAE-CI-PIPELINE-V0-1 | private-match-synthetic-ci | 1.0.0 | pass |
| PM-EVIDENCE-0002 | test-runner | synthetic-test-runner-producer | PMAE-CONFORMANCE-RUNNER-V0-1 | private-match-synthetic-conformance-runner | 1.0.0 | timeout |
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
| fail | 0 |
| skip | 2 |
| unsupported | 1 |
| timeout | 1 |
| tool-error | 0 |

## Required gates

| tool | status | gate | limitation |
|---|---|---|---|
| PMAE-CI-PIPELINE-V0-1 | pass | satisfied | Pass is limited to the stated reviewed check and does not prove Product correctness. |
| PMAE-CONFORMANCE-RUNNER-V0-1 | timeout | blocked | Timeout is preserved and is not converted to fail. |

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
- approval subject: `sha256:678db5c713d44c7a6672e371d7bd61e482239f7286d09a8ff0c775784f77dbf6`
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
