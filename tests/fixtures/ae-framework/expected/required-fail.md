# Private Match ae-framework Assurance report

## Authority and boundary

- artifact status: `test-only`
- integration profile: `private-match-ae-assurance/0.1`
- integration profile digest: `sha256:5c47b4b4e71c1c9448200b97d97c4d54d7e3b5ef0b1d59c3aaa5cf684f560280`
- ae-framework repository: `itdojp/ae-framework`
- ae-framework commit: `bba9b6846608359b87ed5393cb208e321f3ba8af`
- ae-framework package: `ae-framework@1.0.0`
- ae-framework source tree: `sha256:f9348a5f49d7c5d7e01e53914829434a3d43d9c048eaae56171ca67c93391729`
- package digest: `sha256:672717dd0e273726615e6e5624b4b6d8aba3c64419fbf20a8f974e139583cdb2`
- JSON report semantic digest: `sha256:aae2270019db17282a11ec47b3ce6fa149f06c413e2139db1713378112328779`
- Markdown report semantic digest: `sha256:f24d3af95ede8e84aa024bd0f8ce2e3f2b94e5872aa5e5bd0973e624b58e205b`

ae-framework organizes supplied Evidence; it is not a security proof oracle.

ae-framework is not a certification authority.

Automated satisfaction is not human approval or publication approval.

## Producer Evidence

| Evidence ID | producer type | producer | tool | version | status |
|---|---|---|---|---|---|
| PM-EVIDENCE-0001 | ci | synthetic-ci-producer | PMAE-CI-PIPELINE-V0-1 | 1.0.0 | pass |
| PM-EVIDENCE-0002 | test-runner | synthetic-test-runner-producer | PMAE-CONFORMANCE-RUNNER-V0-1 | 1.0.0 | fail |
| PM-EVIDENCE-0003 | formal-tool | synthetic-formal-tool-producer | PMAE-FORMAL-TOOL-V0-1 | 1.0.0 | skip |
| PM-EVIDENCE-0004 | security-tool | synthetic-security-tool-producer | PMAE-SECURITY-TOOL-V0-1 | 1.0.0 | unsupported |
| PM-EVIDENCE-0005 | human-review | synthetic-human-review-producer | PMAE-HUMAN-REVIEW-V0-1 | 1.0.0 | skip |

## External tool inventory

| tool | producer type | requirement | identity | version | implementation digest |
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
| PMAE-CI-PIPELINE-V0-1 | pass | satisfied | Pass is limited to the stated synthetic check and does not prove Product correctness. |
| PMAE-CONFORMANCE-RUNNER-V0-1 | fail | blocked | Failure remains visible and blocks a required gate. |

## Optional gates

| tool | status | gate | limitation |
|---|---|---|---|
| PMAE-FORMAL-TOOL-V0-1 | skip | visible-nonblocking | Skipped work is not evidence of successful execution. |
| PMAE-SECURITY-TOOL-V0-1 | unsupported | visible-nonblocking | Unsupported capability is not converted to pass. |
| PMAE-HUMAN-REVIEW-V0-1 | skip | visible-nonblocking | Skipped work is not evidence of successful execution. |

## Judgment and human approval boundary

- automated judgment: `blocked`
- human approval: `not-applicable-test-only`
- reviewer role: `synthetic-reviewer`
- approval subject: `sha256:6c736b5fe72bd9cf2addc5941c45b847c40ec780f96c99a125eb8b9e4cfac639`

## Limitations

- ae-framework organizes supplied Evidence and is not an oracle of truth.
- This package is neither a security proof nor certification.
- Automated satisfaction is not human approval or publication approval.
- Synthetic fixtures do not establish Product or Protocol correctness.
- No live Product Evidence, private input, or public export is included.
- Native ae-framework warnings remain visible and do not rewrite producer statuses.
