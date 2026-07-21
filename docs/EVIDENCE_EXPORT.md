# Public Evidence Export Contract

## Status and scope

`private-match-public-evidence-export/0.1` is a draft contract for moving a
closed, metadata-only Evidence candidate into a public review bundle. It does
not read raw logs or private source repositories, publish anything, sign a
release, or create a human approval.

The contract consists of three independently validated artifacts:

- [`evidence-export-candidate.v0.1.schema.json`](../schema/evidence-export-candidate.v0.1.schema.json)
  defines the private-side metadata envelope.
- [`public-evidence-export.v0.1.schema.json`](../schema/public-evidence-export.v0.1.schema.json)
  defines the generated public candidate bundle.
- [`public-evidence-export.v0.1.json`](../profiles/public-evidence-export.v0.1.json)
  is the reviewed allowlist, omission, lifecycle, digest, path, and
  serialization policy.

The existing Evidence Schema 0.1 remains unchanged and authoritative for the
embedded `evidence_record` in both contracts.

## Trust and publication boundary

The exporter requires separate privacy, security-boundary, IP, and
vulnerability review markers. It checks their structure and approved or
not-applicable state. It cannot establish that the recorded reviewer had the
claimed authority. That is a human review responsibility.

The exporter always emits:

```json
{"automation_permitted":false,"status":"candidate"}
```

It also records `final_publication_approval: required-not-provided`. CI, an
Agent, and the exporter cannot change the lifecycle beyond `sanitized` or set a
publication approval. A separate human-only publication process is required.

Synthetic fixtures use `artifact_status: test-only`, the
`synthetic-reviewer` role, and synthetic digests. They are not evidence of an
actual review.

## Private-side candidate

The input is one explicit UTF-8 JSON file under the configured repository-local
staging root. It contains only a closed metadata envelope:

- the complete Evidence record;
- source, evidence-set, subject-artifact, and output digests;
- Protocol profile, source revision, State Machine, message-registry, and
  conformance-suite digests;
- the export profile and its digest;
- typed review and sensitivity markers;
- an input-supplied sanitization event; and
- zero or more profile-authorized optional omissions.

Raw evidence, logs, customer identifiers, private repository locators,
credentials, and actual publication approvals are not candidate fields.

## Public bundle

The output binds the input candidate, exporter source file, export profile,
sanitized Evidence record, Protocol artifacts, conformance suite, private
source revision, source evidence set, subject artifact, and Evidence output.
These digests establish identity and origin bindings only. They do not prove
security, correctness, privacy, completeness, or publication suitability.

The bundle digest is detached: it is computed over the complete RFC 8785
bundle with the `bundle_digest` member omitted. This avoids a self-reference.

## Status and lifecycle

All six Evidence result values are preserved exactly:

- `pass`
- `fail`
- `skip`
- `unsupported`
- `timeout`
- `tool-error`

The exporter does not convert among them. It also preserves the existing
Evidence status/execution/output-digest conditions.

Input lifecycle may be `collected`, `validated`, or `sanitized`. For the first
two values, the exporter appends the candidate-supplied sanitization event
without modifying earlier history. Already sanitized input must contain an
identical final sanitization entry. Output lifecycle is exactly `sanitized`.
`published`, `superseded`, and `withdrawn` input is rejected.

## Omission policy

The default profile permits one omission:

- clear the optional `evidence_record.public_artifacts` list under rule
  `OMIT-PUBLIC-ARTIFACTS`.

The omission log records only the JSON path, reviewed rule, category, action,
and human review digest. It does not record an original value, excerpt, length,
reversible encoding, or digest derived from that value. Unknown fields and
ambiguous free-form redaction requests are errors rather than redactions.

## Deterministic serialization

Input and output use strict UTF-8 JSON. Parsing rejects duplicate member names,
NaN, Infinity, negative zero, and integers outside the I-JSON interoperable
range. Output uses RFC 8785 through the Apache-2.0-licensed
`rfc8785==0.1.4` package. Map order is canonical; schema-declared set-like
digest, artifact, and model-property arrays are sorted. Lifecycle history and
other ordered narrative lists retain their input order.

The exporter does not introduce wall-clock time, randomness, environment
values, filesystem paths, or host data. The sanitization timestamp is an
explicit reviewed candidate field. Equal approved semantic input and profile
therefore produce byte-identical output.

The dependency review on 2026-07-21 used
[`rfc8785` 0.1.4](https://pypi.org/project/rfc8785/), which declares Python
3.8 or newer and the Apache Software License. The lock contains both published
artifact hashes. Tests cover the canonical sample and Appendix B number vectors
from [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785), plus unsafe integers,
negative zero, duplicate keys, non-finite values, and Unicode edge cases. No
third-party implementation source was copied into this repository.

## File-system boundary

The CLI accepts repository-relative paths only. The staging root, profile, and
output root must remain inside the checked-out repository. Input is one named,
regular, non-symlink file under the staging root. Absolute paths, `..`, missing
files, directories, symlinks, root escapes, and inputs over 256 KiB are
rejected. The exporter performs no recursive scan, path expansion, network
request, subprocess invocation, repository clone, or GitHub API call.

Successful writes use a restrictive temporary file in the output directory and
an atomic rename. Validation completes before the write; a rejected export does
not leave an output bundle.

Example using only the committed synthetic fixture:

```console
python scripts/export_public_evidence.py \
  --staging-root tests/fixtures/export/input \
  --input protocol-conformance.json \
  --profile profiles/public-evidence-export.v0.1.json \
  --output-dir .codex-local/tmp/export
```

## Allowlist and scanner

Closed JSON Schemas and type-specific Evidence `configuration` allowlists are
the primary controls. The profile currently permits `conformance`, `test`,
`model-check`, `provenance`, and `review` configurations only. An unreviewed
Evidence type or configuration member fails closed.

Every public string leaf is also checked as defense in depth. The scanner uses
Unicode NFKC and constrained URL/base64 decoding for detection only; it never
silently normalizes output. It checks common credential and private-key forms,
internal or non-public destinations, metadata endpoints, private repository and
absolute path forms, account/customer/personal identifiers, control/bidi/zero
width characters, and high-risk vulnerability-detail phrases.

The scanner is not a proof that every secret or identifier has been found. A
passing scan cannot replace the closed schema, source-side staging controls, or
human privacy, security, IP, vulnerability, and publication review.

## Vulnerability and IP gates

Unpublished inventions, patent candidates, embargoed details, unapproved
vulnerability material, and missing review markers are rejected. The exporter
does not make legal, patentability, remediation, or disclosure decisions. It
only enforces the reviewed marker structure and state.

## Protocol fixture pin

The synthetic conformance fixture binds the regular-merge result of Protocol PR
9 without accessing the Protocol repository at runtime:

- merge commit: `2c314027f61ca0f0edbe2dcc55a8305710efd91d`
- Protocol source revision digest:
  `sha256:dba1e8d6efc6083c62c2e4b44f6e12eaa4f5c6cb5ff0cd047a9ad3df0306a208`
- State Machine digest:
  `sha256:42e63b8a1f413e932e46370aae5fa0d972f3ab71d93efe08557472b4c7066fe8`
- message registry digest:
  `sha256:2ff1685ca4325a0ff3bd49c7a411cd7f0857add6215c2f285097bdf40dcbc2b6`
- conformance tree digest:
  `sha256:19d2218c11c6ac7ba1d2f0884ba9e3c79cbd1264bd3ef682e543bcb9a63ccf0f`

These are reviewed synthetic bindings, not a runtime dependency or a claim of
Protocol conformance by a product.

## Validation

The exporter fixtures are checked with:

```console
python -m unittest discover -s tests -p 'test_*.py'
python scripts/export_public_evidence.py \
  --input protocol-conformance.json \
  --output-dir .codex-local/tmp/export
python scripts/validate_assurance.py \
  --root . \
  --report-dir .codex-local/tmp/report \
  --export-bundle .codex-local/tmp/export/public-evidence-export.v0.1.json
```

Public CI uses only committed synthetic candidates and compares the generated
bytes with committed expected output. It does not upload generated evidence
bundles.
