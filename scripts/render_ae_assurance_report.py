#!/usr/bin/env python3
"""Render deterministic Markdown exclusively from a validated JSON package."""

from __future__ import annotations

import html
from typing import Any


def _cell(value: Any) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    return html.escape(text, quote=True).replace("|", "\\|")


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    return [
        "| " + " | ".join(_cell(value) for value in headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
        *["| " + " | ".join(_cell(value) for value in row) + " |" for row in rows],
    ]


def render_markdown(package: dict[str, Any]) -> str:
    """Render the closed report surface; JSON remains the authority."""

    profile = package["integration_profile"]
    framework = package["ae_framework"]
    protocol_authority = package["protocol_conformance_authority"]
    producer_package = package["input_producer_package"]
    producer_subject = producer_package["subject"]
    validation = package["validation_provenance"]
    automated = package["automated_judgment"]
    producer_gate = package["producer_gate_judgment"]
    native_judgment = package["native_ae_judgment"]
    approval = package["human_approval"]
    lines = [
        "# Private Match ae-framework Assurance report",
        "",
        "## Authority and boundary",
        "",
        f"- artifact status: `{_cell(package['artifact_status'])}`",
        f"- integration profile: `{_cell(profile['id'])}/{_cell(profile['version'])}`",
        f"- integration profile digest: `{_cell(profile['digest'])}`",
        f"- ae-framework repository: `{_cell(framework['repository'])}`",
        f"- ae-framework commit: `{_cell(framework['commit'])}`",
        f"- ae-framework package: `{_cell(framework['package_name'])}@{_cell(framework['package_version'])}`",
        f"- ae-framework source tree: `{_cell(framework['source_tree_digest'])}`",
        f"- native input manifest digest: `{_cell(framework['native_input_manifest_digest'])}`",
        f"- Protocol authority: `{_cell(protocol_authority['authority_id'])}/{_cell(protocol_authority['authority_version'])}`",
        f"- Protocol: `{_cell(protocol_authority['protocol']['identifier'])}/{_cell(protocol_authority['protocol']['version'])}`",
        f"- conformance suite: `{_cell(protocol_authority['conformance_suite']['identifier'])}/{_cell(protocol_authority['conformance_suite']['version'])}`",
        f"- conformance suite digest: `{_cell(protocol_authority['conformance_suite']['digest'])}`",
        f"- producer package created at: `{_cell(validation['producer_package_created_at'])}`",
        f"- validation recorded at: `{_cell(validation['validated_at'])}`",
        f"- validation producer package digest: `{_cell(validation['producer_package_digest'])}`",
        f"- package digest: `{_cell(package['package_digest'])}`",
        f"- JSON report model digest: `{_cell(package['report_digests']['json_model_digest'])}`",
        f"- Markdown report model digest: `{_cell(package['report_digests']['markdown_model_digest'])}`",
        "",
        "ae-framework organizes supplied Evidence; it is not a security proof oracle.",
        "",
        "ae-framework is not a certification authority.",
        "",
        "Automated satisfaction is not human approval or publication approval.",
        "",
        "## Embedded producer package",
        "",
        f"- package ID: `{_cell(producer_package['package_id'])}`",
        f"- mode: `{_cell(producer_package['mode'])}`",
        f"- artifact status: `{_cell(producer_package['artifact_status'])}`",
        f"- subject: `{_cell(producer_subject['identifier'])}/{_cell(producer_subject['version'])}`",
        f"- subject digest: `{_cell(producer_subject['digest'])}`",
        f"- producer package digest: `{_cell(producer_package['package_digest'])}`",
        f"- created at: `{_cell(producer_package['created_at'])}`",
        f"- validated at: `{_cell(producer_package['validation_event']['validated_at'])}`",
        f"- Protocol authority: `{_cell(producer_package['protocol_conformance_authority']['authority_id'])}/{_cell(producer_package['protocol_conformance_authority']['authority_version'])}`",
        "",
        "## Producer Evidence",
        "",
        *_table(
            [
                "Evidence ID",
                "producer type",
                "producer",
                "tool role",
                "execution tool",
                "version",
                "status",
            ],
            [
                [
                    item["evidence_id"],
                    item["producer_type"],
                    item["producer_id"],
                    item["tool_role_id"],
                    item["tool_id"],
                    item["tool_version"],
                    item["status"],
                ]
                for item in package["producer_inventory"]
            ],
        ),
        "",
        "## External tool inventory",
        "",
        *_table(
            [
                "tool role",
                "producer type",
                "requirement",
                "identity",
                "version",
                "implementation digest",
            ],
            [
                [
                    item["tool_role_id"],
                    item["producer_type"],
                    item["requirement"],
                    item["tool_id"],
                    item["tool_version"],
                    item["tool_implementation_digest"],
                ]
                for item in package["external_tool_inventory"]
            ],
        ),
        "",
        "## Status counts",
        "",
        *_table(
            ["status", "count"],
            [
                [status, package["status_counts"][status]]
                for status in (
                    "pass",
                    "fail",
                    "skip",
                    "unsupported",
                    "timeout",
                    "tool-error",
                )
            ],
        ),
        "",
        "## Required gates",
        "",
        *_table(
            ["tool", "status", "gate", "limitation"],
            [
                [
                    item["tool_id"],
                    item["status"],
                    item["gate_state"],
                    item["limitation"],
                ]
                for item in package["required_gate_results"]
            ],
        ),
        "",
        "## Optional gates",
        "",
        *_table(
            ["tool", "status", "gate", "limitation"],
            [
                [
                    item["tool_id"],
                    item["status"],
                    item["gate_state"],
                    item["limitation"],
                ]
                for item in package["optional_gate_results"]
            ],
        ),
        "",
        "## Judgment and human approval boundary",
        "",
        f"- automated judgment: `{_cell(automated['state'])}`",
        f"- producer gate judgment: `{_cell(producer_gate['state'])}`",
        f"- native ae judgment: `{_cell(native_judgment['state'])}`",
        f"- native warning treatment: `{_cell(native_judgment['policy_treatment'])}`",
        f"- human approval: `{_cell(approval['state'])}`",
        f"- reviewer role: `{_cell(approval['reviewer_role'])}`",
        f"- approval subject: `{_cell(approval['bound_assurance_content_digest'])}`",
        f"- boundary generated by automation: `{_cell(approval['boundary_artifact_generated_by_automation'])}`",
        f"- approval decision present: `{_cell(approval['approval_decision_present'])}`",
        "",
        "## Native ae-framework judgment",
        "",
        *_table(
            [
                "claim",
                "native status",
                "required lanes",
                "observed lanes",
                "missing lanes",
                "required Evidence kinds",
                "observed Evidence kinds",
                "missing Evidence kinds",
                "warning codes",
                "policy treatment",
            ],
            [
                [
                    claim["claim_id"],
                    claim["status"],
                    ", ".join(claim["required_lanes"]),
                    ", ".join(claim["observed_lanes"]),
                    ", ".join(claim["missing_lanes"]),
                    ", ".join(claim["required_evidence_kinds"]),
                    ", ".join(claim["observed_evidence_kinds"]),
                    ", ".join(claim["missing_evidence_kinds"]),
                    ", ".join(claim["warning_codes"]),
                    native_judgment["policy_treatment"],
                ]
                for claim in native_judgment["claim_results"]
            ],
        ),
        "",
        "## Limitations",
        "",
        *[f"- {_cell(item)}" for item in package["limitations"]],
        "",
    ]
    return "\n".join(lines)
