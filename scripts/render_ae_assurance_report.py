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
    automated = package["automated_judgment"]
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
        f"- package digest: `{_cell(package['package_digest'])}`",
        f"- JSON report semantic digest: `{_cell(package['report_digests']['json_semantic_digest'])}`",
        f"- Markdown report semantic digest: `{_cell(package['report_digests']['markdown_semantic_digest'])}`",
        "",
        "ae-framework organizes supplied Evidence; it is not a security proof oracle.",
        "",
        "ae-framework is not a certification authority.",
        "",
        "Automated satisfaction is not human approval or publication approval.",
        "",
        "## Producer Evidence",
        "",
        *_table(
            ["Evidence ID", "producer type", "producer", "tool", "version", "status"],
            [
                [
                    item["evidence_id"],
                    item["producer_type"],
                    item["producer_id"],
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
                "tool",
                "producer type",
                "requirement",
                "identity",
                "version",
                "implementation digest",
            ],
            [
                [
                    item["tool_id"],
                    item["producer_type"],
                    item["requirement"],
                    item["identity"],
                    item["version"],
                    item["implementation_digest"],
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
        f"- human approval: `{_cell(approval['state'])}`",
        f"- reviewer role: `{_cell(approval['reviewer_role'])}`",
        f"- approval subject: `{_cell(approval['bound_assurance_content_digest'])}`",
        "",
        "## Limitations",
        "",
        *[f"- {_cell(item)}" for item in package["limitations"]],
        "",
    ]
    return "\n".join(lines)
