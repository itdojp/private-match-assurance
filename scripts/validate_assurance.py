#!/usr/bin/env python3
"""Validate Private Match public assurance records."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
from pathlib import Path
from typing import Any, Iterable

from jsonschema import Draft202012Validator, FormatChecker


@dataclasses.dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    path: str
    message: str


SCHEMA_FILES = {
    "claim": "claim.schema.json",
    "assumption": "assumption.schema.json",
    "evidence": "evidence-item.schema.json",
    "evidence-manifest": "evidence-manifest.schema.json",
    "known-limitation": "known-limitation.schema.json",
    "assurance-notice": "correction-withdrawal-notice.schema.json",
}

EXCLUDED_DIRS = {".git", ".venv", "artifacts", "__pycache__", "node_modules", "tests"}
RECORD_DIR = "assurance"


def _iter_json(root: Path) -> Iterable[Path]:
    for path in root.rglob("*.json"):
        if not path.is_file() or any(part in EXCLUDED_DIRS for part in path.parts):
            continue
        yield path


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_schemas(root: Path) -> dict[str, Draft202012Validator]:
    validators: dict[str, Draft202012Validator] = {}
    for record_type, filename in SCHEMA_FILES.items():
        schema = load_json(root / "schema" / filename)
        Draft202012Validator.check_schema(schema)
        validators[record_type] = Draft202012Validator(schema, format_checker=FormatChecker())
    return validators


def _json_path(error: Any) -> str:
    parts = [str(item) for item in error.absolute_path]
    return ".".join(parts) if parts else "$"


def _parse_datetime(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def validate_semantics(record: dict[str, Any], path: str) -> list[Finding]:
    findings: list[Finding] = []
    record_type = record.get("record_type")

    if record_type == "evidence":
        started = _parse_datetime(record.get("started_at"))
        completed = _parse_datetime(record.get("completed_at"))
        if started and completed and completed < started:
            findings.append(Finding("error", "time-order", path, "completed_at must not be before started_at"))

    elif record_type == "claim":
        valid_from = _parse_datetime(record.get("valid_from"))
        valid_until = _parse_datetime(record.get("valid_until"))
        if valid_from and valid_until and valid_until < valid_from:
            findings.append(Finding("error", "time-order", path, "valid_until must not be before valid_from"))

    elif record_type == "assumption":
        reviewed = _parse_datetime(record.get("reviewed_at"))
        next_review = _parse_datetime(record.get("next_review_at"))
        if reviewed and next_review and next_review < reviewed:
            findings.append(Finding("error", "time-order", path, "next_review_at must not be before reviewed_at"))

    elif record_type == "known-limitation":
        identified = _parse_datetime(record.get("identified_at"))
        reviewed = _parse_datetime(record.get("reviewed_at"))
        next_review = _parse_datetime(record.get("next_review_at"))
        if identified and reviewed and reviewed < identified:
            findings.append(Finding("error", "time-order", path, "reviewed_at must not be before identified_at"))
        if reviewed and next_review and next_review < reviewed:
            findings.append(Finding("error", "time-order", path, "next_review_at must not be before reviewed_at"))

    return findings


def validate_record(
    record: Any,
    path: str,
    validators: dict[str, Draft202012Validator],
) -> list[Finding]:
    if not isinstance(record, dict):
        return [Finding("error", "record-shape", path, "record must be a JSON object")]
    record_type = record.get("record_type")
    validator = validators.get(record_type)
    if validator is None:
        return [Finding("error", "unknown-record-type", path, f"unsupported record_type: {record_type!r}")]

    findings: list[Finding] = []
    for error in sorted(validator.iter_errors(record), key=lambda item: list(item.absolute_path)):
        findings.append(Finding("error", "schema", path, f"{_json_path(error)}: {error.message}"))
    findings.extend(validate_semantics(record, path))
    return findings


def _reference_sets(records: list[dict[str, Any]]) -> dict[str, set[str]]:
    result = {record_type: set() for record_type in SCHEMA_FILES}
    for record in records:
        record_type = record.get("record_type")
        record_id = record.get("id")
        if record_type in result and isinstance(record_id, str):
            result[record_type].add(record_id)
    return result


def validate_cross_references(records: list[dict[str, Any]], paths: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    refs = _reference_sets(records)
    all_ids: dict[str, str] = {}
    for record in records:
        record_id = record.get("id")
        if not isinstance(record_id, str):
            continue
        path = paths.get(record_id, record_id)
        if record_id in all_ids:
            findings.append(Finding("error", "duplicate-id", path, f"duplicate id also present in {all_ids[record_id]}"))
        else:
            all_ids[record_id] = path

    for record in records:
        path = paths.get(str(record.get("id")), "unknown")
        if record.get("record_type") == "claim":
            mappings = [
                ("assumptions", "assumption"),
                ("evidence", "evidence"),
                ("limitations", "known-limitation"),
            ]
        elif record.get("record_type") == "evidence-manifest":
            mappings = [
                ("claims", "claim"),
                ("assumptions", "assumption"),
                ("evidence", "evidence"),
                ("limitations", "known-limitation"),
            ]
        elif record.get("record_type") == "known-limitation":
            mappings = [("affected_claims", "claim")]
        elif record.get("record_type") == "assurance-notice":
            mappings = [("affected_claims", "claim")]
        else:
            mappings = []

        for field, target_type in mappings:
            for target in record.get(field, []):
                if target not in refs[target_type]:
                    findings.append(Finding("error", "missing-reference", path, f"{field} references unknown {target_type} id {target}"))
    return findings


def validate_repository(root: Path) -> tuple[list[Finding], list[dict[str, Any]]]:
    validators = load_schemas(root)
    findings: list[Finding] = []
    records: list[dict[str, Any]] = []
    paths: dict[str, str] = {}
    assurance_root = root / RECORD_DIR
    if not assurance_root.exists():
        return findings, records

    for path in _iter_json(assurance_root):
        rel = _relative(path, root)
        try:
            record = load_json(path)
        except Exception as exc:
            findings.append(Finding("error", "json-parse", rel, str(exc)))
            continue
        findings.extend(validate_record(record, rel, validators))
        if isinstance(record, dict):
            records.append(record)
            if isinstance(record.get("id"), str):
                paths[record["id"]] = rel

    findings.extend(validate_cross_references(records, paths))
    return findings, records


def render_markdown(findings: list[Finding], records_count: int) -> str:
    counts = {severity: sum(1 for item in findings if item.severity == severity) for severity in ("error", "warning", "info")}
    lines = [
        "# Assurance Schema Validation Report",
        "",
        f"- generated_at: {dt.datetime.now(dt.timezone.utc).isoformat()}",
        f"- records: {records_count}",
        f"- errors: {counts['error']}",
        f"- warnings: {counts['warning']}",
        f"- info: {counts['info']}",
        "",
    ]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"
    lines.extend(["| Severity | Code | Path | Message |", "|---|---|---|---|"])
    for item in sorted(findings, key=lambda value: (value.severity != "error", value.path, value.code, value.message)):
        escaped_path = item.path.replace("|", "\\|")
        escaped_message = item.message.replace("|", "\\|")
        lines.append(f"| {item.severity} | `{item.code}` | `{escaped_path}` | {escaped_message} |")
    return "\n".join(lines) + "\n"


def write_reports(report_dir: Path, findings: list[Finding], records_count: int) -> None:
    report_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "records": records_count,
        "summary": {
            "errors": sum(1 for item in findings if item.severity == "error"),
            "warnings": sum(1 for item in findings if item.severity == "warning"),
            "info": sum(1 for item in findings if item.severity == "info"),
        },
        "findings": [dataclasses.asdict(item) for item in findings],
    }
    (report_dir / "assurance-schema-report.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (report_dir / "assurance-schema-report.md").write_text(render_markdown(findings, records_count), encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--report-dir", type=Path, default=Path("artifacts"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    report_dir = args.report_dir if args.report_dir.is_absolute() else root / args.report_dir
    findings, records = validate_repository(root)
    write_reports(report_dir, findings, len(records))
    errors = sum(1 for item in findings if item.severity == "error")
    warnings = sum(1 for item in findings if item.severity == "warning")
    print(f"assurance-schema: records={len(records)} errors={errors} warnings={warnings} report={report_dir}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
