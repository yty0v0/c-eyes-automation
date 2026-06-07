#!/usr/bin/env python3
"""
Shared final-report helpers for C-Eyes runs.
"""

from __future__ import annotations

import json
import zipfile
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape


SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
    "unknown": "未知",
}

SEVERITY_COLORS = {
    "critical": "#b42318",
    "high": "#dc6803",
    "medium": "#b54708",
    "low": "#027a48",
    "info": "#155eef",
    "unknown": "#667085",
}

COLLECTION_KEYS = (
    "findings",
    "items",
    "results",
    "rows",
    "entries",
    "alerts",
    "risks",
    "records",
    "data",
    "matches",
    "detections",
)

TITLE_KEYS = (
    "title",
    "name",
    "rule_name",
    "ruleName",
    "message",
    "description",
    "event",
    "target_path",
    "targetPath",
    "path",
    "processName",
    "ipAddress",
    "ip",
)

EVIDENCE_KEYS = (
    "target_path",
    "targetPath",
    "path",
    "file",
    "processName",
    "processId",
    "pid",
    "ipAddress",
    "ip",
    "remoteIp",
    "localIp",
    "port",
    "remotePort",
    "localPort",
    "protocol",
    "status",
    "rule_name",
    "ruleName",
)

STATUS_SEVERITY = {
    "failed": "high",
    "blocked": "medium",
    "warning": "medium",
    "warn": "medium",
    "suspicious": "high",
    "malicious": "critical",
    "infected": "critical",
    "error": "high",
    "ok": "info",
    "success": "info",
    "completed": "info",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def report_result_dir(workspace: Path) -> Path:
    report_dir = workspace / "report_result"
    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir


def relative_path(path_str: str | None, workspace: Path) -> str | None:
    if not path_str:
        return None
    try:
        path = Path(path_str).resolve()
        return path.relative_to(workspace.resolve()).as_posix()
    except Exception:
        return path_str.replace("\\", "/")


def workspace_href(path_str: str | None) -> str | None:
    if not path_str:
        return None
    normalized = path_str.replace("\\", "/")
    if normalized.startswith("report_result/"):
        return normalized[len("report_result/") :]
    return f"../{normalized}"


def status_label(status: str) -> str:
    mapping = {
        "ok": "成功",
        "completed": "成功",
        "dry-run": "仅预演",
        "blocked": "阻塞",
        "failed": "失败",
        "planned": "已计划",
        "review-results": "待复核",
        "manual-follow-up": "需人工跟进",
        "ready-for-live-run": "可执行正式扫描",
        "no-material-findings": "未发现实质异常",
        "findings-present": "存在发现",
    }
    return mapping.get(status, status)


def safe_read_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            return json.load(handle), None
    except Exception as exc:
        return None, str(exc)


def ensure_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def compact_json(value: Any, limit: int = 220) -> str:
    try:
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        text = str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def stringify_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    if isinstance(value, (list, dict)):
        return compact_json(value, 160)
    return str(value)


def normalize_severity(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, (int, float)):
        score = float(value)
        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        if score > 0:
            return "low"
        return "info"

    text = str(value).strip().lower()
    if not text:
        return "unknown"

    mapping = {
        "critical": "critical",
        "severe": "critical",
        "fatal": "critical",
        "malicious": "critical",
        "high": "high",
        "danger": "high",
        "medium": "medium",
        "moderate": "medium",
        "warning": "medium",
        "warn": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "ok": "info",
        "success": "info",
        "passed": "info",
        "unknown": "unknown",
        "严重": "critical",
        "高危": "high",
        "中危": "medium",
        "低危": "low",
        "信息": "info",
        "异常": "medium",
        "可疑": "high",
        "正常": "info",
    }
    if text in mapping:
        return mapping[text]

    for key, normalized in mapping.items():
        if key in text:
            return normalized
    return "unknown"


def infer_record_severity(record: dict[str, Any]) -> str:
    for key in (
        "severity",
        "risk_level",
        "riskLevel",
        "level",
        "alert_level",
        "alertLevel",
        "priority",
        "threat_level",
        "threatLevel",
        "risk_score",
        "riskScore",
        "score",
    ):
        if key in record:
            severity = normalize_severity(record.get(key))
            if severity != "unknown":
                return severity

    status = str(record.get("status") or record.get("result") or "").strip().lower()
    if status in STATUS_SEVERITY:
        return STATUS_SEVERITY[status]
    for key, severity in STATUS_SEVERITY.items():
        if key and key in status:
            return severity
    return "unknown"


def infer_record_title(record: dict[str, Any]) -> str:
    for key in TITLE_KEYS:
        value = stringify_value(record.get(key))
        if value:
            return value
    interesting = summarize_record(record, max_fields=4)
    return interesting or "未命名记录"


def normalize_list_strings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [stringify_value(item) for item in value if stringify_value(item)]
    if isinstance(value, str):
        return [value] if value else []
    return []


def compact_join(parts: list[str], limit: int = 3) -> str:
    cleaned = [item for item in parts if item]
    return " | ".join(cleaned[:limit])


def infer_yara_evidence(record: dict[str, Any]) -> tuple[str | None, str | None]:
    details: list[str] = []

    for key in ("yara_results", "matched_rules", "matchedRules", "rule_matches", "ruleMatches"):
        value = record.get(key)
        if not isinstance(value, list):
            continue
        for item in value[:3]:
            if not isinstance(item, dict):
                continue
            rule_name = stringify_value(item.get("rule_name") or item.get("ruleName") or item.get("name"))
            tags = normalize_list_strings(item.get("tags"))
            severity = stringify_value(item.get("severity"))
            matched_strings = item.get("matched_strings") or item.get("matchedStrings")
            fragments = []
            if rule_name:
                fragments.append(f"rule={rule_name}")
            if tags:
                fragments.append(f"tags={','.join(tags[:3])}")
            if severity:
                fragments.append(f"severity={severity}")
            if isinstance(matched_strings, list) and matched_strings:
                fragments.append(f"matched_strings={len(matched_strings)}")
            if fragments:
                details.append("YARA: " + compact_join(fragments, limit=4))

    single_rule = stringify_value(
        record.get("rule_name")
        or record.get("ruleName")
        or record.get("yara_rule")
        or record.get("yaraRule")
    )
    if single_rule:
        rule_details = [f"rule={single_rule}"]
        tags = normalize_list_strings(record.get("tags"))
        if tags:
            rule_details.append(f"tags={','.join(tags[:3])}")
        details.insert(0, "YARA: " + compact_join(rule_details, limit=3))

    if details:
        return "yara", " ; ".join(details[:2])
    return None, None


def infer_cloud_evidence(record: dict[str, Any]) -> tuple[str | None, str | None]:
    labels = normalize_list_strings(
        record.get("threat_labels")
        or record.get("threatLabels")
        or record.get("cloud_labels")
        or record.get("cloudLabels")
    )
    malicious_votes = stringify_value(record.get("malicious_votes") or record.get("maliciousVotes"))
    total_engines = stringify_value(record.get("total_engines") or record.get("totalEngines"))
    detection_ratio = stringify_value(record.get("detection_ratio") or record.get("detectionRatio"))
    vendor = stringify_value(record.get("cloud_vendor") or record.get("cloudVendor") or record.get("vendor"))

    fragments: list[str] = []
    if vendor:
        fragments.append(f"vendor={vendor}")
    if labels:
        fragments.append(f"labels={','.join(labels[:3])}")
    if detection_ratio:
        fragments.append(f"ratio={detection_ratio}")
    elif malicious_votes and total_engines:
        fragments.append(f"ratio={malicious_votes}/{total_engines}")
    elif malicious_votes:
        fragments.append(f"malicious_votes={malicious_votes}")
    if fragments:
        return "cloud", "Cloud: " + compact_join(fragments, limit=4)
    return None, None


def infer_record_evidence_source(record: dict[str, Any]) -> tuple[str, str, str]:
    yara_source, yara_detail = infer_yara_evidence(record)
    if yara_source and yara_detail:
        return yara_source, "YARA 规则", yara_detail

    cloud_source, cloud_detail = infer_cloud_evidence(record)
    if cloud_source and cloud_detail:
        return cloud_source, "云平台分析", cloud_detail

    status = stringify_value(record.get("status") or record.get("result"))
    if status:
        return "behavior", "行为结果", f"Behavior: status={status}"
    return "other", "通用字段", "General fields"


def infer_record_evidence(record: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in EVIDENCE_KEYS:
        value = stringify_value(record.get(key))
        if value:
            parts.append(f"{key}={value}")
        if len(parts) >= 4:
            break
    if parts:
        return " | ".join(parts)
    return summarize_record(record, max_fields=5)


def infer_record_category(record: dict[str, Any], evidence_label: str) -> str:
    for key in ("category", "type", "family", "threat_type", "threatType", "alert_type", "alertType"):
        value = stringify_value(record.get(key))
        if value:
            return value

    tags = normalize_list_strings(record.get("tags"))
    if tags:
        return tags[0]

    threat_labels = normalize_list_strings(record.get("threat_labels") or record.get("threatLabels"))
    if threat_labels:
        return threat_labels[0]

    return evidence_label


def summarize_record(record: dict[str, Any], max_fields: int = 6) -> str:
    parts: list[str] = []
    for key, value in record.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (dict, list)):
            continue
        parts.append(f"{key}={stringify_value(value)}")
        if len(parts) >= max_fields:
            break
    return " | ".join(parts)


def severity_counts_template() -> dict[str, int]:
    return {key: 0 for key in ("critical", "high", "medium", "low", "info", "unknown")}


def add_severity_count(target: dict[str, int], severity: str) -> None:
    normalized = severity if severity in target else "unknown"
    target[normalized] += 1


def merge_severity_counts(target: dict[str, int], source: dict[str, int]) -> None:
    for key, value in source.items():
        target[key] = target.get(key, 0) + int(value)


def increment_named_count(target: dict[str, int], name: str | None) -> None:
    key = (name or "Unknown").strip() or "Unknown"
    target[key] = target.get(key, 0) + 1


def sorted_named_counts(target: dict[str, int], limit: int = 6) -> list[dict[str, Any]]:
    items = sorted(target.items(), key=lambda item: (-item[1], item[0]))
    return [{"name": name, "count": count} for name, count in items[:limit] if count > 0]


def choose_overall_severity(severity_counts: dict[str, int], fallback_status: str) -> str:
    for severity in ("critical", "high", "medium", "low", "info"):
        if severity_counts.get(severity):
            return severity
    if fallback_status == "failed":
        return "high"
    if fallback_status == "blocked":
        return "medium"
    return "info"


def collect_nested_collections(node: Any, prefix: str = "root", depth: int = 0) -> list[tuple[str, list[Any]]]:
    collections: list[tuple[str, list[Any]]] = []
    if depth > 2:
        return collections

    if isinstance(node, list):
        if node:
            collections.append((prefix, node))
        return collections

    if isinstance(node, dict):
        for key in COLLECTION_KEYS:
            value = node.get(key)
            if isinstance(value, list) and value:
                collections.append((f"{prefix}.{key}", value))
        for key, value in node.items():
            if isinstance(value, dict):
                collections.extend(collect_nested_collections(value, f"{prefix}.{key}", depth + 1))
            elif isinstance(value, list) and key not in COLLECTION_KEYS and value and depth < 2:
                if any(isinstance(item, (dict, list)) for item in value):
                    collections.append((f"{prefix}.{key}", value))
    return collections


def coerce_records(items: list[Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            records.append(item)
        elif isinstance(item, list):
            records.append({"value": compact_json(item, 180)})
        else:
            records.append({"value": item})
    return records


def build_finding_row(
    record: dict[str, Any],
    source_path: str,
    collection_name: str,
) -> dict[str, Any]:
    severity = infer_record_severity(record)
    status = stringify_value(record.get("status") or record.get("result"))
    evidence_source, evidence_source_label, evidence_source_detail = infer_record_evidence_source(record)
    category = infer_record_category(record, evidence_source_label)
    return {
        "severity": severity,
        "severity_label": SEVERITY_LABELS[severity],
        "source_path": source_path,
        "collection": collection_name,
        "title": infer_record_title(record),
        "category": category,
        "status": status,
        "evidence_source": evidence_source,
        "evidence_source_label": evidence_source_label,
        "evidence_source_detail": evidence_source_detail,
        "evidence": infer_record_evidence(record),
        "summary": summarize_record(record, max_fields=7),
        "raw": compact_json(record, 300),
    }


def select_sample_rows(rows: list[dict[str, Any]], limit: int = 8) -> list[dict[str, Any]]:
    ordered = sorted(
        rows,
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 0),
            1 if item.get("status") else 0,
            item.get("title") or "",
        ),
        reverse=True,
    )
    return ordered[:limit]


def build_output_digest(output_path: str, workspace: Path) -> dict[str, Any]:
    source_path = Path(output_path).expanduser().resolve()
    rel_path = relative_path(str(source_path), workspace) or source_path.name
    digest: dict[str, Any] = {
        "path": rel_path,
        "href": workspace_href(rel_path),
        "file_name": source_path.name,
        "format": source_path.suffix.lower().lstrip(".") or "unknown",
        "exists": source_path.exists(),
        "load_error": None,
        "record_count": 0,
        "flagged_count": 0,
        "severity_counts": severity_counts_template(),
        "evidence_source_counts": {},
        "category_counts": {},
        "collections": [],
        "sample_rows": [],
        "top_level_summary": "",
    }

    if not source_path.exists():
        digest["load_error"] = "output file not found"
        return digest

    if source_path.suffix.lower() != ".json":
        digest["top_level_summary"] = "非 JSON 输出，报告层仅保留文件引用。"
        return digest

    payload, error = safe_read_json(source_path)
    if error:
        digest["load_error"] = error
        return digest

    if isinstance(payload, dict):
        top_keys = [key for key in payload.keys()][:8]
        if top_keys:
            digest["top_level_summary"] = "顶层字段: " + ", ".join(top_keys)
    elif isinstance(payload, list):
        digest["top_level_summary"] = f"顶层数组，元素数: {len(payload)}"

    collections = collect_nested_collections(payload)
    if not collections:
        if isinstance(payload, list):
            collections = [("root", payload)]
        elif isinstance(payload, dict):
            collections = [("root", [payload])]

    all_rows: list[dict[str, Any]] = []
    for collection_name, raw_items in collections:
        records = coerce_records(raw_items)
        collection_rows = [build_finding_row(item, rel_path, collection_name) for item in records]
        counts = severity_counts_template()
        evidence_source_counts: dict[str, int] = {}
        category_counts: dict[str, int] = {}
        for row in collection_rows:
            add_severity_count(counts, row["severity"])
            increment_named_count(evidence_source_counts, row.get("evidence_source_label"))
            increment_named_count(category_counts, row.get("category"))
        flagged_count = sum(
            1
            for row in collection_rows
            if row["severity"] in {"critical", "high", "medium"} or row.get("status")
        )
        digest["collections"].append(
            {
                "name": collection_name,
                "record_count": len(collection_rows),
                "flagged_count": flagged_count,
                "severity_counts": counts,
                "evidence_source_counts": evidence_source_counts,
                "category_counts": category_counts,
                "sample_rows": select_sample_rows(collection_rows),
            }
        )
        digest["record_count"] += len(collection_rows)
        digest["flagged_count"] += flagged_count
        merge_severity_counts(digest["severity_counts"], counts)
        for key, value in evidence_source_counts.items():
            digest["evidence_source_counts"][key] = digest["evidence_source_counts"].get(key, 0) + value
        for key, value in category_counts.items():
            digest["category_counts"][key] = digest["category_counts"].get(key, 0) + value
        all_rows.extend(collection_rows)

    digest["sample_rows"] = select_sample_rows(all_rows, limit=10)
    return digest


def collect_output_digests(workspace: Path, output_paths: list[str]) -> list[dict[str, Any]]:
    digests: list[dict[str, Any]] = []
    for item in output_paths:
        if not item:
            continue
        digests.append(build_output_digest(item, workspace))
    return digests


def flatten_output_findings(output_digests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for digest in output_digests:
        for row in digest.get("sample_rows", []):
            rows.append(row)
    return select_sample_rows(rows, limit=20)


def build_chart_summary_from_output_digests(output_digests: list[dict[str, Any]]) -> dict[str, Any]:
    severity_counts = severity_counts_template()
    evidence_source_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for digest in output_digests:
        merge_severity_counts(severity_counts, digest.get("severity_counts", {}))
        for key, value in ensure_dict(digest.get("evidence_source_counts")).items():
            evidence_source_counts[key] = evidence_source_counts.get(key, 0) + int(value)
        for key, value in ensure_dict(digest.get("category_counts")).items():
            category_counts[key] = category_counts.get(key, 0) + int(value)

    secondary_counts = sorted_named_counts(evidence_source_counts)
    secondary_title = "结论来源占比"
    if len(secondary_counts) < 2:
        secondary_counts = []
        secondary_title = ""

    return {
        "severity_counts": severity_counts,
        "evidence_source_counts": sorted_named_counts(evidence_source_counts),
        "category_counts": sorted_named_counts(category_counts),
        "secondary_title": secondary_title,
        "secondary_counts": secondary_counts,
    }


def build_chart_summary_from_findings(findings_items: list[dict[str, Any]], fallback_title: str = "风险类型占比") -> dict[str, Any]:
    severity_counts = severity_counts_template()
    evidence_source_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for item in findings_items:
        add_severity_count(severity_counts, normalize_severity(item.get("severity")))
        increment_named_count(evidence_source_counts, stringify_value(item.get("evidence_source_label")) or "人工聚合")
        increment_named_count(category_counts, stringify_value(item.get("category")) or stringify_value(item.get("type")) or "调查发现")
    secondary_counts = sorted_named_counts(evidence_source_counts)
    fallback_title = "结论来源占比"
    if len(secondary_counts) < 2:
        secondary_counts = []
        fallback_title = ""
    return {
        "severity_counts": severity_counts,
        "evidence_source_counts": sorted_named_counts(evidence_source_counts),
        "category_counts": sorted_named_counts(category_counts),
        "secondary_title": fallback_title,
        "secondary_counts": secondary_counts,
    }


def build_metric(label: str, value: Any, tone: str = "info") -> dict[str, Any]:
    return {"label": label, "value": value, "tone": tone}


def build_workflow_metrics(
    manifest: dict[str, Any],
    summary: dict[str, Any],
    output_digests: list[dict[str, Any]],
    finding_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    chart_summary = build_chart_summary_from_output_digests(output_digests)
    severity_counts = chart_summary["severity_counts"]
    evidence_sources = chart_summary.get("evidence_source_counts", [])
    top_source = evidence_sources[0]["name"] if evidence_sources else "无"

    return [
        build_metric("整体状态", status_label(str(summary.get("status") or "unknown")), tone="info"),
        build_metric("严重/高危", severity_counts.get("critical", 0) + severity_counts.get("high", 0), tone="high"),
        build_metric("中危", severity_counts.get("medium", 0), tone="medium"),
        build_metric("低危/信息", severity_counts.get("low", 0) + severity_counts.get("info", 0), tone="info"),
        build_metric(
            "关键风险项",
            len([row for row in finding_rows if row["severity"] in {"critical", "high", "medium"}]),
            tone="high",
        ),
        build_metric("结论主要来源", top_source, tone="info"),
        build_metric("输出文件", len(output_digests), tone="info"),
    ]


def build_investigation_metrics(
    decision: dict[str, Any],
    findings_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    chart_summary = build_chart_summary_from_findings(findings_items)
    severity_counts = chart_summary["severity_counts"]
    steps = decision.get("executed_steps", [])
    blocked_steps = len([step for step in steps if step.get("status") == "blocked"])
    failed_steps = len([step for step in steps if step.get("status") == "failed"])
    return [
        build_metric("调查状态", status_label(str(decision.get("status") or "unknown")), tone="info"),
        build_metric("关键发现", len(findings_items), tone="high"),
        build_metric("严重/高危", severity_counts.get("critical", 0) + severity_counts.get("high", 0), tone="high"),
        build_metric("中危", severity_counts.get("medium", 0), tone="medium"),
        build_metric("阻塞步骤", blocked_steps, tone="medium"),
        build_metric("失败步骤", failed_steps, tone="high"),
        build_metric("调查目标", decision.get("goal") or "unknown", tone="info"),
    ]


def build_artifact_index(
    summary_json: str | None,
    manifest_json: str | None,
    output_paths: list[str],
    extra_paths: list[str] | None = None,
) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    if summary_json:
        items.append({"label": "summary.json", "path": summary_json, "href": workspace_href(summary_json) or ""})
    if manifest_json:
        items.append({"label": "manifest.json", "path": manifest_json, "href": workspace_href(manifest_json) or ""})
    for path in output_paths:
        items.append({"label": "output", "path": path, "href": workspace_href(path) or ""})
    for path in extra_paths or []:
        items.append({"label": "evidence", "path": path, "href": workspace_href(path) or ""})
    return items


def build_workflow_report(
    workspace: Path,
    manifest: dict[str, Any],
    summary: dict[str, Any],
) -> dict[str, Any]:
    status = str(summary.get("status") or manifest.get("status") or "unknown")
    workflow = str(summary.get("workflow") or manifest.get("workflow") or "unknown")
    outputs = [relative_path(item, workspace) for item in summary.get("outputs", []) if item]
    output_digests = collect_output_digests(workspace, [item for item in summary.get("outputs", []) if item])
    finding_rows = flatten_output_findings(output_digests)
    chart_summary = build_chart_summary_from_output_digests(output_digests)
    severity_counts = chart_summary["severity_counts"]
    overall_severity = choose_overall_severity(severity_counts, status)

    commands = []
    command_evidence: list[str] = []
    for command in manifest.get("commands", []):
        output_path = relative_path(command.get("output_path"), workspace)
        stdout_path = relative_path(command.get("stdout_path"), workspace)
        stderr_path = relative_path(command.get("stderr_path"), workspace)
        if stdout_path:
            command_evidence.append(stdout_path)
        if stderr_path:
            command_evidence.append(stderr_path)
        commands.append(
            {
                "index": command.get("index"),
                "name": command.get("name"),
                "status": command.get("status"),
                "status_label": status_label(str(command.get("status"))),
                "exit_code": command.get("exit_code"),
                "output_path": output_path,
                "output_href": workspace_href(output_path),
                "stdout_path": stdout_path,
                "stdout_href": workspace_href(stdout_path),
                "stderr_path": stderr_path,
                "stderr_href": workspace_href(stderr_path),
            }
        )

    if status == "ok":
        conclusion = f"`{workflow}` 已执行完成，可直接根据本报告查看风险摘要和扫描结果。"
        next_action = "先阅读风险项和输出摘要；若仍需下钻，再打开对应 evidence 路径。"
    elif status == "dry-run":
        conclusion = f"`{workflow}` 仅完成预演，尚未执行正式扫描。"
        next_action = "确认参数后去掉 `--dry-run` 重新执行。"
    elif status == "blocked":
        conclusion = f"`{workflow}` 未执行成功，当前被阻塞。"
        next_action = "优先处理权限、参数或 runtime 问题，再重新执行。"
    else:
        conclusion = f"`{workflow}` 执行失败。"
        next_action = "优先检查 stderr、manifest.json 和对应输出文件。"

    warnings = list((summary.get("preflight") or {}).get("warnings", []))
    errors = list((summary.get("preflight") or {}).get("errors", []))
    artifact_index = build_artifact_index(
        summary_json="summary.json",
        manifest_json="manifest.json",
        output_paths=[item for item in outputs if item],
        extra_paths=[relative_path(item, workspace) for item in summary.get("runtime_state_files", []) if item],
    )

    return {
        "report_version": "2.0",
        "report_kind": "single-workflow",
        "title": f"C-Eyes Workflow Report - {workflow}",
        "generated_at": utc_now(),
        "status": status,
        "status_label": status_label(status),
        "severity": overall_severity,
        "severity_label": SEVERITY_LABELS[overall_severity],
        "workspace": str(workspace),
        "workspace_relative_report_dir": "report_result",
        "overview": {
            "workflow": workflow,
            "message": summary.get("message"),
            "requested_at": manifest.get("requested_at"),
            "dry_run": bool(manifest.get("dry_run")),
            "download_only": bool(manifest.get("download_only")),
        },
        "metrics": build_workflow_metrics(manifest, summary, output_digests, finding_rows),
        "chart_summary": chart_summary,
        "risk_summary": {
            "overall_severity": overall_severity,
            "overall_label": SEVERITY_LABELS[overall_severity],
            "counts": severity_counts,
        },
        "runtime": {
            "platform": manifest.get("runtime_target", {}).get("platform"),
            "arch": manifest.get("runtime_target", {}).get("arch"),
            "bundle_dir": manifest.get("runtime_target", {}).get("bundle_dir"),
            "binary": manifest.get("runtime_target", {}).get("binary"),
            "dist_root": manifest.get("runtime_target", {}).get("dist_root"),
            "staged_binary": relative_path(
                manifest.get("runtime_target", {}).get("staged_binary"),
                workspace,
            ),
        },
        "artifacts": {
            "summary_json": "summary.json",
            "manifest_json": "manifest.json",
            "outputs": outputs,
            "runtime_state_files": [
                relative_path(item, workspace)
                for item in summary.get("runtime_state_files", [])
                if item
            ],
        },
        "artifact_index": artifact_index,
        "commands": commands,
        "output_digests": output_digests,
        "findings": {
            "status": "findings-present"
            if any(row["severity"] in {"critical", "high", "medium"} for row in finding_rows)
            else "no-material-findings",
            "items": finding_rows,
        },
        "preflight": {
            "status": (summary.get("preflight") or {}).get("status"),
            "warnings": warnings,
            "errors": errors,
        },
        "technical_details": {
            "commands": commands,
            "command_evidence": command_evidence,
        },
        "conclusion": conclusion,
        "next_action": next_action,
    }


def build_investigation_report(
    workspace: Path,
    decision: dict[str, Any],
    findings: dict[str, Any],
    next_actions: dict[str, Any],
) -> dict[str, Any]:
    executed_steps = []
    step_artifacts: list[str] = []
    step_output_digests: list[dict[str, Any]] = []
    for step in decision.get("executed_steps", []):
        summary_path = relative_path(step.get("summary_path"), workspace)
        manifest_path = relative_path(step.get("manifest_path"), workspace)
        outputs = [relative_path(item, workspace) for item in step.get("outputs", []) if item]
        step_artifacts.extend([item for item in [summary_path, manifest_path, *outputs] if item])
        raw_output_digests = collect_output_digests(workspace, [item for item in step.get("outputs", []) if item])
        step_output_digests.extend(raw_output_digests)
        executed_steps.append(
            {
                "index": step.get("index"),
                "workflow": step.get("workflow"),
                "status": step.get("status"),
                "status_label": status_label(str(step.get("status"))),
                "workspace": relative_path(step.get("workspace"), workspace),
                "summary_path": summary_path,
                "summary_href": workspace_href(summary_path),
                "manifest_path": manifest_path,
                "manifest_href": workspace_href(manifest_path),
                "outputs": outputs,
                "output_hrefs": [workspace_href(item) for item in outputs if item],
                "preflight": step.get("preflight"),
                "output_digests": raw_output_digests,
            }
        )

    rendered_findings = []
    severity_counts = severity_counts_template()
    for item in findings.get("findings", []):
        severity = normalize_severity(item.get("severity"))
        add_severity_count(severity_counts, severity)
        evidence_paths = [
            relative_path(path, workspace) for path in item.get("evidence_paths", []) if path
        ]
        source_label = "人工聚合"
        source_detail = "Top-level investigation finding"
        if evidence_paths:
            first_path = evidence_paths[0]
            if "yara" in first_path.lower():
                source_label = "YARA 规则"
            elif "cloud" in first_path.lower():
                source_label = "云平台分析"
        rendered_findings.append(
            {
                "type": item.get("type"),
                "severity": severity,
                "severity_label": SEVERITY_LABELS[severity],
                "category": item.get("type") or item.get("workflow") or "调查发现",
                "workflow": item.get("workflow"),
                "status": item.get("status"),
                "message": item.get("message"),
                "evidence_paths": evidence_paths,
                "evidence_hrefs": [
                    workspace_href(relative_path(path, workspace))
                    for path in item.get("evidence_paths", [])
                    if path
                ],
                "evidence_source_label": source_label,
                "evidence_source_detail": source_detail,
                "evidence": item.get("message"),
            }
        )

    status = str(decision.get("status") or "unknown")
    overall_severity = choose_overall_severity(severity_counts, status)
    chart_summary = build_chart_summary_from_findings(rendered_findings)
    if status == "completed":
        conclusion = "自动调查链已执行完成，可直接从本报告查看调查结论、关键发现和后续建议。"
    elif status == "dry-run":
        conclusion = "自动调查链仅完成预演，尚未执行真实扫描步骤。"
    elif status == "blocked":
        conclusion = "自动调查链已阻塞，请先处理缺失参数、权限或 runtime 问题。"
    else:
        conclusion = "自动调查链执行失败，请结合步骤证据和日志继续排查。"

    artifact_index = [
        {"label": "decision.json", "path": "decision.json", "href": "../decision.json"},
        {"label": "findings.json", "path": "findings.json", "href": "../findings.json"},
        {"label": "next_actions.json", "path": "next_actions.json", "href": "../next_actions.json"},
    ]
    artifact_index.extend(build_artifact_index(None, None, [], extra_paths=step_artifacts))

    return {
        "report_version": "2.0",
        "report_kind": "investigation",
        "title": f"C-Eyes Investigation Report - {decision.get('goal', 'unknown')}",
        "generated_at": utc_now(),
        "status": status,
        "status_label": status_label(status),
        "severity": overall_severity,
        "severity_label": SEVERITY_LABELS[overall_severity],
        "workspace": str(workspace),
        "workspace_relative_report_dir": "report_result",
        "overview": {
            "goal": decision.get("goal"),
            "goal_description": decision.get("goal_description"),
            "selected_chain": decision.get("selected_chain", []),
            "stop_reason": decision.get("stop_reason"),
            "requested_at": decision.get("requested_at"),
        },
        "metrics": build_investigation_metrics(decision, rendered_findings),
        "chart_summary": chart_summary,
        "risk_summary": {
            "overall_severity": overall_severity,
            "overall_label": SEVERITY_LABELS[overall_severity],
            "counts": severity_counts,
        },
        "investigation_artifacts": {
            "decision_json": "decision.json",
            "findings_json": "findings.json",
            "next_actions_json": "next_actions.json",
        },
        "artifact_index": artifact_index,
        "executed_steps": executed_steps,
        "step_output_digests": step_output_digests,
        "findings": {
            "status": findings.get("status"),
            "status_label": status_label(str(findings.get("status"))),
            "items": rendered_findings,
        },
        "next_actions": {
            "status": next_actions.get("status"),
            "status_label": status_label(str(next_actions.get("status"))),
            "recommended_action": next_actions.get("recommended_action"),
            "reason": next_actions.get("reason"),
        },
        "technical_details": {
            "steps": executed_steps,
        },
        "conclusion": conclusion,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = [
        f"# {report['title']}",
        "",
        f"- 状态：{report['status_label']}",
        f"- 整体风险：{report['severity_label']}",
        f"- 工作目录：`{report['workspace']}`",
        f"- 最终报告目录：`report_result/`",
        f"- 生成时间：`{report['generated_at']}`",
        f"- Excel 报告：`report_result/report.xlsx`",
        "",
        "## 结论",
        "",
        report.get("conclusion", "无"),
        "",
        "## 关键指标",
        "",
    ]

    for metric in report.get("metrics", []):
        lines.append(f"- {metric['label']}: `{metric['value']}`")
    lines.append("")

    overview = report.get("overview", {})
    lines.extend(["## 概览", ""])
    for key, value in overview.items():
        lines.append(f"- {key}: `{value}`")
    lines.append("")

    lines.extend(["## 证据入口", ""])
    for item in report.get("artifact_index", []):
        lines.append(f"- {item['label']}: `{item['path']}`")
    lines.append("")

    findings_items = report.get("findings", {}).get("items", [])
    lines.extend(["## 风险摘要", ""])
    if findings_items:
        for item in findings_items[:10]:
            lines.append(
                f"- [{item.get('severity_label')}] {item.get('title')} / {item.get('source_path')}"
            )
            if item.get("evidence"):
                lines.append(f"  - evidence: `{item['evidence']}`")
    else:
        lines.append("- 未发现实质风险项")
    lines.append("")

    if report.get("report_kind") == "single-workflow":
        lines.extend(["## 输出文件摘要", ""])
        for digest in report.get("output_digests", []):
            lines.append(
                f"- `{digest['path']}` / records={digest['record_count']} / flagged={digest['flagged_count']}"
            )
        lines.extend(["", "## 下一步建议", "", report.get("next_action", "无"), ""])
    else:
        lines.extend(["## 调查步骤", ""])
        for step in report.get("executed_steps", []):
            lines.append(
                f"- [{step.get('index')}] {step.get('workflow')} / {step.get('status_label')}"
            )
            if step.get("summary_path"):
                lines.append(f"  - summary: `{step.get('summary_path')}`")
            if step.get("manifest_path"):
                lines.append(f"  - manifest: `{step.get('manifest_path')}`")
        lines.extend(
            [
                "",
                "## 下一步建议",
                "",
                f"- status: `{report.get('next_actions', {}).get('status')}`",
                f"- action: `{report.get('next_actions', {}).get('recommended_action')}`",
                f"- reason: {report.get('next_actions', {}).get('reason')}",
                "",
            ]
        )

    return "\n".join(lines)


def render_badge(text: str, severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["unknown"])
    return (
        f"<span class='badge badge-{severity}' style='--badge-color:{color};'>"
        f"{escape(text)}</span>"
    )


def render_metric_cards(metrics: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for metric in metrics:
        tone = str(metric.get("tone") or "info")
        parts.append(
            "<div class='metric-card'>"
            f"<div class='metric-label'>{escape(str(metric['label']))}</div>"
            f"<div class='metric-value metric-{escape(tone)}'>{escape(str(metric['value']))}</div>"
            "</div>"
        )
    return "".join(parts)


def render_risk_summary(risk_summary: dict[str, Any]) -> str:
    counts = ensure_dict(risk_summary.get("counts"))
    total = sum(int(counts.get(key, 0)) for key in counts)
    rows: list[str] = []
    for severity in ("critical", "high", "medium", "low", "info", "unknown"):
        count = int(counts.get(severity, 0))
        width = 0 if total == 0 else round(count / total * 100, 1)
        rows.append(
            "<div class='risk-row'>"
            f"<div class='risk-row-label'>{render_badge(SEVERITY_LABELS[severity], severity)}</div>"
            f"<div class='risk-bar'><span style='width:{width}%; background:{SEVERITY_COLORS[severity]};'></span></div>"
            f"<div class='risk-count'>{count}</div>"
            "</div>"
        )
    return "".join(rows)


def render_artifact_links(items: list[dict[str, str]]) -> str:
    if not items:
        return "<div class='empty'>暂无证据入口</div>"
    rows = []
    for item in items:
        href = item.get("href") or "#"
        rows.append(
            "<tr>"
            f"<td>{escape(item.get('label') or '')}</td>"
            f"<td><a href='{escape(href)}'>{escape(item.get('path') or '')}</a></td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>类型</th><th>路径</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def render_findings_table(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<div class='empty'>未发现实质风险项</div>"

    rows = []
    for item in items:
        rows.append(
            "<tr>"
            f"<td>{render_badge(str(item.get('severity_label') or item.get('severity')), str(item.get('severity')))}</td>"
            f"<td>{escape(str(item.get('title') or ''))}</td>"
            f"<td>{escape(str(item.get('evidence_source_label') or '聚合结论'))}</td>"
            f"<td>{escape(str(item.get('evidence_source_detail') or item.get('evidence') or item.get('message') or ''))}</td>"
            f"<td>{escape(str(item.get('evidence') or item.get('message') or ''))}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>级别</th><th>标题</th><th>结论来源</th><th>来源证据</th><th>关键证据</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def render_severity_bar_chart(counts: dict[str, int]) -> str:
    labels = [
        ("critical", "严重"),
        ("high", "高危"),
        ("medium", "中危"),
        ("low", "低危"),
        ("info", "信息"),
    ]
    max_value = max([int(counts.get(key, 0)) for key, _ in labels] + [1])
    columns = []
    for key, label in labels:
        value = int(counts.get(key, 0))
        height = max(8, round((value / max_value) * 180)) if value > 0 else 8
        columns.append(
            "<div class='bar-col'>"
            f"<div class='bar-count'>{value}</div>"
            "<div class='bar-track'>"
            f"<div class='bar-fill' style='height:{height}px; background:{SEVERITY_COLORS[key]};'></div>"
            "</div>"
            f"<div class='bar-label'>{label}</div>"
            "</div>"
        )
    return "<div class='bar-chart'>" + "".join(columns) + "</div>"


def render_donut_chart(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<div class='empty'>暂无占比数据</div>"

    palette = ["#b42318", "#155eef", "#16a34a", "#ea580c", "#7c3aed", "#0891b2"]
    total = sum(int(item.get("count", 0)) for item in items) or 1
    angle = 0.0
    gradient_parts: list[str] = []
    legends: list[str] = []
    for index, item in enumerate(items):
        count = int(item.get("count", 0))
        share = count / total
        color = palette[index % len(palette)]
        start = angle
        angle += share * 360.0
        gradient_parts.append(f"{color} {start:.2f}deg {angle:.2f}deg")
        legends.append(
            "<div class='donut-legend-item'>"
            f"<span class='legend-dot' style='background:{color};'></span>"
            f"<span>{escape(str(item.get('name')))} ({count})</span>"
            "</div>"
        )
    gradient = ", ".join(gradient_parts)
    return (
        "<div class='donut-wrap'>"
        f"<div class='donut-chart' style='background:conic-gradient({gradient});'><span>{total}</span></div>"
        f"<div class='donut-legend'>{''.join(legends)}</div>"
        "</div>"
    )


def render_chart_summary(chart_summary: dict[str, Any]) -> str:
    severity_counts = ensure_dict(chart_summary.get("severity_counts"))
    secondary_title = stringify_value(chart_summary.get("secondary_title"))
    secondary_counts = chart_summary.get("secondary_counts", [])
    primary = (
        "<section class='chart-card'>"
        "<h2>风险数量分布</h2>"
        + render_severity_bar_chart(severity_counts)
        + "</section>"
    )
    if secondary_title and secondary_counts:
        return (
            "<div class='charts-grid'>"
            + primary
            + "<section class='chart-card'>"
            + f"<h2>{escape(secondary_title)}</h2>"
            + render_donut_chart(secondary_counts)
            + "</section>"
            + "</div>"
        )
    return "<div class='charts-grid charts-grid-single'>" + primary + "</div>"


def render_output_digests(output_digests: list[dict[str, Any]]) -> str:
    if not output_digests:
        return "<div class='empty'>没有可展示的 workflow 输出</div>"

    cards: list[str] = []
    for digest in output_digests:
        collection_rows: list[str] = []
        for collection in digest.get("collections", []):
            sample_rows = collection.get("sample_rows", [])
            sample_html = render_findings_table(sample_rows)
            collection_rows.append(
                "<details class='collection-card'>"
                f"<summary>{escape(collection['name'])} / records={collection['record_count']} / flagged={collection['flagged_count']}</summary>"
                f"<div class='collection-body'>{sample_html}</div>"
                "</details>"
            )

        notes = []
        if digest.get("top_level_summary"):
            notes.append(f"<div class='muted'>{escape(str(digest['top_level_summary']))}</div>")
        if digest.get("load_error"):
            notes.append(f"<div class='danger'>读取失败: {escape(str(digest['load_error']))}</div>")

        href = digest.get("href") or "#"
        cards.append(
            "<section class='output-card'>"
            f"<div class='output-card-header'><h3><a href='{escape(href)}'>{escape(digest['path'])}</a></h3>"
            f"<div class='output-meta'>records={digest['record_count']} / flagged={digest['flagged_count']}</div></div>"
            + "".join(notes)
            + "".join(collection_rows or ["<div class='empty'>没有可提取的记录集合</div>"])
            + "</section>"
        )
    return "".join(cards)


def render_commands_table(commands: list[dict[str, Any]]) -> str:
    if not commands:
        return "<div class='empty'>没有命令执行记录</div>"

    rows = []
    for command in commands:
        links: list[str] = []
        if command.get("output_path") and command.get("output_href"):
            links.append(f"<a href='{escape(command['output_href'])}'>output</a>")
        if command.get("stdout_path") and command.get("stdout_href"):
            links.append(f"<a href='{escape(command['stdout_href'])}'>stdout</a>")
        if command.get("stderr_path") and command.get("stderr_href"):
            links.append(f"<a href='{escape(command['stderr_href'])}'>stderr</a>")
        rows.append(
            "<tr>"
            f"<td>{escape(str(command.get('index')))}</td>"
            f"<td>{escape(str(command.get('name')))}</td>"
            f"<td>{escape(str(command.get('status_label')))}</td>"
            f"<td>{escape(str(command.get('exit_code')))}</td>"
            f"<td>{' / '.join(links) or '-'}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>#</th><th>命令</th><th>状态</th><th>退出码</th><th>证据</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def render_steps_table(steps: list[dict[str, Any]]) -> str:
    if not steps:
        return "<div class='empty'>没有执行步骤</div>"

    rows = []
    for step in steps:
        evidence: list[str] = []
        if step.get("summary_path") and step.get("summary_href"):
            evidence.append(f"<a href='{escape(step['summary_href'])}'>summary</a>")
        if step.get("manifest_path") and step.get("manifest_href"):
            evidence.append(f"<a href='{escape(step['manifest_href'])}'>manifest</a>")
        rows.append(
            "<tr>"
            f"<td>{escape(str(step.get('index')))}</td>"
            f"<td>{escape(str(step.get('workflow')))}</td>"
            f"<td>{escape(str(step.get('status_label')))}</td>"
            f"<td>{' / '.join(evidence) or '-'}</td>"
            "</tr>"
        )
    return (
        "<table><thead><tr><th>#</th><th>Workflow</th><th>状态</th><th>证据</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def render_html(report: dict[str, Any]) -> str:
    top_actions = (
        "<div class='top-actions'>"
        "<a class='action-link' href='report.json'>report.json</a>"
        "<a class='action-link' href='summary.md'>summary.md</a>"
        "<a class='action-link' href='report.xlsx'>report.xlsx</a>"
        "</div>"
    )

    overview_items = "".join(
        "<div class='overview-item'>"
        f"<div class='overview-key'>{escape(str(key))}</div>"
        f"<div class='overview-value'>{escape(stringify_value(value))}</div>"
        "</div>"
        for key, value in report.get("overview", {}).items()
    )

    preflight = ensure_dict(report.get("preflight"))
    preflight_html = ""
    warnings = list(preflight.get("warnings", []))
    errors = list(preflight.get("errors", []))
    if warnings or errors:
        preflight_rows = "".join(f"<li>warning: {escape(str(item))}</li>" for item in warnings) + "".join(
            f"<li>error: {escape(str(item))}</li>" for item in errors
        )
        preflight_html = f"<section><h2>预检信息</h2><ul>{preflight_rows}</ul></section>"

    appendix_html = ""
    if report.get("report_kind") == "single-workflow":
        details_section = (
            "<section><h2>扫描结果摘要</h2>"
            + render_output_digests(report.get("output_digests", []))
            + "</section>"
            "<section><h2>下一步建议</h2>"
            f"<p>{escape(str(report.get('next_action') or '无'))}</p>"
            "</section>"
        )
        appendix_html = (
            "<details class='appendix'><summary>技术附录</summary>"
            "<div class='appendix-body'>"
            "<h3>执行命令</h3>"
            + render_commands_table(report.get("commands", []))
            + "</div></details>"
        )
    else:
        details_section = (
            "<section><h2>步骤结果摘要</h2>"
            + render_output_digests(report.get("step_output_digests", []))
            + "</section>"
            "<section><h2>下一步建议</h2>"
            f"<p><strong>{escape(str(report.get('next_actions', {}).get('status_label') or ''))}</strong></p>"
            f"<p>action: <code>{escape(str(report.get('next_actions', {}).get('recommended_action') or ''))}</code></p>"
            f"<p>{escape(str(report.get('next_actions', {}).get('reason') or ''))}</p>"
            "</section>"
        )
        appendix_html = (
            "<details class='appendix'><summary>技术附录</summary>"
            "<div class='appendix-body'>"
            "<h3>调查步骤</h3>"
            + render_steps_table(report.get("executed_steps", []))
            + "</div></details>"
        )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(report['title'])}</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --panel: #ffffff;
      --panel-alt: #f8fafc;
      --line: #d0d5dd;
      --text: #101828;
      --muted: #475467;
      --brand: #123156;
      --brand-2: #1f4b82;
      --brand-3: #5ea0ef;
      --danger: #b42318;
      --warning: #b54708;
      --success: #027a48;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
    }}
    .hero {{
      background: linear-gradient(135deg, var(--brand) 0%, var(--brand-2) 62%, #15365b 100%);
      color: #fff;
      padding: 32px 0 28px;
    }}
    .hero-inner, main {{
      max-width: 1320px;
      margin: 0 auto;
      padding: 0 28px;
    }}
    .eyebrow {{
      font-size: 12px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      opacity: 0.78;
      margin-bottom: 8px;
    }}
    h1 {{
      margin: 0;
      font-size: 30px;
      line-height: 1.2;
    }}
    .hero-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }}
    .chip, .action-link {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 7px 12px;
      border-radius: 999px;
      border: 1px solid rgba(255,255,255,0.18);
      background: rgba(255,255,255,0.10);
      color: #fff;
      text-decoration: none;
      font-size: 13px;
    }}
    .top-actions {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 16px;
    }}
    main {{
      padding-top: 26px;
      padding-bottom: 48px;
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 22px;
      margin-bottom: 18px;
    }}
    h2 {{
      margin: 0 0 16px;
      font-size: 18px;
    }}
    h3 {{
      margin: 0 0 10px;
      font-size: 16px;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }}
    .charts-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
      margin-bottom: 18px;
    }}
    .charts-grid-single {{
      grid-template-columns: 1fr;
    }}
    .chart-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 22px;
    }}
    .metric-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px;
      min-height: 96px;
    }}
    .metric-label {{
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 8px;
    }}
    .metric-value {{
      font-size: 28px;
      font-weight: 700;
      word-break: break-word;
    }}
    .metric-high {{ color: var(--danger); }}
    .metric-medium {{ color: var(--warning); }}
    .metric-info {{ color: var(--brand-2); }}
    .layout-2 {{
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 18px;
      margin-bottom: 18px;
    }}
    .overview-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    .overview-item {{
      background: var(--panel-alt);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px 14px;
    }}
    .overview-key {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 4px;
    }}
    .overview-value {{
      font-size: 14px;
      word-break: break-word;
    }}
    .risk-row {{
      display: grid;
      grid-template-columns: 88px 1fr 42px;
      gap: 10px;
      align-items: center;
      margin-bottom: 10px;
    }}
    .risk-bar {{
      height: 10px;
      background: #e4e7ec;
      border-radius: 999px;
      overflow: hidden;
    }}
    .risk-bar span {{
      display: block;
      height: 100%;
      border-radius: 999px;
    }}
    .risk-count {{
      text-align: right;
      font-weight: 700;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      background: color-mix(in srgb, var(--badge-color) 14%, white);
      color: var(--badge-color);
      font-size: 12px;
      font-weight: 700;
    }}
    .bar-chart {{
      height: 260px;
      display: grid;
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 14px;
      align-items: end;
      padding-top: 10px;
    }}
    .bar-col {{
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      height: 100%;
    }}
    .bar-count {{
      font-weight: 700;
      color: var(--muted);
    }}
    .bar-track {{
      display: flex;
      align-items: end;
      justify-content: center;
      height: 190px;
      width: 100%;
      background: linear-gradient(to top, #eef2f6, #f8fafc);
      border-radius: 10px;
      padding: 8px;
    }}
    .bar-fill {{
      width: min(72px, 100%);
      border-radius: 10px 10px 4px 4px;
    }}
    .bar-label {{
      font-size: 13px;
      color: var(--muted);
    }}
    .donut-wrap {{
      display: grid;
      grid-template-columns: 280px 1fr;
      gap: 20px;
      align-items: center;
      min-height: 260px;
    }}
    .donut-chart {{
      width: 248px;
      height: 248px;
      border-radius: 50%;
      position: relative;
      margin: 0 auto;
    }}
    .donut-chart::before {{
      content: "";
      position: absolute;
      inset: 48px;
      background: #fff;
      border-radius: 50%;
      box-shadow: inset 0 0 0 1px var(--line);
    }}
    .donut-chart span {{
      position: absolute;
      inset: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 32px;
      font-weight: 700;
      color: var(--brand);
    }}
    .donut-legend {{
      display: flex;
      flex-direction: column;
      gap: 10px;
    }}
    .donut-legend-item {{
      display: flex;
      align-items: center;
      gap: 10px;
      color: var(--text);
    }}
    .legend-dot {{
      width: 12px;
      height: 12px;
      border-radius: 50%;
      flex: none;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      text-align: left;
      padding: 11px 10px;
      vertical-align: top;
      font-size: 14px;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    a {{
      color: var(--brand-2);
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}
    code {{
      background: #eef2f6;
      padding: 2px 6px;
      border-radius: 4px;
      word-break: break-all;
    }}
    .output-card {{
      background: var(--panel-alt);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 14px;
    }}
    .output-card-header {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: start;
      margin-bottom: 10px;
    }}
    .output-meta, .muted {{
      color: var(--muted);
      font-size: 13px;
    }}
    .collection-card {{
      margin-top: 10px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
      padding: 10px 12px;
    }}
    .collection-card summary {{
      cursor: pointer;
      font-weight: 600;
    }}
    .collection-body {{
      margin-top: 12px;
    }}
    .empty {{
      color: var(--muted);
      padding: 8px 0;
    }}
    .danger {{
      color: var(--danger);
      font-size: 13px;
      margin-top: 6px;
    }}
    .appendix {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px 18px;
      margin-bottom: 18px;
    }}
    .appendix summary {{
      cursor: pointer;
      font-weight: 700;
    }}
    .appendix-body {{
      margin-top: 16px;
    }}
    @media (max-width: 1100px) {{
      .summary-grid {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
      .charts-grid {{ grid-template-columns: 1fr; }}
      .layout-2 {{ grid-template-columns: 1fr; }}
      .donut-wrap {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 720px) {{
      .summary-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .overview-grid {{ grid-template-columns: 1fr; }}
      .hero-inner, main {{ padding-left: 16px; padding-right: 16px; }}
      h1 {{ font-size: 24px; }}
    }}
  </style>
</head>
<body>
  <header class="hero">
    <div class="hero-inner">
      <div class="eyebrow">c-eyes-automation final report</div>
      <h1>{escape(report['title'])}</h1>
      <div class="hero-meta">
        <span class="chip">状态：{escape(report['status_label'])}</span>
        <span class="chip">整体风险：{escape(report['severity_label'])}</span>
        <span class="chip">报告目录：report_result/</span>
        <span class="chip">生成时间：{escape(report['generated_at'])}</span>
      </div>
      {top_actions}
    </div>
  </header>
  <main>
    <section>
      <h2>结论</h2>
      <p>{escape(str(report.get('conclusion') or '无'))}</p>
    </section>

    <div class="summary-grid">{render_metric_cards(report.get('metrics', []))}</div>

    {render_chart_summary(report.get('chart_summary', {}))}

    <div class="layout-2">
      <section>
        <h2>任务概览</h2>
        <div class="overview-grid">{overview_items}</div>
      </section>
      <section>
        <h2>风险总览</h2>
        {render_risk_summary(report.get('risk_summary', {}))}
      </section>
    </div>

    <section>
      <h2>关键发现</h2>
      {render_findings_table(report.get('findings', {}).get('items', []))}
    </section>

    <section>
      <h2>证据入口</h2>
      {render_artifact_links(report.get('artifact_index', []))}
    </section>

    {details_section}
    {appendix_html}
    {preflight_html}
  </main>
</body>
</html>
"""


def excel_cell_ref(row: int, col: int) -> str:
    result = ""
    current = col
    while current > 0:
        current, remainder = divmod(current - 1, 26)
        result = chr(65 + remainder) + result
    return f"{result}{row}"


def excel_column_width(rows: list[list[Any]], index: int) -> int:
    width = 10
    for row in rows:
        if index < len(row):
            width = max(width, min(48, len(stringify_value(row[index])) + 2))
    return width


def excel_inline_cell(value: Any, row: int, col: int) -> str:
    ref = excel_cell_ref(row, col)
    if value is None:
        return f'<c r="{ref}" t="inlineStr"><is><t></t></is></c>'
    if isinstance(value, bool):
        numeric = "1" if value else "0"
        return f'<c r="{ref}" t="n"><v>{numeric}</v></c>'
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return f'<c r="{ref}" t="n"><v>{value}</v></c>'
    text = xml_escape(stringify_value(value))
    return f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>'


def build_sheet_xml(rows: list[list[Any]]) -> str:
    max_cols = max((len(row) for row in rows), default=1)
    cols = "".join(
        f'<col min="{index}" max="{index}" width="{excel_column_width(rows, index - 1)}" customWidth="1"/>'
        for index in range(1, max_cols + 1)
    )
    row_xml: list[str] = []
    for row_index, row in enumerate(rows, start=1):
        cells = "".join(excel_inline_cell(value, row_index, col_index) for col_index, value in enumerate(row, start=1))
        row_xml.append(f'<row r="{row_index}">{cells}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"<cols>{cols}</cols>"
        f"<sheetData>{''.join(row_xml)}</sheetData>"
        "</worksheet>"
    )


def build_workbook_xml(sheet_names: list[str]) -> str:
    sheets = "".join(
        f'<sheet name="{xml_escape(name)}" sheetId="{index}" r:id="rId{index}"/>'
        for index, name in enumerate(sheet_names, start=1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{sheets}</sheets>"
        "</workbook>"
    )


def build_workbook_rels(sheet_count: int) -> str:
    rels = "".join(
        f'<Relationship Id="rId{index}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, sheet_count + 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{rels}"
        "</Relationships>"
    )


def build_root_rels() -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )


def build_content_types(sheet_count: int) -> str:
    overrides = [
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
    ]
    overrides.extend(
        f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for index in range(1, sheet_count + 1)
    )
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f"{''.join(overrides)}"
        "</Types>"
    )


def write_xlsx(path: Path, sheets: list[tuple[str, list[list[Any]]]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as workbook:
        workbook.writestr("[Content_Types].xml", build_content_types(len(sheets)))
        workbook.writestr("_rels/.rels", build_root_rels())
        workbook.writestr("xl/workbook.xml", build_workbook_xml([name for name, _ in sheets]))
        workbook.writestr("xl/_rels/workbook.xml.rels", build_workbook_rels(len(sheets)))
        for index, (_, rows) in enumerate(sheets, start=1):
            workbook.writestr(f"xl/worksheets/sheet{index}.xml", build_sheet_xml(rows))


def build_workflow_excel_sheets(report: dict[str, Any]) -> list[tuple[str, list[list[Any]]]]:
    overview_rows = [
        ["字段", "值"],
        ["title", report.get("title")],
        ["status", report.get("status_label")],
        ["severity", report.get("severity_label")],
        ["workflow", report.get("overview", {}).get("workflow")],
        ["message", report.get("overview", {}).get("message")],
        ["requested_at", report.get("overview", {}).get("requested_at")],
        ["generated_at", report.get("generated_at")],
        ["conclusion", report.get("conclusion")],
        ["next_action", report.get("next_action")],
    ]

    findings_rows = [["级别", "标题", "结论来源", "来源证据", "关键证据", "来源文件"]]
    for item in report.get("findings", {}).get("items", []):
        findings_rows.append(
            [
                item.get("severity_label"),
                item.get("title"),
                item.get("evidence_source_label"),
                item.get("evidence_source_detail"),
                item.get("evidence"),
                item.get("source_path"),
            ]
        )

    outputs_rows = [["输出文件", "格式", "记录数", "风险项", "顶层摘要"]]
    for digest in report.get("output_digests", []):
        outputs_rows.append(
            [
                digest.get("path"),
                digest.get("format"),
                digest.get("record_count"),
                digest.get("flagged_count"),
                digest.get("top_level_summary") or digest.get("load_error"),
            ]
        )

    commands_rows = [["#", "命令", "状态", "退出码", "output", "stdout", "stderr"]]
    for command in report.get("commands", []):
        commands_rows.append(
            [
                command.get("index"),
                command.get("name"),
                command.get("status_label"),
                command.get("exit_code"),
                command.get("output_path"),
                command.get("stdout_path"),
                command.get("stderr_path"),
            ]
        )

    evidence_rows = [["类型", "路径"]]
    for item in report.get("artifact_index", []):
        evidence_rows.append([item.get("label"), item.get("path")])

    return [
        ("Overview", overview_rows),
        ("Findings", findings_rows),
        ("Outputs", outputs_rows),
        ("Technical", commands_rows),
        ("Evidence", evidence_rows),
    ]


def build_investigation_excel_sheets(report: dict[str, Any]) -> list[tuple[str, list[list[Any]]]]:
    overview_rows = [
        ["字段", "值"],
        ["title", report.get("title")],
        ["status", report.get("status_label")],
        ["severity", report.get("severity_label")],
        ["goal", report.get("overview", {}).get("goal")],
        ["goal_description", report.get("overview", {}).get("goal_description")],
        ["selected_chain", ", ".join(str(item) for item in report.get("overview", {}).get("selected_chain", []))],
        ["stop_reason", report.get("overview", {}).get("stop_reason")],
        ["generated_at", report.get("generated_at")],
        ["conclusion", report.get("conclusion")],
        ["recommended_action", report.get("next_actions", {}).get("recommended_action")],
        ["reason", report.get("next_actions", {}).get("reason")],
    ]

    findings_rows = [["级别", "workflow", "结论来源", "消息", "证据路径"]]
    for item in report.get("findings", {}).get("items", []):
        findings_rows.append(
            [
                item.get("severity_label"),
                item.get("workflow"),
                item.get("evidence_source_label"),
                item.get("message"),
                " | ".join(item.get("evidence_paths", [])),
            ]
        )

    steps_rows = [["#", "workflow", "状态", "workspace", "summary", "manifest", "outputs"]]
    for step in report.get("executed_steps", []):
        steps_rows.append(
            [
                step.get("index"),
                step.get("workflow"),
                step.get("status_label"),
                step.get("workspace"),
                step.get("summary_path"),
                step.get("manifest_path"),
                " | ".join(step.get("outputs", [])),
            ]
        )

    evidence_rows = [["类型", "路径"]]
    for item in report.get("artifact_index", []):
        evidence_rows.append([item.get("label"), item.get("path")])

    outputs_rows = [["输出文件", "格式", "记录数", "风险项", "顶层摘要"]]
    for digest in report.get("step_output_digests", []):
        outputs_rows.append(
            [
                digest.get("path"),
                digest.get("format"),
                digest.get("record_count"),
                digest.get("flagged_count"),
                digest.get("top_level_summary") or digest.get("load_error"),
            ]
        )

    return [
        ("Overview", overview_rows),
        ("Findings", findings_rows),
        ("Technical", steps_rows),
        ("Outputs", outputs_rows),
        ("Evidence", evidence_rows),
    ]


def write_report_bundle(workspace: Path, report: dict[str, Any]) -> None:
    report_dir = report_result_dir(workspace)
    write_json(report_dir / "report.json", report)
    write_text(report_dir / "summary.md", render_markdown(report))
    write_text(report_dir / "report.html", render_html(report))
    sheets = (
        build_workflow_excel_sheets(report)
        if report.get("report_kind") == "single-workflow"
        else build_investigation_excel_sheets(report)
    )
    write_xlsx(report_dir / "report.xlsx", sheets)


# ---------------------------------------------------------------------------
# Clean report overrides
# ---------------------------------------------------------------------------

SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
    "unknown": "未知",
}

SEVERITY_COLORS = {
    "critical": "#b42318",
    "high": "#dc6803",
    "medium": "#b54708",
    "low": "#027a48",
    "info": "#155eef",
    "unknown": "#667085",
}

STATUS_LABELS = {
    "ok": "成功",
    "completed": "成功",
    "dry-run": "仅预演",
    "blocked": "阻塞",
    "failed": "失败",
    "planned": "已计划",
    "review-results": "待复核",
    "manual-follow-up": "需人工跟进",
    "ready-for-live-run": "可正式执行",
    "no-material-findings": "未发现重点问题",
    "findings-present": "存在重点结果",
}

WORKFLOW_LABELS = {
    "host-triage": "主机快速排查",
    "filescan-risk": "文件风险扫描",
    "baseline-check": "安全基线检查",
    "network-inventory": "内网探测",
    "eventlog-timeline": "日志信息收集",
    "sbom-inventory": "软件清单盘点",
}

WORKFLOW_PROFILES = {
    "host-triage": "risk",
    "filescan-risk": "risk",
    "baseline-check": "baseline",
    "network-inventory": "collection",
    "eventlog-timeline": "collection",
    "sbom-inventory": "collection",
}


def status_label(status: str) -> str:
    key = str(status or "").strip()
    return STATUS_LABELS.get(key, key or "未知")


def normalize_severity(value: Any) -> str:
    if value is None:
        return "unknown"
    if isinstance(value, (int, float)):
        score = float(value)
        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        if score > 0:
            return "low"
        return "info"

    text = str(value).strip().lower()
    if not text:
        return "unknown"

    mapping = {
        "critical": "critical",
        "severe": "critical",
        "fatal": "critical",
        "malicious": "critical",
        "high": "high",
        "danger": "high",
        "medium": "medium",
        "moderate": "medium",
        "warning": "medium",
        "warn": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "ok": "info",
        "success": "info",
        "passed": "info",
        "unknown": "unknown",
        "严重": "critical",
        "高危": "high",
        "中危": "medium",
        "低危": "low",
        "信息": "info",
        "异常": "medium",
        "可疑": "high",
        "正常": "info",
        "高": "high",
        "中": "medium",
        "低": "low",
    }
    if text in mapping:
        return mapping[text]
    for key, normalized in mapping.items():
        if key and key in text:
            return normalized
    return "unknown"


def infer_record_title(record: dict[str, Any]) -> str:
    for key in TITLE_KEYS:
        value = stringify_value(record.get(key))
        if value:
            return value
    interesting = summarize_record(record, max_fields=4)
    return interesting or "未命名记录"


def infer_record_evidence_source(record: dict[str, Any]) -> tuple[str, str, str]:
    yara_source, yara_detail = infer_yara_evidence(record)
    if yara_source and yara_detail:
        return yara_source, "YARA 规则", yara_detail

    cloud_source, cloud_detail = infer_cloud_evidence(record)
    if cloud_source and cloud_detail:
        return cloud_source, "云平台分析", cloud_detail

    status = stringify_value(record.get("status") or record.get("result"))
    if status:
        return "behavior", "行为结果", f"Behavior: status={status}"
    return "other", "通用字段", "General fields"


def infer_record_evidence(record: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in EVIDENCE_KEYS:
        if key == "status":
            continue
        value = stringify_value(record.get(key))
        if value:
            parts.append(f"{key}={value}")
        if len(parts) >= 3:
            break
    if parts:
        return " | ".join(parts)
    return summarize_record(record, max_fields=5)


def workflow_display_name(workflow: str) -> str:
    return WORKFLOW_LABELS.get(workflow, workflow or "未知流程")


def workflow_profile(workflow: str) -> str:
    return WORKFLOW_PROFILES.get(workflow, "risk")


def derive_workflow_from_output_path(output_path: str) -> str:
    path = Path(output_path)
    parent = path.parent.name.strip()
    return parent or "unknown"


def normalize_text_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [stringify_value(item) for item in value if stringify_value(item)]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def format_timestamp(value: Any) -> str:
    text = stringify_value(value)
    if not text:
        return ""
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), tz=timezone.utc).isoformat()
        except Exception:
            return text
    return text


def display_asset_status(value: str) -> str:
    mapping = {
        "managed": "受管",
        "unmanaged": "未纳管",
        "ignored": "已忽略",
        "unknown": "未知",
    }
    raw = value.strip().lower()
    return mapping.get(raw, value or "未知")


def display_event_level(value: str) -> str:
    mapping = {
        "critical": "严重",
        "error": "错误",
        "warning": "告警",
        "warn": "告警",
        "info": "信息",
        "informational": "信息",
        "debug": "调试",
    }
    raw = value.strip().lower()
    return mapping.get(raw, value or "未标注")


def display_result(value: str) -> str:
    mapping = {
        "ok": "正常",
        "success": "成功",
        "warning": "关注",
        "failed": "失败",
        "error": "错误",
        "blocked": "阻塞",
    }
    raw = value.strip().lower()
    return mapping.get(raw, value or "")


def build_generic_table_section(
    title: str,
    columns: list[dict[str, str]],
    rows: list[dict[str, Any]],
    empty_message: str,
    filters: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "title": title,
        "columns": columns,
        "rows": rows,
        "empty_message": empty_message,
        "filters": filters or [],
    }


def rows_to_sheet_rows(section: dict[str, Any]) -> list[list[Any]]:
    columns = section.get("columns", [])
    rows = section.get("rows", [])
    header = [column["label"] for column in columns]
    sheet_rows = [header]
    for row in rows:
        sheet_rows.append([row.get(column["key"]) for column in columns])
    return sheet_rows


def make_filter_definition(label: str, column: str, options: list[str]) -> dict[str, Any]:
    normalized = [item for item in options if item]
    unique = sorted(set(normalized))
    return {"label": label, "column": column, "options": unique}


def make_status_filter_options(rows: list[dict[str, Any]], key: str) -> list[str]:
    values: list[str] = []
    for row in rows:
        value = stringify_value(row.get(key))
        if value:
            values.append(value)
    return sorted(set(values))


def severity_bar_items(counts: dict[str, int]) -> list[dict[str, Any]]:
    return [
        {"name": SEVERITY_LABELS[key], "count": int(counts.get(key, 0)), "color": SEVERITY_COLORS[key]}
        for key in ("critical", "high", "medium", "low", "info", "unknown")
    ]


def named_count_items(named_counts: dict[str, int], palette: list[str] | None = None) -> list[dict[str, Any]]:
    colors = palette or ["#1f4b82", "#155eef", "#027a48", "#dc6803", "#7a5af8", "#475467"]
    items: list[dict[str, Any]] = []
    for index, (name, count) in enumerate(sorted(named_counts.items(), key=lambda item: (-item[1], item[0]))):
        if count <= 0:
            continue
        items.append({"name": name, "count": int(count), "color": colors[index % len(colors)]})
    return items


def baseline_status_bucket(record: dict[str, Any]) -> str:
    status = stringify_value(record.get("status")).strip().lower()
    status_reason = stringify_value(record.get("status_reason") or record.get("statusReason")).strip().lower()
    execution_status = stringify_value(record.get("execution_status") or record.get("executionStatus")).strip().lower()
    evaluated = record.get("evaluated")

    if execution_status == "pending" or status == "pending":
        return "pending"
    if status == "pass":
        return "pass"
    if status == "fail":
        return "fail"
    if status == "unknown" and status_reason == "informational_check":
        return "informational"
    if status == "unknown":
        return "unknown"
    if evaluated is False:
        return "pending"
    return "unknown"


def baseline_status_display(bucket: str) -> str:
    mapping = {
        "pass": "符合",
        "fail": "不符合",
        "unknown": "待确认",
        "informational": "信息项",
        "pending": "待执行",
    }
    return mapping.get(bucket, "待确认")


def baseline_row_severity(record: dict[str, Any], bucket: str) -> str:
    if bucket == "fail":
        severity = normalize_severity(record.get("severity"))
        return severity if severity != "unknown" else "medium"
    if bucket in {"pass", "informational"}:
        return "info"
    if bucket == "pending":
        return "unknown"
    return "low"


def build_baseline_row(record: dict[str, Any], source_path: str, collection_name: str) -> dict[str, Any]:
    bucket = baseline_status_bucket(record)
    severity = baseline_row_severity(record, bucket)
    risk_level = SEVERITY_LABELS[severity] if bucket == "fail" else ""
    expected = stringify_value(record.get("expected"))
    actual = stringify_value(record.get("actual"))
    recommendation = stringify_value(record.get("recommendation"))
    evidence = stringify_value(record.get("evidence"))
    check_id = stringify_value(record.get("check_id") or record.get("checkId"))
    check_name = stringify_value(record.get("check_name") or record.get("checkName") or record.get("title"))
    category = stringify_value(record.get("category"))
    description = stringify_value(record.get("description"))
    title = check_name or description or check_id or "未命名检查项"
    key_evidence = " | ".join([item for item in [actual, evidence] if item][:2])

    return {
        "severity": severity,
        "severity_label": SEVERITY_LABELS[severity],
        "status": stringify_value(record.get("status")),
        "status_label": baseline_status_display(bucket),
        "bucket": bucket,
        "title": title,
        "source_path": source_path,
        "collection": collection_name,
        "evidence_source": "baseline",
        "evidence_source_label": "基线判定",
        "evidence_source_detail": baseline_status_display(bucket),
        "evidence": key_evidence,
        "summary": summarize_record(record, max_fields=6),
        "raw": compact_json(record, 300),
        "check_id": check_id,
        "check_name": check_name or title,
        "category": category,
        "expected": expected,
        "actual": actual,
        "recommendation": recommendation,
        "risk_level": risk_level,
        "_attrs": {
            "bucket": bucket,
            "category": category.lower(),
            "risk-level": risk_level.lower(),
        },
    }


def build_network_row(record: dict[str, Any], source_path: str, collection_name: str) -> dict[str, Any]:
    hostname = stringify_value(record.get("hostname"))
    ip_address = stringify_value(record.get("ipAddress"))
    asset_status_raw = stringify_value(record.get("assetStatus"))
    asset_status = display_asset_status(asset_status_raw)
    os_family = stringify_value(record.get("osFamily"))
    device_type = stringify_value(record.get("deviceType"))
    sources = normalize_text_list(record.get("sources") or record.get("source"))
    scan_modes = normalize_text_list(record.get("scanModes") or record.get("scanMode"))
    ports = record.get("openPorts") or record.get("openTcpPorts") or []
    confidence = stringify_value(record.get("confidence"))
    severity = infer_record_severity(record)
    status = stringify_value(record.get("status"))
    title = hostname or ip_address or stringify_value(record.get("assetId")) or "未知资产"
    ports_text = ", ".join(str(item) for item in ports[:12]) if isinstance(ports, list) else stringify_value(ports)
    attention = asset_status_raw.lower() == "unmanaged" or severity in {"critical", "high", "medium"} or status.lower() == "warning"

    return {
        "severity": severity if severity != "unknown" else "info",
        "severity_label": SEVERITY_LABELS[severity if severity != "unknown" else "info"],
        "title": title,
        "source_path": source_path,
        "collection": collection_name,
        "status": status,
        "status_label": display_result(status) or asset_status,
        "category": asset_status or device_type,
        "evidence_source": "asset-row",
        "evidence_source_label": "资产记录",
        "evidence_source_detail": " / ".join([item for item in [asset_status, os_family, device_type] if item]),
        "evidence": " | ".join([item for item in [f"开放端口={ports_text}" if ports_text else "", f"来源={', '.join(sources[:4])}" if sources else ""] if item]),
        "summary": summarize_record(record, max_fields=7),
        "raw": compact_json(record, 300),
        "ip_address": ip_address,
        "hostname": hostname,
        "asset_status": asset_status,
        "os_family": os_family,
        "device_type": device_type,
        "open_ports": ports_text,
        "sources": ", ".join(sources),
        "scan_modes": ", ".join(scan_modes),
        "confidence": confidence,
        "last_seen": format_timestamp(record.get("lastSeen")),
        "attention": attention,
        "_attrs": {
            "asset-status": asset_status_raw.lower(),
            "asset-status-label": asset_status.lower(),
            "os-family": os_family.lower(),
            "attention": "yes" if attention else "no",
        },
    }


def build_eventlog_row(record: dict[str, Any], source_path: str, collection_name: str) -> dict[str, Any]:
    event_level_raw = stringify_value(record.get("eventLevel"))
    event_level = display_event_level(event_level_raw)
    result_raw = stringify_value(record.get("result") or record.get("status"))
    result = display_result(result_raw)
    source = stringify_value(record.get("source"))
    process_name = stringify_value(record.get("processName"))
    username = stringify_value(record.get("username"))
    target_path = stringify_value(record.get("targetPath") or record.get("target_path"))
    remote_ip = stringify_value(record.get("remoteIp"))
    message = stringify_value(record.get("message"))
    severity = infer_record_severity(record)
    title = (
        stringify_value(record.get("title"))
        or process_name
        or message
        or stringify_value(record.get("eventCode"))
        or "日志记录"
    )
    attention = severity in {"critical", "high", "medium"} or result_raw.lower() in {"warning", "failed", "error"}

    return {
        "severity": severity if severity != "unknown" else "info",
        "severity_label": SEVERITY_LABELS[severity if severity != "unknown" else "info"],
        "title": title,
        "source_path": source_path,
        "collection": collection_name,
        "status": result_raw,
        "status_label": result,
        "category": source or stringify_value(record.get("eventType")),
        "evidence_source": "eventlog-row",
        "evidence_source_label": "日志记录",
        "evidence_source_detail": " / ".join(
            [
                item
                for item in [
                    source,
                    stringify_value(record.get("eventType")),
                    event_level,
                    stringify_value(record.get("eventCode")),
                ]
                if item
            ]
        ),
        "evidence": " | ".join(
            [
                item
                for item in [
                    f"process={process_name}" if process_name else "",
                    f"user={username}" if username else "",
                    f"target={target_path}" if target_path else "",
                    f"remoteIp={remote_ip}" if remote_ip else "",
                ]
                if item
            ]
        ),
        "summary": summarize_record(record, max_fields=8),
        "raw": compact_json(record, 300),
        "timestamp": format_timestamp(record.get("timestamp")),
        "source": source,
        "event_type": stringify_value(record.get("eventType")),
        "event_level": event_level,
        "event_code": stringify_value(record.get("eventCode")),
        "event_action": stringify_value(record.get("eventAction")),
        "result": result,
        "process_name": process_name,
        "username": username,
        "target_path": target_path,
        "remote_ip": remote_ip,
        "message": message,
        "attention": attention,
        "_attrs": {
            "event-level": event_level_raw.lower(),
            "event-level-label": event_level.lower(),
            "source": source.lower(),
            "result": result_raw.lower(),
            "result-label": result.lower(),
            "attention": "yes" if attention else "no",
        },
    }


def build_generic_collection_row(record: dict[str, Any], source_path: str, collection_name: str) -> dict[str, Any]:
    title = infer_record_title(record)
    severity = infer_record_severity(record)
    attention = severity in {"critical", "high", "medium"}
    return {
        "severity": severity if severity != "unknown" else "info",
        "severity_label": SEVERITY_LABELS[severity if severity != "unknown" else "info"],
        "title": title,
        "source_path": source_path,
        "collection": collection_name,
        "status": stringify_value(record.get("status") or record.get("result")),
        "status_label": stringify_value(record.get("status") or record.get("result")),
        "category": stringify_value(record.get("category") or record.get("type")),
        "evidence_source": "collection-row",
        "evidence_source_label": "采集记录",
        "evidence_source_detail": stringify_value(record.get("type") or record.get("category")),
        "evidence": infer_record_evidence(record),
        "summary": summarize_record(record, max_fields=8),
        "raw": compact_json(record, 300),
        "attention": attention,
        "_attrs": {"attention": "yes" if attention else "no"},
    }


def build_risk_finding_row(record: dict[str, Any], source_path: str, collection_name: str) -> dict[str, Any]:
    severity = infer_record_severity(record)
    status = stringify_value(record.get("status") or record.get("result"))
    evidence_source, evidence_source_label, evidence_source_detail = infer_record_evidence_source(record)
    category = infer_record_category(record, evidence_source_label)
    return {
        "severity": severity,
        "severity_label": SEVERITY_LABELS[severity],
        "source_path": source_path,
        "collection": collection_name,
        "title": infer_record_title(record),
        "category": category,
        "status": status,
        "status_label": status,
        "evidence_source": evidence_source,
        "evidence_source_label": evidence_source_label,
        "evidence_source_detail": evidence_source_detail,
        "evidence": infer_record_evidence(record),
        "summary": summarize_record(record, max_fields=7),
        "raw": compact_json(record, 300),
        "_attrs": {"severity": severity, "source": evidence_source},
    }


def summarize_baseline_counts(rows: list[dict[str, Any]], payload_summary: dict[str, Any] | None) -> dict[str, int | float]:
    if payload_summary:
        total = int(payload_summary.get("total") or len(rows))
        passed = int(payload_summary.get("pass") or 0)
        failed = int(payload_summary.get("fail") or 0)
        unknown = int(payload_summary.get("unknown") or 0)
        informational = int(payload_summary.get("informational") or 0)
        pending = int(payload_summary.get("pending") or 0)
    else:
        total = len(rows)
        passed = len([row for row in rows if row.get("bucket") == "pass"])
        failed = len([row for row in rows if row.get("bucket") == "fail"])
        unknown = len([row for row in rows if row.get("bucket") == "unknown"])
        informational = len([row for row in rows if row.get("bucket") == "informational"])
        pending = len([row for row in rows if row.get("bucket") == "pending"])

    evaluated = max(total - pending, 0)
    compliance_rate = round((passed / evaluated) * 100, 1) if evaluated else 0.0
    return {
        "total": total,
        "pass": passed,
        "fail": failed,
        "unknown": unknown,
        "informational": informational,
        "pending": pending,
        "evaluated": evaluated,
        "compliance_rate": compliance_rate,
    }


def build_output_digest(output_path: str, workspace: Path, workflow: str | None = None) -> dict[str, Any]:
    source_path = Path(output_path).expanduser().resolve()
    rel_path = relative_path(str(source_path), workspace) or source_path.name
    resolved_workflow = workflow or derive_workflow_from_output_path(output_path)
    profile = workflow_profile(resolved_workflow)
    digest: dict[str, Any] = {
        "path": rel_path,
        "href": workspace_href(rel_path),
        "file_name": source_path.name,
        "format": source_path.suffix.lower().lstrip(".") or "unknown",
        "exists": source_path.exists(),
        "load_error": None,
        "workflow": resolved_workflow,
        "profile": profile,
        "record_count": 0,
        "flagged_count": 0,
        "severity_counts": severity_counts_template(),
        "table_rows": [],
        "table_columns": [],
        "highlight_rows": [],
        "chart_title": "",
        "chart_items": [],
        "top_level_summary": "",
    }

    if not source_path.exists():
        digest["load_error"] = "输出文件不存在"
        return digest

    if source_path.suffix.lower() != ".json":
        digest["top_level_summary"] = "非 JSON 输出，仅保留文件入口。"
        return digest

    payload, error = safe_read_json(source_path)
    if error:
        digest["load_error"] = error
        return digest

    if isinstance(payload, dict):
        top_keys = [key for key in payload.keys()][:8]
        if top_keys:
            digest["top_level_summary"] = "顶层字段: " + ", ".join(top_keys)
    elif isinstance(payload, list):
        digest["top_level_summary"] = f"顶层数组，元素数: {len(payload)}"

    if profile == "baseline":
        raw_rows = []
        if isinstance(payload, dict):
            raw_rows = payload.get("rows") or payload.get("items") or []
        elif isinstance(payload, list):
            raw_rows = payload
        rows = [build_baseline_row(item, rel_path, "baseline.rows") for item in coerce_records(raw_rows)]
        counts = summarize_baseline_counts(rows, ensure_dict(payload).get("summary") if isinstance(payload, dict) else None)
        severity_counts = severity_counts_template()
        for row in rows:
            add_severity_count(severity_counts, row["severity"])
        digest.update(
            {
                "record_count": len(rows),
                "flagged_count": counts["fail"],
                "severity_counts": severity_counts,
                "status_counts": counts,
                "table_columns": [
                    {"key": "check_id", "label": "检查项编号"},
                    {"key": "check_name", "label": "检查项名称"},
                    {"key": "category", "label": "分类"},
                    {"key": "status_label", "label": "判定结果"},
                    {"key": "risk_level", "label": "风险等级"},
                    {"key": "expected", "label": "基线要求"},
                    {"key": "actual", "label": "实际结果"},
                    {"key": "recommendation", "label": "整改建议"},
                ],
                "table_rows": rows,
                "highlight_rows": [row for row in rows if row.get("bucket") == "fail"],
                "chart_title": "基线结果分布",
                "chart_items": [
                    {"name": "不符合", "count": int(counts["fail"]), "color": "#b42318"},
                    {"name": "符合", "count": int(counts["pass"]), "color": "#027a48"},
                    {"name": "待确认", "count": int(counts["unknown"]), "color": "#b54708"},
                    {"name": "信息项", "count": int(counts["informational"]), "color": "#155eef"},
                    {"name": "待执行", "count": int(counts["pending"]), "color": "#667085"},
                ],
            }
        )
        return digest

    if profile == "collection":
        raw_rows = []
        if isinstance(payload, dict):
            raw_rows = payload.get("rows") or payload.get("items") or payload.get("results") or []
        elif isinstance(payload, list):
            raw_rows = payload

        builder = build_generic_collection_row
        chart_counts: dict[str, int] = {}
        if resolved_workflow == "network-inventory":
            builder = build_network_row
        elif resolved_workflow == "eventlog-timeline":
            builder = build_eventlog_row

        rows = [builder(item, rel_path, "collection.rows") for item in coerce_records(raw_rows)]
        attention_rows = [row for row in rows if row.get("attention")]
        severity_counts = severity_counts_template()
        for row in rows:
            add_severity_count(severity_counts, row["severity"])

        if resolved_workflow == "network-inventory":
            for row in rows:
                increment_named_count(chart_counts, stringify_value(row.get("asset_status")) or "未知")
            digest["table_columns"] = [
                {"key": "ip_address", "label": "IP"},
                {"key": "hostname", "label": "主机名"},
                {"key": "asset_status", "label": "资产状态"},
                {"key": "os_family", "label": "系统"},
                {"key": "device_type", "label": "设备类型"},
                {"key": "open_ports", "label": "开放端口"},
                {"key": "sources", "label": "发现来源"},
                {"key": "scan_modes", "label": "探测方式"},
                {"key": "confidence", "label": "置信度"},
                {"key": "last_seen", "label": "最近发现时间"},
            ]
            digest["chart_title"] = "资产状态分布"
        elif resolved_workflow == "eventlog-timeline":
            for row in rows:
                increment_named_count(chart_counts, stringify_value(row.get("event_level")) or "未标注")
            digest["table_columns"] = [
                {"key": "timestamp", "label": "时间"},
                {"key": "source", "label": "来源"},
                {"key": "event_type", "label": "事件类型"},
                {"key": "event_level", "label": "事件级别"},
                {"key": "event_code", "label": "事件编号"},
                {"key": "event_action", "label": "动作"},
                {"key": "result", "label": "结果"},
                {"key": "process_name", "label": "进程"},
                {"key": "username", "label": "用户"},
                {"key": "target_path", "label": "目标路径"},
                {"key": "remote_ip", "label": "远端 IP"},
                {"key": "message", "label": "消息"},
            ]
            digest["chart_title"] = "事件级别分布"
        else:
            for row in rows:
                increment_named_count(chart_counts, stringify_value(row.get("category")) or "未分类")
            digest["table_columns"] = [
                {"key": "title", "label": "标题"},
                {"key": "status_label", "label": "状态"},
                {"key": "category", "label": "分类"},
                {"key": "evidence", "label": "关键内容"},
                {"key": "summary", "label": "摘要"},
            ]
            digest["chart_title"] = "记录分类分布"

        digest.update(
            {
                "record_count": len(rows),
                "flagged_count": len(attention_rows),
                "severity_counts": severity_counts,
                "table_rows": rows,
                "highlight_rows": attention_rows,
                "chart_items": named_count_items(chart_counts),
            }
        )
        return digest

    collections = collect_nested_collections(payload)
    if not collections:
        if isinstance(payload, list):
            collections = [("root", payload)]
        elif isinstance(payload, dict):
            collections = [("root", [payload])]

    all_rows: list[dict[str, Any]] = []
    for collection_name, raw_items in collections:
        rows = [build_risk_finding_row(item, rel_path, collection_name) for item in coerce_records(raw_items)]
        all_rows.extend(rows)

    severity_counts = severity_counts_template()
    for row in all_rows:
        add_severity_count(severity_counts, row["severity"])

    digest.update(
        {
            "record_count": len(all_rows),
            "flagged_count": len([row for row in all_rows if row["severity"] in {"critical", "high", "medium"}]),
            "severity_counts": severity_counts,
            "table_columns": [
                {"key": "severity_label", "label": "级别"},
                {"key": "title", "label": "标题"},
                {"key": "evidence_source_label", "label": "结论来源"},
                {"key": "evidence_source_detail", "label": "来源证据"},
                {"key": "evidence", "label": "关键证据"},
            ],
            "table_rows": all_rows,
            "highlight_rows": select_sample_rows(all_rows, limit=20),
            "chart_title": "风险级别分布",
            "chart_items": severity_bar_items(severity_counts),
        }
    )
    return digest


def collect_output_digests(workspace: Path, output_paths: list[str], workflow: str | None = None) -> list[dict[str, Any]]:
    digests: list[dict[str, Any]] = []
    for item in output_paths:
        if not item:
            continue
        digests.append(build_output_digest(item, workspace, workflow))
    return digests


def flatten_output_findings(output_digests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for digest in output_digests:
        rows.extend(digest.get("highlight_rows", []))
    return select_sample_rows(rows, limit=30)


def aggregate_severity_counts(output_digests: list[dict[str, Any]]) -> dict[str, int]:
    counts = severity_counts_template()
    for digest in output_digests:
        merge_severity_counts(counts, ensure_dict(digest.get("severity_counts")))
    return counts


def build_workflow_commands(manifest: dict[str, Any], workspace: Path) -> tuple[list[dict[str, Any]], list[str]]:
    commands: list[dict[str, Any]] = []
    evidence_paths: list[str] = []
    for command in manifest.get("commands", []):
        output_path = relative_path(command.get("output_path"), workspace)
        stdout_path = relative_path(command.get("stdout_path"), workspace)
        stderr_path = relative_path(command.get("stderr_path"), workspace)
        if stdout_path:
            evidence_paths.append(stdout_path)
        if stderr_path:
            evidence_paths.append(stderr_path)
        commands.append(
            {
                "index": command.get("index"),
                "name": command.get("name"),
                "status": command.get("status"),
                "status_label": status_label(str(command.get("status"))),
                "exit_code": command.get("exit_code"),
                "output_path": output_path,
                "output_href": workspace_href(output_path),
                "stdout_path": stdout_path,
                "stdout_href": workspace_href(stdout_path),
                "stderr_path": stderr_path,
                "stderr_href": workspace_href(stderr_path),
            }
        )
    return commands, evidence_paths


def build_output_cards(output_digests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    for digest in output_digests:
        profile = digest.get("profile")
        count_label = {
            "risk": "风险项",
            "baseline": "不符合项",
            "collection": "关注记录",
        }.get(profile, "记录")
        cards.append(
            {
                "path": digest.get("path"),
                "href": digest.get("href"),
                "record_count": digest.get("record_count"),
                "flagged_count": digest.get("flagged_count"),
                "flagged_label": count_label,
                "note": digest.get("top_level_summary") or digest.get("load_error") or "",
            }
        )
    return cards


def build_workflow_report(workspace: Path, manifest: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    status = str(summary.get("status") or manifest.get("status") or "unknown")
    workflow = str(summary.get("workflow") or manifest.get("workflow") or "unknown")
    profile = workflow_profile(workflow)
    outputs_abs = [item for item in summary.get("outputs", []) if item]
    outputs = [relative_path(item, workspace) for item in outputs_abs if item]
    output_digests = collect_output_digests(workspace, outputs_abs, workflow)
    commands, command_evidence = build_workflow_commands(manifest, workspace)
    artifact_index = build_artifact_index(
        summary_json="summary.json",
        manifest_json="manifest.json",
        output_paths=[item for item in outputs if item],
        extra_paths=[relative_path(item, workspace) for item in summary.get("runtime_state_files", []) if item],
    )
    warnings = list((summary.get("preflight") or {}).get("warnings", []))
    errors = list((summary.get("preflight") or {}).get("errors", []))

    metrics: list[dict[str, Any]] = []
    chart_summary: dict[str, Any] = {}
    findings_items: list[dict[str, Any]] = []
    presentation: dict[str, Any] = {"mode": profile, "output_cards": build_output_cards(output_digests)}

    if profile == "baseline":
        all_rows: list[dict[str, Any]] = []
        total_counts = {"total": 0, "pass": 0, "fail": 0, "unknown": 0, "informational": 0, "pending": 0, "evaluated": 0, "compliance_rate": 0.0}
        severity_counts = severity_counts_template()
        for digest in output_digests:
            all_rows.extend(digest.get("table_rows", []))
            counts = ensure_dict(digest.get("status_counts"))
            for key in ("total", "pass", "fail", "unknown", "informational", "pending", "evaluated"):
                total_counts[key] += int(counts.get(key, 0))
            merge_severity_counts(severity_counts, ensure_dict(digest.get("severity_counts")))
        total_counts["compliance_rate"] = round((total_counts["pass"] / total_counts["evaluated"]) * 100, 1) if total_counts["evaluated"] else 0.0
        fail_rows = [row for row in all_rows if row.get("bucket") == "fail"]
        findings_items = fail_rows[:50]
        overall_severity = choose_overall_severity(severity_counts, status) if fail_rows else "info"
        metrics = [
            build_metric("执行状态", status_label(status), tone="info"),
            build_metric("检查项总数", total_counts["total"], tone="info"),
            build_metric("不符合项", total_counts["fail"], tone="high"),
            build_metric("符合项", total_counts["pass"], tone="info"),
            build_metric("符合率", f"{total_counts['compliance_rate']}%", tone="info"),
            build_metric("待确认/信息项", total_counts["unknown"] + total_counts["informational"] + total_counts["pending"], tone="medium"),
            build_metric("输出文件", len(output_digests), tone="info"),
        ]
        chart_summary = {
            "type": "named",
            "title": "基线结果分布",
            "items": [
                {"name": "不符合", "count": total_counts["fail"], "color": "#b42318"},
                {"name": "符合", "count": total_counts["pass"], "color": "#027a48"},
                {"name": "待确认", "count": total_counts["unknown"], "color": "#b54708"},
                {"name": "信息项", "count": total_counts["informational"], "color": "#155eef"},
                {"name": "待执行", "count": total_counts["pending"], "color": "#667085"},
            ],
        }
        presentation.update(
            {
                "primary_section": build_generic_table_section(
                    "未符合基线要求的检查项",
                    output_digests[0].get("table_columns", []) if output_digests else [],
                    fail_rows,
                    "未发现不符合基线要求的检查项。",
                    filters=[
                        make_filter_definition("分类", "category", make_status_filter_options(all_rows, "category")),
                        make_filter_definition("风险等级", "risk-level", make_status_filter_options(all_rows, "risk_level")),
                    ],
                ),
                "secondary_section": build_generic_table_section(
                    "完整基线结果",
                    output_digests[0].get("table_columns", []) if output_digests else [],
                    all_rows,
                    "没有可展示的基线结果。",
                    filters=[
                        make_filter_definition("判定结果", "bucket", ["fail", "pass", "unknown", "informational", "pending"]),
                        make_filter_definition("分类", "category", make_status_filter_options(all_rows, "category")),
                    ],
                ),
            }
        )
        conclusion = (
            f"本次{workflow_display_name(workflow)}已完成，共发现 {total_counts['fail']} 项不符合要求。"
            if status == "ok" and total_counts["fail"] > 0
            else f"本次{workflow_display_name(workflow)}已完成，当前未发现不符合项。"
            if status == "ok"
            else f"{workflow_display_name(workflow)}未成功完成。"
        )
        next_action = (
            "优先处理“不符合项”表中的整改建议，再结合原始导出的 Excel 或 JSON 逐项复核。"
            if total_counts["fail"] > 0
            else "可将完整基线结果作为当前主机的合规快照留档。"
        )
    elif profile == "collection":
        all_rows: list[dict[str, Any]] = []
        attention_rows: list[dict[str, Any]] = []
        for digest in output_digests:
            all_rows.extend(digest.get("table_rows", []))
            attention_rows.extend(digest.get("highlight_rows", []))
        output_columns = output_digests[0].get("table_columns", []) if output_digests else []

        if workflow == "network-inventory":
            managed = len([row for row in all_rows if stringify_value(row.get("_attrs", {}).get("asset-status")) == "managed"])
            unmanaged = len([row for row in all_rows if stringify_value(row.get("_attrs", {}).get("asset-status")) == "unmanaged"])
            chart_items = output_digests[0].get("chart_items", []) if output_digests else []
            metrics = [
                build_metric("执行状态", status_label(status), tone="info"),
                build_metric("资产总数", len(all_rows), tone="info"),
                build_metric("受管资产", managed, tone="info"),
                build_metric("未纳管资产", unmanaged, tone="medium"),
                build_metric("需关注记录", len(attention_rows), tone="medium"),
                build_metric("输出文件", len(output_digests), tone="info"),
            ]
            chart_summary = {"type": "named", "title": "资产状态分布", "items": chart_items}
            filters = [
                make_filter_definition("资产状态", "asset-status-label", make_status_filter_options(all_rows, "asset_status")),
                make_filter_definition("系统", "os-family", make_status_filter_options(all_rows, "os_family")),
            ]
            conclusion = f"{workflow_display_name(workflow)}已完成，共收集 {len(all_rows)} 条资产记录。"
            next_action = "优先按资产状态、IP、系统类型筛选结果，再决定是否继续做更深入的主机或文件排查。"
        elif workflow == "eventlog-timeline":
            chart_items = output_digests[0].get("chart_items", []) if output_digests else []
            metrics = [
                build_metric("执行状态", status_label(status), tone="info"),
                build_metric("日志总数", len(all_rows), tone="info"),
                build_metric("需关注记录", len(attention_rows), tone="medium"),
                build_metric("数据源", len(set(stringify_value(row.get("source")) for row in all_rows if stringify_value(row.get("source")))), tone="info"),
                build_metric("输出文件", len(output_digests), tone="info"),
            ]
            chart_summary = {"type": "named", "title": "事件级别分布", "items": chart_items}
            filters = [
                make_filter_definition("事件级别", "event-level-label", make_status_filter_options(all_rows, "event_level")),
                make_filter_definition("来源", "source", make_status_filter_options(all_rows, "source")),
                make_filter_definition("结果", "result-label", make_status_filter_options(all_rows, "result")),
            ]
            conclusion = f"{workflow_display_name(workflow)}已完成，共收集 {len(all_rows)} 条日志记录。"
            next_action = "先按时间、事件级别、来源和结果筛选，再围绕具体进程、用户或远端 IP 做人工判断。"
        else:
            chart_summary = {"type": "named", "title": "记录分布", "items": output_digests[0].get("chart_items", []) if output_digests else []}
            metrics = [
                build_metric("执行状态", status_label(status), tone="info"),
                build_metric("记录总数", len(all_rows), tone="info"),
                build_metric("需关注记录", len(attention_rows), tone="medium"),
                build_metric("输出文件", len(output_digests), tone="info"),
            ]
            filters = []
            conclusion = f"{workflow_display_name(workflow)}已完成，共收集 {len(all_rows)} 条记录。"
            next_action = "先筛选目标组件或分类，再决定是否进入后续调查链。"

        findings_items = attention_rows[:50]
        overall_severity = "info" if status in {"ok", "completed", "dry-run"} else "medium" if status == "blocked" else "high"
        presentation.update(
            {
                "primary_section": build_generic_table_section(
                    "需关注记录",
                    output_columns,
                    attention_rows,
                    "当前没有额外标记为需关注的记录。",
                    filters=filters,
                ),
                "secondary_section": build_generic_table_section(
                    "采集结果明细",
                    output_columns,
                    all_rows,
                    "没有可展示的数据采集结果。",
                    filters=filters,
                ),
            }
        )
    else:
        severity_counts = aggregate_severity_counts(output_digests)
        findings_items = flatten_output_findings(output_digests)
        overall_severity = choose_overall_severity(severity_counts, status)
        top_source = ""
        source_counts: dict[str, int] = {}
        for row in findings_items:
            increment_named_count(source_counts, stringify_value(row.get("evidence_source_label")))
        if source_counts:
            top_source = sorted(source_counts.items(), key=lambda item: (-item[1], item[0]))[0][0]

        metrics = [
            build_metric("执行状态", status_label(status), tone="info"),
            build_metric("严重/高危", severity_counts.get("critical", 0) + severity_counts.get("high", 0), tone="high"),
            build_metric("中危", severity_counts.get("medium", 0), tone="medium"),
            build_metric("低危/信息", severity_counts.get("low", 0) + severity_counts.get("info", 0), tone="info"),
            build_metric("重点风险项", len([row for row in findings_items if row["severity"] in {"critical", "high", "medium"}]), tone="high"),
            build_metric("主要结论来源", top_source or "无", tone="info"),
            build_metric("输出文件", len(output_digests), tone="info"),
        ]
        chart_summary = {"type": "severity", "title": "风险级别分布", "counts": severity_counts}
        presentation.update(
            {
                "primary_section": build_generic_table_section(
                    "重点风险信息",
                    [
                        {"key": "severity_label", "label": "级别"},
                        {"key": "title", "label": "标题"},
                        {"key": "evidence_source_label", "label": "结论来源"},
                        {"key": "evidence_source_detail", "label": "来源证据"},
                        {"key": "evidence", "label": "关键证据"},
                    ],
                    findings_items,
                    "未发现重点风险项。",
                    filters=[
                        make_filter_definition("级别", "severity", ["critical", "high", "medium", "low", "info", "unknown"]),
                        make_filter_definition("结论来源", "source", make_status_filter_options(findings_items, "evidence_source")),
                    ],
                ),
            }
        )
        if status == "ok":
            conclusion = f"{workflow_display_name(workflow)}已完成，可直接查看本报告中的风险摘要和证据入口。"
            next_action = "先看重点风险信息，再按证据入口下钻到原始结果文件。"
        elif status == "dry-run":
            conclusion = f"{workflow_display_name(workflow)}仅完成预演，尚未执行正式扫描。"
            next_action = "确认参数无误后，去掉 --dry-run 再执行正式扫描。"
        elif status == "blocked":
            conclusion = f"{workflow_display_name(workflow)}当前被阻塞，未完成正式扫描。"
            next_action = "优先处理权限、参数或 runtime 问题后重试。"
        else:
            conclusion = f"{workflow_display_name(workflow)}执行失败。"
            next_action = "优先检查 stderr、manifest.json 和原始输出文件。"

    if profile != "risk":
        overall_severity = locals().get("overall_severity", "info")
    else:
        overall_severity = locals().get("overall_severity", "info")

    return {
        "report_version": "3.0",
        "report_kind": "single-workflow",
        "workflow_profile": profile,
        "title": f"C-Eyes {workflow_display_name(workflow)}报告",
        "generated_at": utc_now(),
        "status": status,
        "status_label": status_label(status),
        "severity": overall_severity,
        "severity_label": SEVERITY_LABELS[overall_severity],
        "workspace": str(workspace),
        "workspace_relative_report_dir": "report_result",
        "overview": {
            "workflow": workflow,
            "workflow_label": workflow_display_name(workflow),
            "message": summary.get("message"),
            "requested_at": manifest.get("requested_at"),
            "dry_run": bool(manifest.get("dry_run")),
            "download_only": bool(manifest.get("download_only")),
        },
        "metrics": metrics,
        "chart_summary": chart_summary,
        "runtime": {
            "platform": manifest.get("runtime_target", {}).get("platform"),
            "arch": manifest.get("runtime_target", {}).get("arch"),
            "bundle_dir": manifest.get("runtime_target", {}).get("bundle_dir"),
            "binary": manifest.get("runtime_target", {}).get("binary"),
            "dist_root": manifest.get("runtime_target", {}).get("dist_root"),
            "staged_binary": relative_path(manifest.get("runtime_target", {}).get("staged_binary"), workspace),
        },
        "artifacts": {
            "summary_json": "summary.json",
            "manifest_json": "manifest.json",
            "outputs": outputs,
            "runtime_state_files": [relative_path(item, workspace) for item in summary.get("runtime_state_files", []) if item],
        },
        "artifact_index": artifact_index,
        "commands": commands,
        "output_digests": output_digests,
        "findings": {
            "status": "findings-present" if findings_items else "no-material-findings",
            "items": findings_items,
        },
        "preflight": {
            "status": (summary.get("preflight") or {}).get("status"),
            "warnings": warnings,
            "errors": errors,
        },
        "technical_details": {
            "commands": commands,
            "command_evidence": command_evidence,
        },
        "presentation": presentation,
        "conclusion": conclusion,
        "next_action": next_action,
    }


def build_investigation_report(
    workspace: Path,
    decision: dict[str, Any],
    findings: dict[str, Any],
    next_actions: dict[str, Any],
) -> dict[str, Any]:
    executed_steps = []
    step_artifacts: list[str] = []
    step_output_digests: list[dict[str, Any]] = []
    for step in decision.get("executed_steps", []):
        summary_path = relative_path(step.get("summary_path"), workspace)
        manifest_path = relative_path(step.get("manifest_path"), workspace)
        outputs = [relative_path(item, workspace) for item in step.get("outputs", []) if item]
        step_artifacts.extend([item for item in [summary_path, manifest_path, *outputs] if item])
        raw_output_digests = collect_output_digests(workspace, [item for item in step.get("outputs", []) if item], step.get("workflow"))
        step_output_digests.extend(raw_output_digests)
        executed_steps.append(
            {
                "index": step.get("index"),
                "workflow": step.get("workflow"),
                "workflow_label": workflow_display_name(str(step.get("workflow") or "")),
                "status": step.get("status"),
                "status_label": status_label(str(step.get("status"))),
                "workspace": relative_path(step.get("workspace"), workspace),
                "summary_path": summary_path,
                "summary_href": workspace_href(summary_path),
                "manifest_path": manifest_path,
                "manifest_href": workspace_href(manifest_path),
                "outputs": outputs,
                "output_hrefs": [workspace_href(item) for item in outputs if item],
                "output_digests": raw_output_digests,
            }
        )

    rendered_findings = []
    severity_counts = severity_counts_template()
    for item in findings.get("findings", []):
        severity = normalize_severity(item.get("severity"))
        add_severity_count(severity_counts, severity)
        evidence_paths = [relative_path(path, workspace) for path in item.get("evidence_paths", []) if path]
        source_label = "人工聚合"
        if evidence_paths:
            first_path = evidence_paths[0].lower()
            if "yara" in first_path:
                source_label = "YARA 规则"
            elif "cloud" in first_path:
                source_label = "云平台分析"
        rendered_findings.append(
            {
                "severity": severity,
                "severity_label": SEVERITY_LABELS[severity],
                "workflow": item.get("workflow"),
                "workflow_label": workflow_display_name(stringify_value(item.get("workflow"))),
                "type": item.get("type"),
                "title": stringify_value(item.get("message")) or stringify_value(item.get("type")) or "调查发现",
                "category": stringify_value(item.get("type")) or stringify_value(item.get("workflow")) or "调查发现",
                "message": item.get("message"),
                "evidence_paths": evidence_paths,
                "evidence_source_label": source_label,
                "evidence_source_detail": "调查链聚合结果",
                "evidence": " | ".join(evidence_paths[:3]),
                "_attrs": {"severity": severity, "workflow": stringify_value(item.get("workflow")).lower()},
            }
        )

    status = str(decision.get("status") or "unknown")
    overall_severity = choose_overall_severity(severity_counts, status)
    chart_summary = {"type": "severity", "title": "发现级别分布", "counts": severity_counts}
    if status == "completed":
        conclusion = "自动调查链已完成，可直接查看调查结论、关键发现和后续建议。"
    elif status == "dry-run":
        conclusion = "自动调查链仅完成预演，尚未执行正式调查步骤。"
    elif status == "blocked":
        conclusion = "自动调查链已阻塞，请先处理缺失参数、权限或 runtime 问题。"
    else:
        conclusion = "自动调查链执行失败，请结合步骤证据和日志继续排查。"

    artifact_index = [
        {"label": "decision.json", "path": "decision.json", "href": "../decision.json"},
        {"label": "findings.json", "path": "findings.json", "href": "../findings.json"},
        {"label": "next_actions.json", "path": "next_actions.json", "href": "../next_actions.json"},
    ]
    artifact_index.extend(build_artifact_index(None, None, [], extra_paths=step_artifacts))

    presentation = {
        "mode": "investigation",
        "output_cards": build_output_cards(step_output_digests),
        "primary_section": build_generic_table_section(
            "关键调查发现",
            [
                {"key": "severity_label", "label": "级别"},
                {"key": "workflow_label", "label": "来源流程"},
                {"key": "evidence_source_label", "label": "结论来源"},
                {"key": "message", "label": "结论"},
                {"key": "evidence", "label": "证据路径"},
            ],
            rendered_findings,
            "当前没有关键调查发现。",
            filters=[
                make_filter_definition("级别", "severity", ["critical", "high", "medium", "low", "info", "unknown"]),
                make_filter_definition("来源流程", "workflow", make_status_filter_options(rendered_findings, "workflow")),
            ],
        ),
        "secondary_section": build_generic_table_section(
            "执行步骤",
            [
                {"key": "index", "label": "#"},
                {"key": "workflow_label", "label": "流程"},
                {"key": "status_label", "label": "状态"},
                {"key": "summary_path", "label": "summary"},
                {"key": "manifest_path", "label": "manifest"},
            ],
            executed_steps,
            "没有执行步骤记录。",
        ),
    }

    return {
        "report_version": "3.0",
        "report_kind": "investigation",
        "workflow_profile": "investigation",
        "title": f"C-Eyes 自动调查报告 - {decision.get('goal', 'unknown')}",
        "generated_at": utc_now(),
        "status": status,
        "status_label": status_label(status),
        "severity": overall_severity,
        "severity_label": SEVERITY_LABELS[overall_severity],
        "workspace": str(workspace),
        "workspace_relative_report_dir": "report_result",
        "overview": {
            "goal": decision.get("goal"),
            "goal_description": decision.get("goal_description"),
            "selected_chain": decision.get("selected_chain", []),
            "stop_reason": decision.get("stop_reason"),
            "requested_at": decision.get("requested_at"),
        },
        "metrics": [
            build_metric("调查状态", status_label(status), tone="info"),
            build_metric("关键发现", len(rendered_findings), tone="high"),
            build_metric("严重/高危", severity_counts.get("critical", 0) + severity_counts.get("high", 0), tone="high"),
            build_metric("中危", severity_counts.get("medium", 0), tone="medium"),
            build_metric("执行步骤", len(executed_steps), tone="info"),
            build_metric("阻塞步骤", len([step for step in executed_steps if step.get("status") == "blocked"]), tone="medium"),
        ],
        "chart_summary": chart_summary,
        "artifact_index": artifact_index,
        "executed_steps": executed_steps,
        "step_output_digests": step_output_digests,
        "findings": {
            "status": findings.get("status"),
            "status_label": status_label(str(findings.get("status"))),
            "items": rendered_findings,
        },
        "next_actions": {
            "status": next_actions.get("status"),
            "status_label": status_label(str(next_actions.get("status"))),
            "recommended_action": next_actions.get("recommended_action"),
            "reason": next_actions.get("reason"),
        },
        "technical_details": {"steps": executed_steps},
        "presentation": presentation,
        "conclusion": conclusion,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# {report['title']}",
        "",
        f"- 状态：{report['status_label']}",
        f"- 整体级别：{report['severity_label']}",
        f"- 工作目录：`{report['workspace']}`",
        f"- 最终报告目录：`report_result/`",
        f"- 生成时间：`{report['generated_at']}`",
        f"- Excel 报告：`report_result/report.xlsx`",
        "",
        "## 结论",
        "",
        stringify_value(report.get("conclusion")),
        "",
        "## 关键指标",
        "",
    ]
    for metric in report.get("metrics", []):
        lines.append(f"- {metric['label']}: `{metric['value']}`")

    lines.extend(["", "## 证据入口", ""])
    for item in report.get("artifact_index", []):
        lines.append(f"- {item['label']}: `{item['path']}`")

    presentation = ensure_dict(report.get("presentation"))
    primary = ensure_dict(presentation.get("primary_section"))
    if primary:
        lines.extend(["", f"## {primary.get('title')}", ""])
        rows = primary.get("rows", [])
        if rows:
            for row in rows[:10]:
                title = stringify_value(row.get("title") or row.get("check_name") or row.get("ip_address") or row.get("timestamp"))
                desc = stringify_value(row.get("evidence") or row.get("actual") or row.get("message"))
                lines.append(f"- {title}")
                if desc:
                    lines.append(f"  - {desc}")
        else:
            lines.append(f"- {primary.get('empty_message')}")

    if report.get("report_kind") == "single-workflow":
        lines.extend(["", "## 下一步建议", "", stringify_value(report.get("next_action")), ""])
    else:
        lines.extend(
            [
                "",
                "## 下一步建议",
                "",
                f"- 状态：`{report.get('next_actions', {}).get('status')}`",
                f"- 建议动作：`{report.get('next_actions', {}).get('recommended_action')}`",
                f"- 原因：{report.get('next_actions', {}).get('reason')}",
                "",
            ]
        )
    return "\n".join(lines)


def render_severity_bar_chart(counts: dict[str, int]) -> str:
    labels = [
        ("critical", "严重"),
        ("high", "高危"),
        ("medium", "中危"),
        ("low", "低危"),
        ("info", "信息"),
        ("unknown", "未知"),
    ]
    max_value = max([int(counts.get(key, 0)) for key, _ in labels] + [1])
    columns = []
    for key, label in labels:
        value = int(counts.get(key, 0))
        height = max(8, round((value / max_value) * 180)) if value > 0 else 8
        columns.append(
            "<div class='bar-col'>"
            f"<div class='bar-count'>{value}</div>"
            "<div class='bar-track'>"
            f"<div class='bar-fill' style='height:{height}px; background:{SEVERITY_COLORS[key]};'></div>"
            "</div>"
            f"<div class='bar-label'>{label}</div>"
            "</div>"
        )
    return "<div class='bar-chart'>" + "".join(columns) + "</div>"


def render_named_bar_chart(items: list[dict[str, Any]]) -> str:
    if not items:
        return "<div class='empty'>暂无统计数据</div>"
    max_value = max([int(item.get("count", 0)) for item in items] + [1])
    rows: list[str] = []
    for item in items:
        value = int(item.get("count", 0))
        width = round((value / max_value) * 100, 1) if max_value else 0
        rows.append(
            "<div class='risk-row'>"
            f"<div class='risk-row-label'>{escape(str(item.get('name')))}</div>"
            f"<div class='risk-bar'><span style='width:{width}%; background:{escape(str(item.get('color') or '#1f4b82'))};'></span></div>"
            f"<div class='risk-count'>{value}</div>"
            "</div>"
        )
    return "".join(rows)


def render_chart_summary(chart_summary: dict[str, Any]) -> str:
    chart_type = stringify_value(chart_summary.get("type"))
    title = stringify_value(chart_summary.get("title")) or "统计图"
    if not chart_type:
        return ""
    if chart_type == "severity":
        body = render_severity_bar_chart(ensure_dict(chart_summary.get("counts")))
    else:
        body = render_named_bar_chart(chart_summary.get("items", []))
    return "<div class='charts-grid charts-grid-single'><section class='chart-card'><h2>" + escape(title) + "</h2>" + body + "</section></div>"


def render_artifact_links(items: list[dict[str, str]]) -> str:
    if not items:
        return "<div class='empty'>暂无证据入口</div>"
    rows = []
    for item in items:
        href = item.get("href") or "#"
        rows.append(
            "<tr>"
            f"<td>{escape(item.get('label') or '')}</td>"
            f"<td><a href='{escape(href)}'>{escape(item.get('path') or '')}</a></td>"
            "</tr>"
        )
    return "<table><thead><tr><th>类型</th><th>路径</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def render_commands_table(commands: list[dict[str, Any]]) -> str:
    if not commands:
        return "<div class='empty'>没有命令执行记录</div>"
    rows = []
    for command in commands:
        links: list[str] = []
        if command.get("output_path") and command.get("output_href"):
            links.append(f"<a href='{escape(command['output_href'])}'>output</a>")
        if command.get("stdout_path") and command.get("stdout_href"):
            links.append(f"<a href='{escape(command['stdout_href'])}'>stdout</a>")
        if command.get("stderr_path") and command.get("stderr_href"):
            links.append(f"<a href='{escape(command['stderr_href'])}'>stderr</a>")
        rows.append(
            "<tr>"
            f"<td>{escape(str(command.get('index')))}</td>"
            f"<td>{escape(str(command.get('name')))}</td>"
            f"<td>{escape(str(command.get('status_label')))}</td>"
            f"<td>{escape(str(command.get('exit_code')))}</td>"
            f"<td>{' / '.join(links) or '-'}</td>"
            "</tr>"
        )
    return "<table><thead><tr><th>#</th><th>命令</th><th>状态</th><th>退出码</th><th>证据</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def render_steps_table(steps: list[dict[str, Any]]) -> str:
    if not steps:
        return "<div class='empty'>没有执行步骤</div>"
    rows = []
    for step in steps:
        evidence: list[str] = []
        if step.get("summary_path") and step.get("summary_href"):
            evidence.append(f"<a href='{escape(step['summary_href'])}'>summary</a>")
        if step.get("manifest_path") and step.get("manifest_href"):
            evidence.append(f"<a href='{escape(step['manifest_href'])}'>manifest</a>")
        rows.append(
            "<tr>"
            f"<td>{escape(str(step.get('index')))}</td>"
            f"<td>{escape(str(step.get('workflow_label') or step.get('workflow')))}</td>"
            f"<td>{escape(str(step.get('status_label')))}</td>"
            f"<td>{' / '.join(evidence) or '-'}</td>"
            "</tr>"
        )
    return "<table><thead><tr><th>#</th><th>流程</th><th>状态</th><th>证据</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"


def render_output_cards(output_cards: list[dict[str, Any]]) -> str:
    if not output_cards:
        return "<div class='empty'>没有输出文件摘要</div>"
    cards: list[str] = []
    for card in output_cards:
        href = card.get("href") or "#"
        note = stringify_value(card.get("note"))
        cards.append(
            "<section class='output-card'>"
            "<div class='output-card-header'>"
            f"<h3><a href='{escape(href)}'>{escape(stringify_value(card.get('path')))}</a></h3>"
            f"<div class='output-meta'>records={card.get('record_count')} / {escape(stringify_value(card.get('flagged_label')))}={card.get('flagged_count')}</div>"
            "</div>"
            + (f"<div class='muted'>{escape(note)}</div>" if note else "")
            + "</section>"
        )
    return "".join(cards)


def render_filter_toolbar(section_id: str, filters: list[dict[str, Any]]) -> str:
    controls = [
        f"<input class='filter-input' type='search' placeholder='输入关键词筛选...' data-filter-input data-filter-target='{escape(section_id)}'>"
    ]
    for item in filters:
        options = ["<option value=''>全部</option>"]
        for option in item.get("options", []):
            options.append(f"<option value='{escape(str(option).lower())}'>{escape(str(option))}</option>")
        controls.append(
            "<label class='filter-select-wrap'>"
            f"<span>{escape(str(item.get('label')))}</span>"
            f"<select class='filter-select' data-filter-column='{escape(str(item.get('column')))}' data-filter-target='{escape(section_id)}'>"
            + "".join(options)
            + "</select></label>"
        )
    return "<div class='filter-toolbar'>" + "".join(controls) + "</div>"


def render_section_table(section: dict[str, Any], section_id: str) -> str:
    rows = section.get("rows", [])
    if not rows:
        return "<div class='empty'>" + escape(stringify_value(section.get("empty_message"))) + "</div>"

    toolbar = render_filter_toolbar(section_id, section.get("filters", []))
    header = "".join(f"<th>{escape(column['label'])}</th>" for column in section.get("columns", []))
    body_rows: list[str] = []
    for row in rows:
        attrs = row.get("_attrs", {})
        attr_html = "".join(
            f" data-{escape(str(name))}='{escape(str(value).lower())}'"
            for name, value in attrs.items()
            if stringify_value(value)
        )
        cells = []
        for column in section.get("columns", []):
            value = row.get(column["key"])
            if column["key"] == "severity_label":
                cells.append(f"<td>{render_badge(stringify_value(value), stringify_value(row.get('severity')))}</td>")
            else:
                cells.append(f"<td>{escape(stringify_value(value))}</td>")
        body_rows.append(f"<tr{attr_html}>" + "".join(cells) + "</tr>")

    return (
        toolbar
        + "<div class='table-wrap'><table class='data-table' id='"
        + escape(section_id)
        + "'><thead><tr>"
        + header
        + "</tr></thead><tbody>"
        + "".join(body_rows)
        + "</tbody></table></div>"
    )


def render_html(report: dict[str, Any]) -> str:
    top_actions = (
        "<div class='top-actions'>"
        "<a class='action-link' href='report.json'>report.json</a>"
        "<a class='action-link' href='summary.md'>summary.md</a>"
        "<a class='action-link' href='report.xlsx'>report.xlsx</a>"
        "</div>"
    )

    overview_items = "".join(
        "<div class='overview-item'>"
        f"<div class='overview-key'>{escape(str(key))}</div>"
        f"<div class='overview-value'>{escape(stringify_value(value))}</div>"
        "</div>"
        for key, value in report.get("overview", {}).items()
    )

    preflight = ensure_dict(report.get("preflight"))
    warnings = list(preflight.get("warnings", []))
    errors = list(preflight.get("errors", []))
    preflight_html = ""
    if warnings or errors:
        rows = "".join(f"<li>warning: {escape(str(item))}</li>" for item in warnings) + "".join(
            f"<li>error: {escape(str(item))}</li>" for item in errors
        )
        preflight_html = f"<section><h2>预检信息</h2><ul>{rows}</ul></section>"

    presentation = ensure_dict(report.get("presentation"))
    primary_section = ensure_dict(presentation.get("primary_section"))
    secondary_section = ensure_dict(presentation.get("secondary_section"))

    primary_html = ""
    if primary_section:
        primary_html = "<section><h2>" + escape(stringify_value(primary_section.get("title"))) + "</h2>" + render_section_table(primary_section, "primary-table") + "</section>"

    secondary_html = ""
    if secondary_section:
        secondary_html = "<section><h2>" + escape(stringify_value(secondary_section.get("title"))) + "</h2>" + render_section_table(secondary_section, "secondary-table") + "</section>"

    appendix_html = ""
    if report.get("report_kind") == "single-workflow":
        appendix_html = (
            "<details class='appendix'><summary>技术附录</summary><div class='appendix-body'><h3>执行命令</h3>"
            + render_commands_table(report.get("commands", []))
            + "</div></details>"
        )
    else:
        appendix_html = (
            "<details class='appendix'><summary>技术附录</summary><div class='appendix-body'><h3>执行步骤</h3>"
            + render_steps_table(report.get("executed_steps", []))
            + "</div></details>"
        )

    next_action_html = ""
    if report.get("report_kind") == "single-workflow":
        next_action_html = "<section><h2>下一步建议</h2><p>" + escape(stringify_value(report.get("next_action"))) + "</p></section>"
    else:
        next_action_html = (
            "<section><h2>下一步建议</h2>"
            f"<p><strong>{escape(stringify_value(report.get('next_actions', {}).get('status_label')))}</strong></p>"
            f"<p>action: <code>{escape(stringify_value(report.get('next_actions', {}).get('recommended_action')))}</code></p>"
            f"<p>{escape(stringify_value(report.get('next_actions', {}).get('reason')))}</p>"
            "</section>"
        )

    output_cards_html = render_output_cards(presentation.get("output_cards", []))

    chart_html = render_chart_summary(report.get("chart_summary", {}))

    script = """
  <script>
    function attachTableFilters(sectionId) {
      const table = document.getElementById(sectionId);
      if (!table) return;
      const targetControls = document.querySelectorAll('[data-filter-target="' + sectionId + '"]');
      function applyFilters() {
        const search = (document.querySelector('[data-filter-input][data-filter-target="' + sectionId + '"]')?.value || '').toLowerCase().trim();
        const selects = document.querySelectorAll('select[data-filter-target="' + sectionId + '"]');
        const rows = table.querySelectorAll('tbody tr');
        rows.forEach((row) => {
          let visible = true;
          const text = row.innerText.toLowerCase();
          if (search && !text.includes(search)) {
            visible = false;
          }
          selects.forEach((select) => {
            const column = select.getAttribute('data-filter-column');
            const expected = (select.value || '').toLowerCase();
            if (!expected) return;
            const actual = (row.getAttribute('data-' + column) || '').toLowerCase();
            if (actual !== expected) {
              visible = false;
            }
          });
          row.style.display = visible ? '' : 'none';
        });
      }
      targetControls.forEach((control) => {
        control.addEventListener('input', applyFilters);
        control.addEventListener('change', applyFilters);
      });
      applyFilters();
    }
    window.addEventListener('DOMContentLoaded', () => {
      attachTableFilters('primary-table');
      attachTableFilters('secondary-table');
    });
  </script>
"""

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(report['title'])}</title>
  <style>
    :root {{
      --bg: #f5f7fb;
      --panel: #ffffff;
      --panel-alt: #f8fafc;
      --line: #d0d5dd;
      --text: #101828;
      --muted: #475467;
      --brand: #123156;
      --brand-2: #1f4b82;
      --brand-3: #5ea0ef;
      --danger: #b42318;
      --warning: #b54708;
      --success: #027a48;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
    }}
    .hero {{
      background: linear-gradient(135deg, var(--brand) 0%, var(--brand-2) 62%, #15365b 100%);
      color: #fff;
      padding: 32px 0 28px;
    }}
    .hero-inner, main {{
      max-width: 1380px;
      margin: 0 auto;
      padding: 0 24px;
    }}
    .eyebrow {{
      font-size: 12px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      opacity: 0.78;
      margin-bottom: 8px;
    }}
    h1 {{
      margin: 0;
      font-size: 30px;
      line-height: 1.2;
    }}
    .hero-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }}
    .chip, .action-link {{
      display: inline-flex;
      align-items: center;
      padding: 7px 12px;
      border-radius: 999px;
      background: rgba(255,255,255,0.14);
      color: #fff;
      font-size: 13px;
    }}
    .top-actions {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 16px;
    }}
    main {{
      padding-top: 26px;
      padding-bottom: 48px;
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 22px;
      margin-bottom: 18px;
    }}
    h2 {{
      margin: 0 0 16px;
      font-size: 18px;
    }}
    h3 {{
      margin: 0 0 10px;
      font-size: 16px;
    }}
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }}
    .charts-grid {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 18px;
      margin-bottom: 18px;
    }}
    .chart-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 22px;
    }}
    .metric-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px;
      min-height: 96px;
    }}
    .metric-label {{
      font-size: 12px;
      color: var(--muted);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 8px;
    }}
    .metric-value {{
      font-size: 28px;
      font-weight: 700;
      word-break: break-word;
    }}
    .metric-high {{ color: var(--danger); }}
    .metric-medium {{ color: var(--warning); }}
    .metric-info {{ color: var(--brand-2); }}
    .layout-2 {{
      display: grid;
      grid-template-columns: 1.15fr 0.85fr;
      gap: 18px;
      margin-bottom: 18px;
    }}
    .overview-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }}
    .overview-item {{
      background: var(--panel-alt);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px 14px;
    }}
    .overview-key {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 4px;
    }}
    .overview-value {{
      font-size: 14px;
      word-break: break-word;
    }}
    .risk-row {{
      display: grid;
      grid-template-columns: 180px 1fr 56px;
      gap: 10px;
      align-items: center;
      margin-bottom: 12px;
    }}
    .risk-row-label {{
      font-size: 14px;
      word-break: break-word;
    }}
    .risk-bar {{
      height: 10px;
      background: #e4e7ec;
      border-radius: 999px;
      overflow: hidden;
    }}
    .risk-bar span {{
      display: block;
      height: 100%;
      border-radius: 999px;
    }}
    .risk-count {{
      text-align: right;
      font-weight: 700;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      padding: 4px 10px;
      border-radius: 999px;
      background: color-mix(in srgb, var(--badge-color) 14%, white);
      color: var(--badge-color);
      font-size: 12px;
      font-weight: 700;
    }}
    .bar-chart {{
      height: 260px;
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 14px;
      align-items: end;
      padding-top: 10px;
    }}
    .bar-col {{
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 8px;
      height: 100%;
    }}
    .bar-count {{
      font-weight: 700;
      color: var(--muted);
    }}
    .bar-track {{
      display: flex;
      align-items: end;
      justify-content: center;
      height: 190px;
      width: 100%;
      background: linear-gradient(to top, #eef2f6, #f8fafc);
      border-radius: 10px;
      padding: 8px;
    }}
    .bar-fill {{
      width: min(72px, 100%);
      border-radius: 10px 10px 4px 4px;
    }}
    .bar-label {{
      font-size: 13px;
      color: var(--muted);
      text-align: center;
    }}
    .filter-toolbar {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      margin-bottom: 14px;
      align-items: end;
    }}
    .filter-input, .filter-select {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 8px 10px;
      font-size: 14px;
      background: #fff;
      min-width: 220px;
    }}
    .filter-select-wrap {{
      display: flex;
      flex-direction: column;
      gap: 6px;
      color: var(--muted);
      font-size: 12px;
    }}
    .table-wrap {{
      overflow-x: auto;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 980px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      text-align: left;
      padding: 11px 10px;
      vertical-align: top;
      font-size: 14px;
      word-break: break-word;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      background: #fcfcfd;
      position: sticky;
      top: 0;
    }}
    a {{
      color: var(--brand-2);
      text-decoration: none;
    }}
    a:hover {{
      text-decoration: underline;
    }}
    code {{
      background: #eef2f6;
      padding: 2px 6px;
      border-radius: 4px;
      word-break: break-all;
    }}
    .output-card {{
      background: var(--panel-alt);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 14px;
    }}
    .output-card-header {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: start;
      margin-bottom: 10px;
    }}
    .output-meta, .muted {{
      color: var(--muted);
      font-size: 13px;
    }}
    .empty {{
      color: var(--muted);
      padding: 8px 0;
    }}
    .appendix {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 16px 18px;
      margin-bottom: 18px;
    }}
    .appendix summary {{
      cursor: pointer;
      font-weight: 700;
    }}
    .appendix-body {{
      margin-top: 16px;
    }}
    @media (max-width: 1100px) {{
      .summary-grid {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
      .layout-2 {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 720px) {{
      .summary-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .overview-grid {{ grid-template-columns: 1fr; }}
      .hero-inner, main {{ padding-left: 16px; padding-right: 16px; }}
      h1 {{ font-size: 24px; }}
      .risk-row {{ grid-template-columns: 1fr; }}
      .filter-input, .filter-select {{ min-width: 0; width: 100%; }}
    }}
  </style>
</head>
<body>
  <header class="hero">
    <div class="hero-inner">
      <div class="eyebrow">c-eyes-automation final report</div>
      <h1>{escape(report['title'])}</h1>
      <div class="hero-meta">
        <span class="chip">状态：{escape(report['status_label'])}</span>
        <span class="chip">整体级别：{escape(report['severity_label'])}</span>
        <span class="chip">报告目录：report_result/</span>
        <span class="chip">生成时间：{escape(report['generated_at'])}</span>
      </div>
      {top_actions}
    </div>
  </header>
  <main>
    <section>
      <h2>结论</h2>
      <p>{escape(stringify_value(report.get('conclusion')))}</p>
    </section>

    <div class="summary-grid">{render_metric_cards(report.get('metrics', []))}</div>

    {chart_html}

    <div class="layout-2">
      <section>
        <h2>任务概览</h2>
        <div class="overview-grid">{overview_items}</div>
      </section>
      <section>
        <h2>结果文件摘要</h2>
        {output_cards_html}
      </section>
    </div>

    {primary_html}
    {secondary_html}

    <section>
      <h2>证据入口</h2>
      {render_artifact_links(report.get('artifact_index', []))}
    </section>

    {next_action_html}
    {appendix_html}
    {preflight_html}
  </main>
{script}
</body>
</html>
"""


def build_workflow_excel_sheets(report: dict[str, Any]) -> list[tuple[str, list[list[Any]]]]:
    overview_rows = [
        ["字段", "值"],
        ["title", report.get("title")],
        ["status", report.get("status_label")],
        ["severity", report.get("severity_label")],
        ["workflow", report.get("overview", {}).get("workflow_label") or report.get("overview", {}).get("workflow")],
        ["message", report.get("overview", {}).get("message")],
        ["requested_at", report.get("overview", {}).get("requested_at")],
        ["generated_at", report.get("generated_at")],
        ["conclusion", report.get("conclusion")],
        ["next_action", report.get("next_action")],
    ]

    output_rows = [["输出文件", "格式", "记录数", "重点数", "摘要"]]
    for digest in report.get("output_digests", []):
        output_rows.append(
            [
                digest.get("path"),
                digest.get("format"),
                digest.get("record_count"),
                digest.get("flagged_count"),
                digest.get("top_level_summary") or digest.get("load_error"),
            ]
        )

    evidence_rows = [["类型", "路径"]]
    for item in report.get("artifact_index", []):
        evidence_rows.append([item.get("label"), item.get("path")])

    technical_rows = [["#", "命令", "状态", "退出码", "output", "stdout", "stderr"]]
    for command in report.get("commands", []):
        technical_rows.append(
            [
                command.get("index"),
                command.get("name"),
                command.get("status_label"),
                command.get("exit_code"),
                command.get("output_path"),
                command.get("stdout_path"),
                command.get("stderr_path"),
            ]
        )

    sections = [("Overview", overview_rows)]
    presentation = ensure_dict(report.get("presentation"))
    primary = ensure_dict(presentation.get("primary_section"))
    secondary = ensure_dict(presentation.get("secondary_section"))
    if primary:
        sections.append(("Primary", rows_to_sheet_rows(primary)))
    if secondary:
        sections.append(("Details", rows_to_sheet_rows(secondary)))
    sections.extend([("Outputs", output_rows), ("Evidence", evidence_rows), ("Technical", technical_rows)])
    return sections


def build_investigation_excel_sheets(report: dict[str, Any]) -> list[tuple[str, list[list[Any]]]]:
    overview_rows = [
        ["字段", "值"],
        ["title", report.get("title")],
        ["status", report.get("status_label")],
        ["severity", report.get("severity_label")],
        ["goal", report.get("overview", {}).get("goal")],
        ["goal_description", report.get("overview", {}).get("goal_description")],
        ["selected_chain", ", ".join(str(item) for item in report.get("overview", {}).get("selected_chain", []))],
        ["stop_reason", report.get("overview", {}).get("stop_reason")],
        ["generated_at", report.get("generated_at")],
        ["conclusion", report.get("conclusion")],
        ["recommended_action", report.get("next_actions", {}).get("recommended_action")],
        ["reason", report.get("next_actions", {}).get("reason")],
    ]

    evidence_rows = [["类型", "路径"]]
    for item in report.get("artifact_index", []):
        evidence_rows.append([item.get("label"), item.get("path")])

    output_rows = [["输出文件", "格式", "记录数", "重点数", "摘要"]]
    for digest in report.get("step_output_digests", []):
        output_rows.append(
            [
                digest.get("path"),
                digest.get("format"),
                digest.get("record_count"),
                digest.get("flagged_count"),
                digest.get("top_level_summary") or digest.get("load_error"),
            ]
        )

    sections = [("Overview", overview_rows)]
    presentation = ensure_dict(report.get("presentation"))
    primary = ensure_dict(presentation.get("primary_section"))
    secondary = ensure_dict(presentation.get("secondary_section"))
    if primary:
        sections.append(("Findings", rows_to_sheet_rows(primary)))
    if secondary:
        sections.append(("Steps", rows_to_sheet_rows(secondary)))
    sections.extend([("Outputs", output_rows), ("Evidence", evidence_rows)])
    return sections
