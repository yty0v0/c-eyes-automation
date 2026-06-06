#!/usr/bin/env python3
"""
Shared final-report helpers for C-Eyes runs.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any


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


def build_workflow_report(
    workspace: Path,
    manifest: dict[str, Any],
    summary: dict[str, Any],
) -> dict[str, Any]:
    status = str(summary.get("status") or manifest.get("status") or "unknown")
    workflow = str(summary.get("workflow") or manifest.get("workflow") or "unknown")
    outputs = [relative_path(item, workspace) for item in summary.get("outputs", []) if item]
    commands = []
    for command in manifest.get("commands", []):
        commands.append(
            {
                "index": command.get("index"),
                "name": command.get("name"),
                "status": command.get("status"),
                "exit_code": command.get("exit_code"),
                "output_path": relative_path(command.get("output_path"), workspace),
                "stdout_path": relative_path(command.get("stdout_path"), workspace),
                "stderr_path": relative_path(command.get("stderr_path"), workspace),
            }
        )

    if status == "ok":
        conclusion = f"`{workflow}` 已执行完成，可以先查看 summary.json 和 outputs/。"
        next_action = "结合输出文件继续人工研判，必要时再选择自动调查链。"
    elif status == "dry-run":
        conclusion = f"`{workflow}` 已完成预演，尚未执行真实扫描。"
        next_action = "确认参数后去掉 dry-run 重新执行。"
    elif status == "blocked":
        conclusion = f"`{workflow}` 未执行成功，当前被阻塞。"
        next_action = "先解决权限、参数或 runtime 阻塞，再重新执行。"
    else:
        conclusion = f"`{workflow}` 执行失败，请先查看 raw 日志和 manifest.json。"
        next_action = "检查失败命令、stderr 日志与 runtime 状态后再重试。"

    warnings = list((summary.get("preflight") or {}).get("warnings", []))
    errors = list((summary.get("preflight") or {}).get("errors", []))

    return {
        "report_version": "1.0",
        "report_kind": "single-workflow",
        "title": f"C-Eyes Workflow Report - {workflow}",
        "generated_at": utc_now(),
        "status": status,
        "status_label": status_label(status),
        "workspace": str(workspace),
        "workspace_relative_report_dir": "report_result",
        "overview": {
            "workflow": workflow,
            "message": summary.get("message"),
            "requested_at": manifest.get("requested_at"),
            "dry_run": bool(manifest.get("dry_run")),
            "download_only": bool(manifest.get("download_only")),
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
        "commands": commands,
        "preflight": {
            "status": (summary.get("preflight") or {}).get("status"),
            "warnings": warnings,
            "errors": errors,
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
    for step in decision.get("executed_steps", []):
        executed_steps.append(
            {
                "index": step.get("index"),
                "workflow": step.get("workflow"),
                "status": step.get("status"),
                "status_label": status_label(str(step.get("status"))),
                "workspace": relative_path(step.get("workspace"), workspace),
                "summary_path": relative_path(step.get("summary_path"), workspace),
                "manifest_path": relative_path(step.get("manifest_path"), workspace),
                "outputs": [relative_path(item, workspace) for item in step.get("outputs", []) if item],
                "preflight": step.get("preflight"),
            }
        )

    rendered_findings = []
    for item in findings.get("findings", []):
        rendered_findings.append(
            {
                "type": item.get("type"),
                "severity": item.get("severity"),
                "workflow": item.get("workflow"),
                "status": item.get("status"),
                "message": item.get("message"),
                "evidence_paths": [
                    relative_path(path, workspace) for path in item.get("evidence_paths", []) if path
                ],
            }
        )

    status = str(decision.get("status") or "unknown")
    if status == "completed":
        conclusion = "自动调查链已执行完成，可以直接从本报告查看调查结论和下一步建议。"
    elif status == "dry-run":
        conclusion = "自动调查链仅完成预演，尚未执行真实扫描步骤。"
    elif status == "blocked":
        conclusion = "自动调查链已阻塞，请先处理缺失参数、权限或运行时问题。"
    else:
        conclusion = "自动调查链执行失败，请结合步骤证据和日志继续排查。"

    return {
        "report_version": "1.0",
        "report_kind": "investigation",
        "title": f"C-Eyes Investigation Report - {decision.get('goal', 'unknown')}",
        "generated_at": utc_now(),
        "status": status,
        "status_label": status_label(status),
        "workspace": str(workspace),
        "workspace_relative_report_dir": "report_result",
        "overview": {
            "goal": decision.get("goal"),
            "goal_description": decision.get("goal_description"),
            "selected_chain": decision.get("selected_chain", []),
            "stop_reason": decision.get("stop_reason"),
            "requested_at": decision.get("requested_at"),
        },
        "investigation_artifacts": {
            "decision_json": "decision.json",
            "findings_json": "findings.json",
            "next_actions_json": "next_actions.json",
        },
        "executed_steps": executed_steps,
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
        "conclusion": conclusion,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines: list[str] = [
        f"# {report['title']}",
        "",
        f"- 状态：{report['status_label']}",
        f"- 工作目录：`{report['workspace']}`",
        f"- 最终报告目录：`report_result/`",
        f"- 生成时间：`{report['generated_at']}`",
        "",
        "## 结论",
        "",
        report.get("conclusion", "无"),
        "",
    ]

    overview = report.get("overview", {})
    lines.extend(["## 概览", ""])
    for key, value in overview.items():
        lines.append(f"- {key}: `{value}`")
    lines.append("")

    if report.get("report_kind") == "single-workflow":
        lines.extend(["## 输出文件", ""])
        artifacts = report.get("artifacts", {})
        lines.append(f"- summary.json: `{artifacts.get('summary_json')}`")
        lines.append(f"- manifest.json: `{artifacts.get('manifest_json')}`")
        for item in artifacts.get("outputs", []):
            lines.append(f"- output: `{item}`")
        lines.append("")

        preflight = report.get("preflight", {})
        if preflight.get("warnings") or preflight.get("errors"):
            lines.extend(["## 预检信息", ""])
            for item in preflight.get("warnings", []):
                lines.append(f"- warning: {item}")
            for item in preflight.get("errors", []):
                lines.append(f"- error: {item}")
            lines.append("")

        lines.extend(["## 执行命令", ""])
        commands = report.get("commands", [])
        if not commands:
            lines.append("- 无命令记录")
        else:
            for item in commands:
                lines.append(
                    f"- [{item.get('index')}] {item.get('name')} / {status_label(str(item.get('status')))} / "
                    f"output=`{item.get('output_path')}`"
                )
        lines.extend(["", "## 下一步建议", "", report.get("next_action", "无"), ""])
    else:
        lines.extend(["## 关键发现", ""])
        findings = report.get("findings", {})
        if not findings.get("items"):
            lines.append("- 未发现实质异常")
        else:
            for item in findings.get("items", []):
                lines.append(
                    f"- [{item.get('severity')}] {item.get('workflow')} / {item.get('message')}"
                )
                for path in item.get("evidence_paths", []):
                    lines.append(f"  - evidence: `{path}`")
        lines.append("")

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


def render_html(report: dict[str, Any]) -> str:
    def render_list(items: list[str]) -> str:
        if not items:
            return "<li>无</li>"
        return "".join(f"<li><code>{escape(item)}</code></li>" for item in items)

    overview_items = "".join(
        f"<li><strong>{escape(str(key))}</strong>: <code>{escape(str(value))}</code></li>"
        for key, value in report.get("overview", {}).items()
    )

    body_parts = [
        f"<h1>{escape(report['title'])}</h1>",
        (
            "<div class='meta'>"
            f"<span>状态: {escape(report['status_label'])}</span>"
            f"<span>工作目录: {escape(report['workspace'])}</span>"
            f"<span>报告目录: report_result/</span>"
            f"<span>生成时间: {escape(report['generated_at'])}</span>"
            "</div>"
        ),
        f"<section><h2>结论</h2><p>{escape(str(report.get('conclusion', '无')))}</p></section>",
        f"<section><h2>概览</h2><ul>{overview_items}</ul></section>",
    ]

    if report.get("report_kind") == "single-workflow":
        artifacts = report.get("artifacts", {})
        body_parts.append(
            "<section><h2>输出文件</h2><ul>"
            f"<li><code>{escape(str(artifacts.get('summary_json')))}</code></li>"
            f"<li><code>{escape(str(artifacts.get('manifest_json')))}</code></li>"
            f"{render_list(list(artifacts.get('outputs', [])))}"
            "</ul></section>"
        )
        commands_html = []
        for command in report.get("commands", []):
            commands_html.append(
                "<tr>"
                f"<td>{escape(str(command.get('index')))}</td>"
                f"<td>{escape(str(command.get('name')))}</td>"
                f"<td>{escape(status_label(str(command.get('status'))))}</td>"
                f"<td><code>{escape(str(command.get('output_path')))}</code></td>"
                "</tr>"
            )
        body_parts.append(
            "<section><h2>执行命令</h2><table><thead><tr>"
            "<th>#</th><th>命令</th><th>状态</th><th>输出</th>"
            "</tr></thead><tbody>"
            + ("".join(commands_html) if commands_html else "<tr><td colspan='4'>无命令记录</td></tr>")
            + "</tbody></table></section>"
        )
        body_parts.append(
            f"<section><h2>下一步建议</h2><p>{escape(str(report.get('next_action', '无')))}</p></section>"
        )
    else:
        findings_items = report.get("findings", {}).get("items", [])
        if findings_items:
            findings_html = []
            for item in findings_items:
                evidences = "".join(
                    f"<li><code>{escape(str(path))}</code></li>"
                    for path in item.get("evidence_paths", [])
                )
                findings_html.append(
                    "<div class='card'>"
                    f"<h3>{escape(str(item.get('workflow')))} / {escape(str(item.get('severity')))}</h3>"
                    f"<p>{escape(str(item.get('message')))}</p>"
                    f"<ul>{evidences or '<li>无证据路径</li>'}</ul>"
                    "</div>"
                )
            body_parts.append("<section><h2>关键发现</h2>" + "".join(findings_html) + "</section>")
        else:
            body_parts.append("<section><h2>关键发现</h2><p>未发现实质异常。</p></section>")

        steps_html = []
        for step in report.get("executed_steps", []):
            refs: list[str] = []
            if step.get("summary_path"):
                refs.append(step["summary_path"])
            if step.get("manifest_path"):
                refs.append(step["manifest_path"])
            steps_html.append(
                "<tr>"
                f"<td>{escape(str(step.get('index')))}</td>"
                f"<td>{escape(str(step.get('workflow')))}</td>"
                f"<td>{escape(str(step.get('status_label')))}</td>"
                f"<td>{''.join(f'<div><code>{escape(ref)}</code></div>' for ref in refs) or '无'}</td>"
                "</tr>"
            )
        body_parts.append(
            "<section><h2>调查步骤</h2><table><thead><tr>"
            "<th>#</th><th>workflow</th><th>状态</th><th>证据</th>"
            "</tr></thead><tbody>"
            + "".join(steps_html)
            + "</tbody></table></section>"
        )
        next_actions = report.get("next_actions", {})
        body_parts.append(
            "<section><h2>下一步建议</h2>"
            f"<p><strong>{escape(str(next_actions.get('status_label')))}</strong></p>"
            f"<p>action: <code>{escape(str(next_actions.get('recommended_action')))}</code></p>"
            f"<p>{escape(str(next_actions.get('reason')))}</p>"
            "</section>"
        )

    body = "".join(body_parts)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{escape(report['title'])}</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 0;
      background: #f5f7fb;
      color: #111827;
    }}
    main {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 32px 24px 48px;
    }}
    h1, h2, h3 {{ margin: 0 0 12px; }}
    section {{
      background: #ffffff;
      border: 1px solid #dbe2ea;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 16px;
    }}
    .meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin: 16px 0 20px;
      color: #4b5563;
    }}
    .meta span {{
      background: #ffffff;
      border: 1px solid #dbe2ea;
      border-radius: 6px;
      padding: 8px 10px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
    }}
    th, td {{
      border: 1px solid #dbe2ea;
      padding: 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: #eef3f8;
    }}
    code {{
      background: #eef3f8;
      padding: 2px 4px;
      border-radius: 4px;
      word-break: break-all;
    }}
    .card {{
      border: 1px solid #dbe2ea;
      border-radius: 8px;
      padding: 14px;
      margin-bottom: 12px;
      background: #fafcff;
    }}
  </style>
</head>
<body>
  <main>{body}</main>
</body>
</html>
"""


def write_report_bundle(workspace: Path, report: dict[str, Any]) -> None:
    report_dir = report_result_dir(workspace)
    write_json(report_dir / "report.json", report)
    write_text(report_dir / "summary.md", render_markdown(report))
    write_text(report_dir / "report.html", render_html(report))
