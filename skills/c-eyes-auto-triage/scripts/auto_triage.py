#!/usr/bin/env python3
"""
Top-level EDR investigation orchestrator built on c-eyes-orchestrator.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ORCHESTRATOR_SCRIPTS = (
    Path(__file__).resolve().parent.parent.parent / "c-eyes-orchestrator" / "scripts"
)
if str(ORCHESTRATOR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(ORCHESTRATOR_SCRIPTS))

from reporting import build_investigation_report, write_report_bundle


SUPPORTED_CHAINS: dict[str, dict[str, Any]] = {
    "host-investigation": {
        "description": "Host-wide triage followed by timeline review and optional file scan.",
        "steps": [
            {"workflow": "host-triage"},
            {"workflow": "eventlog-timeline"},
            {"workflow": "filescan-risk", "requires_target_path": True},
        ],
    },
    "file-alert-investigation": {
        "description": "Investigate a suspicious file or directory and enrich it with SBOM context.",
        "steps": [
            {"workflow": "filescan-risk", "requires_target_path": True},
            {"workflow": "sbom-inventory", "requires_target_path": True},
        ],
    },
    "network-investigation": {
        "description": "Inspect internal network visibility and then triage the current host if needed.",
        "steps": [
            {"workflow": "network-inventory"},
            {"workflow": "host-triage"},
        ],
    },
    "baseline-investigation": {
        "description": "Run baseline checks and enrich with recent event context.",
        "steps": [
            {"workflow": "baseline-check"},
            {"workflow": "eventlog-timeline"},
        ],
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def write_investigation_outputs(
    workspace: Path,
    decision: dict[str, Any],
    findings: dict[str, Any],
    next_actions: dict[str, Any],
) -> None:
    write_json(workspace / "decision.json", decision)
    write_json(workspace / "findings.json", findings)
    write_json(workspace / "next_actions.json", next_actions)
    write_report_bundle(workspace, build_investigation_report(workspace, decision, findings, next_actions))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a fixed C-Eyes investigation chain.")
    parser.add_argument("--goal", required=True, choices=sorted(SUPPORTED_CHAINS))
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--dist-root")
    parser.add_argument("--config")
    parser.add_argument("--platform", default="windows" if sys.platform.startswith("win") else "linux")
    parser.add_argument("--arch", default="amd64")
    parser.add_argument("--target-path")
    parser.add_argument("--time-window", default="24h")
    parser.add_argument("--risk-mode", default="smart")
    parser.add_argument("--baseline-level", type=int, default=1)
    parser.add_argument("--reachable-segments", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--enforce-privilege", action="store_true")
    return parser.parse_args()


def build_runner_args(
    runner_path: Path,
    args: argparse.Namespace,
    step_workspace: Path,
    step: dict[str, Any],
) -> list[str]:
    command = [
        sys.executable,
        str(runner_path),
        "--workflow",
        step["workflow"],
        "--workspace",
        str(step_workspace),
        "--platform",
        args.platform,
        "--arch",
        args.arch,
        "--time-window",
        args.time_window,
        "--risk-mode",
        args.risk_mode,
        "--baseline-level",
        str(args.baseline_level),
    ]

    if args.dist_root:
        command.extend(["--dist-root", args.dist_root])
    if args.config:
        command.extend(["--config", args.config])
    if step.get("requires_target_path") and args.target_path:
        command.extend(["--target-path", args.target_path])
    if step["workflow"] == "network-inventory" and args.reachable_segments:
        command.append("--reachable-segments")
    if args.dry_run:
        command.append("--dry-run")
    if args.enforce_privilege:
        command.append("--enforce-privilege")
    return command


def summarize_step(
    step_index: int,
    step: dict[str, Any],
    step_workspace: Path,
    exit_code: int,
) -> dict[str, Any]:
    summary_path = step_workspace / "summary.json"
    manifest_path = step_workspace / "manifest.json"
    summary = load_json(summary_path) if summary_path.exists() else {}
    manifest = load_json(manifest_path) if manifest_path.exists() else {}
    status = summary.get("status") or ("ok" if exit_code == 0 else "failed")
    outputs = summary.get("outputs", [])

    return {
        "index": step_index,
        "workflow": step["workflow"],
        "workspace": str(step_workspace),
        "status": status,
        "exit_code": exit_code,
        "summary_path": str(summary_path) if summary_path.exists() else None,
        "manifest_path": str(manifest_path) if manifest_path.exists() else None,
        "outputs": outputs,
        "preflight": summary.get("preflight") or manifest.get("preflight"),
    }


def build_findings(executed_steps: list[dict[str, Any]]) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for step in executed_steps:
        if step["status"] not in {"blocked", "failed"}:
            continue
        evidence_paths = [
            path
            for path in [step.get("summary_path"), step.get("manifest_path"), *step.get("outputs", [])]
            if path
        ]
        findings.append(
            {
                "type": "workflow-issue",
                "severity": "high" if step["status"] == "failed" else "medium",
                "workflow": step["workflow"],
                "status": step["status"],
                "evidence_paths": evidence_paths,
                "message": f"Workflow '{step['workflow']}' ended with status '{step['status']}'.",
            }
        )

    return {
        "status": "findings-present" if findings else "no-material-findings",
        "findings": findings,
    }


def build_next_actions(
    goal: str,
    final_status: str,
    stop_reason: str,
    executed_steps: list[dict[str, Any]],
) -> dict[str, Any]:
    if final_status == "blocked" and stop_reason == "missing-target-path":
        return {
            "status": "manual-follow-up",
            "recommended_action": "collect-target-path",
            "goal": goal,
            "reason": "A required target path was not provided for the selected investigation chain.",
        }
    if final_status == "blocked":
        return {
            "status": "manual-follow-up",
            "recommended_action": "resolve-blocker",
            "goal": goal,
            "reason": stop_reason,
        }
    if final_status == "failed":
        failed_step = executed_steps[-1] if executed_steps else None
        return {
            "status": "manual-follow-up",
            "recommended_action": "review-step-logs",
            "goal": goal,
            "reason": f"Review logs for workflow '{failed_step['workflow']}'." if failed_step else stop_reason,
        }
    if final_status == "dry-run":
        return {
            "status": "ready-for-live-run",
            "recommended_action": "rerun-without-dry-run",
            "goal": goal,
            "reason": "The investigation chain completed planning only and did not execute live commands.",
        }
    return {
        "status": "review-results",
        "recommended_action": "review-findings-and-evidence",
        "goal": goal,
        "reason": "The supported investigation chain completed without blocking conditions.",
    }


def main() -> int:
    args = parse_args()
    skill_root = Path(__file__).resolve().parent.parent
    runner_path = skill_root.parent / "c-eyes-orchestrator" / "scripts" / "ceyes_runner.py"
    workspace = Path(args.workspace).expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    goal_config = SUPPORTED_CHAINS.get(args.goal)
    selected_chain = [step["workflow"] for step in goal_config["steps"]]
    decision: dict[str, Any] = {
        "requested_at": utc_now(),
        "goal": args.goal,
        "goal_description": goal_config["description"],
        "selected_chain": selected_chain,
        "workspace": str(workspace),
        "status": "planned",
        "stop_reason": None,
        "executed_steps": [],
    }

    if not runner_path.exists():
        decision["status"] = "blocked"
        decision["stop_reason"] = f"runner not found: {runner_path}"
        executed_steps: list[dict[str, Any]] = []
        findings = build_findings(executed_steps)
        next_actions = build_next_actions(args.goal, "blocked", decision["stop_reason"], executed_steps)
        write_investigation_outputs(workspace, decision, findings, next_actions)
        return 2

    executed_steps: list[dict[str, Any]] = []
    final_status = "completed"
    stop_reason = "chain-complete"

    for index, step in enumerate(goal_config["steps"], start=1):
        if step.get("requires_target_path") and not args.target_path:
            final_status = "blocked"
            stop_reason = "missing-target-path"
            executed_steps.append(
                {
                    "index": index,
                    "workflow": step["workflow"],
                    "workspace": None,
                    "status": "blocked",
                    "exit_code": None,
                    "summary_path": None,
                    "manifest_path": None,
                    "outputs": [],
                    "preflight": {
                        "status": "blocked",
                        "errors": [f"workflow '{step['workflow']}' requires --target-path"],
                    },
                }
            )
            break

        step_workspace = workspace / "steps" / f"{index:02d}-{step['workflow']}"
        command = build_runner_args(runner_path, args, step_workspace, step)
        completed = subprocess.run(command, check=False)
        step_record = summarize_step(index, step, step_workspace, completed.returncode)
        executed_steps.append(step_record)

        if step_record["status"] == "blocked":
            final_status = "blocked"
            stop_reason = f"step-blocked:{step['workflow']}"
            break
        if step_record["status"] == "failed":
            final_status = "failed"
            stop_reason = f"step-failed:{step['workflow']}"
            break
        if step_record["status"] == "dry-run":
            final_status = "dry-run"

    decision["status"] = final_status
    decision["stop_reason"] = stop_reason
    decision["executed_steps"] = executed_steps
    findings = build_findings(executed_steps)
    next_actions = build_next_actions(args.goal, final_status, stop_reason, executed_steps)

    write_investigation_outputs(workspace, decision, findings, next_actions)
    return 0 if final_status in {"completed", "dry-run"} else 1 if final_status == "failed" else 2


if __name__ == "__main__":
    sys.exit(main())
