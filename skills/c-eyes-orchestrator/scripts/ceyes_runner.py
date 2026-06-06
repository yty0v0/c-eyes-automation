#!/usr/bin/env python3
"""
Shared C-Eyes workflow runner.

Resolves the current-platform public runtime, downloads it on demand when
missing, stages it into a workspace, executes a named workflow, and emits run
metadata for downstream LLM reasoning.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform as py_platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from reporting import build_workflow_report, write_report_bundle


DEFAULT_RELEASE_REPO = "m-sec-org/c-eyes"
DEFAULT_TARGETS = {
    ("windows", "amd64"): {
        "bundle_dir": "dist-windows-amd64-public",
        "binary": "c-eyes.exe",
    },
    ("linux", "amd64"): {
        "bundle_dir": "dist-linux-amd64-public",
        "binary": "c-eyes",
    },
    ("linux", "arm64"): {
        "bundle_dir": "dist-linux-arm64-public",
        "binary": "c-eyes",
    },
}

WORKFLOW_NAMES = (
    "host-triage",
    "filescan-risk",
    "eventlog-timeline",
    "network-inventory",
    "sbom-inventory",
    "baseline-check",
)


@dataclass
class RuntimeTarget:
    platform_name: str
    arch: str
    bundle_dir: str
    binary: str

    @property
    def target_key(self) -> str:
        return f"{self.platform_name}-{self.arch}"

    @property
    def asset_name(self) -> str:
        return f"{self.bundle_dir}.zip"


@dataclass
class RuntimeSource:
    dist_root: Path
    release_repo: str
    release_tag: str | None
    cache_dir: Path


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def detect_platform_name() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    return sys.platform


def detect_arch() -> str:
    machine = py_platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    return machine


def is_elevated(platform_name: str) -> bool:
    try:
        if platform_name == "windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        if platform_name == "linux":
            return os.geteuid() == 0
    except Exception:
        return False
    return False


def load_json_file(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, indent=2)
        handle.write("\n")


def write_manifest_summary_and_report(
    workspace: Path,
    manifest: dict[str, Any],
    summary: dict[str, Any],
) -> None:
    write_json(workspace / "manifest.json", manifest)
    write_json(workspace / "summary.json", summary)
    write_report_bundle(workspace, build_workflow_report(workspace, manifest, summary))


def clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def resolve_path_value(raw: str | None, base_dir: Path | None) -> Path | None:
    if not raw:
        return None
    path = Path(raw).expanduser()
    if path.is_absolute():
        return path.resolve()
    if base_dir is not None:
        return (base_dir / path).resolve()
    return path.resolve()


def default_bundled_dist_root(repo_root: Path) -> Path:
    candidates = [
        (repo_root / "runtime").resolve(),
        (repo_root / "c-eyes-skill-pack" / "runtime").resolve(),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    if repo_root.name == "c-eyes-skill-pack":
        return candidates[0]
    return candidates[1]


def default_cache_dir(dist_root: Path) -> Path:
    return (dist_root / "_downloads").resolve()


def sanitize_repo_name(repo: str) -> str:
    return repo.replace("/", "_").replace("\\", "_")


def resolve_target_config(
    config: dict[str, Any],
    platform_name: str,
    arch: str,
) -> RuntimeTarget | None:
    overrides = config.get("runtime_targets", {})
    default = DEFAULT_TARGETS.get((platform_name, arch))
    if default is None and not isinstance(overrides, dict):
        return None

    target_key = f"{platform_name}-{arch}"
    raw = overrides.get(target_key) if isinstance(overrides, dict) else None
    if raw is None:
        if default is None:
            return None
        raw = default

    bundle_dir = raw.get("bundle_dir") or raw.get("bundle") if isinstance(raw, dict) else None
    binary = raw.get("binary") if isinstance(raw, dict) else None
    if not bundle_dir or not binary:
        return None

    return RuntimeTarget(
        platform_name=platform_name,
        arch=arch,
        bundle_dir=bundle_dir,
        binary=binary,
    )


def resolve_dist_root(
    args: argparse.Namespace,
    config: dict[str, Any],
    config_dir: Path | None,
    repo_root: Path,
) -> Path:
    explicit = args.dist_root or os.environ.get("C_EYES_DIST_ROOT") or config.get("dist_root")
    resolved = resolve_path_value(explicit, config_dir)
    if resolved is not None:
        return resolved
    return default_bundled_dist_root(repo_root)


def resolve_cache_dir(
    config: dict[str, Any],
    config_dir: Path | None,
    dist_root: Path,
) -> Path:
    resolved = resolve_path_value(config.get("cache_dir"), config_dir)
    if resolved is not None:
        return resolved
    return default_cache_dir(dist_root)


def resolve_runtime_source(
    args: argparse.Namespace,
    config: dict[str, Any],
    config_dir: Path | None,
    skill_root: Path,
) -> RuntimeSource:
    repo_root = skill_root.parent.parent.parent
    dist_root = resolve_dist_root(args, config, config_dir, repo_root)
    return RuntimeSource(
        dist_root=dist_root,
        release_repo=str(config.get("release_repo") or DEFAULT_RELEASE_REPO),
        release_tag=str(config.get("release_tag")) if config.get("release_tag") else None,
        cache_dir=resolve_cache_dir(config, config_dir, dist_root),
    )


def build_output_path(workspace: Path, workflow: str, filename: str) -> Path:
    output_dir = workspace / "outputs" / workflow
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir / filename


def require_target_path(args: argparse.Namespace, workflow: str) -> str:
    if not args.target_path:
        raise ValueError(f"workflow '{workflow}' requires --target-path")
    return str(Path(args.target_path).expanduser().resolve())


def build_workflow_commands(
    args: argparse.Namespace,
    workspace: Path,
    staged_binary: Path,
) -> list[dict[str, Any]]:
    risk_mode = args.risk_mode or "smart"
    commands: list[dict[str, Any]] = []

    if args.workflow == "host-triage":
        output_path = build_output_path(workspace, args.workflow, "host-triage.json")
        commands.append(
            {
                "name": "host-triage",
                "output_path": str(output_path),
                "args": [
                    str(staged_binary),
                    "-o",
                    str(output_path),
                    "-r",
                    "hostscan",
                    "--all",
                ],
            }
        )
    elif args.workflow == "filescan-risk":
        output_path = build_output_path(workspace, args.workflow, "filescan-risk.json")
        target_path = require_target_path(args, args.workflow)
        commands.append(
            {
                "name": "filescan-risk",
                "output_path": str(output_path),
                "args": [
                    str(staged_binary),
                    "-o",
                    str(output_path),
                    "-r",
                    "--risk-mode",
                    risk_mode,
                    "filescan",
                    "--scan-mode",
                    "path",
                    target_path,
                    "--smart",
                ],
            }
        )
    elif args.workflow == "eventlog-timeline":
        output_path = build_output_path(workspace, args.workflow, "eventlog-timeline.json")
        commands.append(
            {
                "name": "eventlog-timeline",
                "output_path": str(output_path),
                "args": [
                    str(staged_binary),
                    "-o",
                    str(output_path),
                    "eventlog",
                    "-last",
                    args.time_window,
                ],
            }
        )
    elif args.workflow == "network-inventory":
        output_path = build_output_path(workspace, args.workflow, "network-inventory.json")
        command = [
            str(staged_binary),
            "-o",
            str(output_path),
            "netscan",
        ]
        if args.reachable_segments:
            command.append("-reachableSegments")
        commands.append(
            {
                "name": "network-inventory",
                "output_path": str(output_path),
                "args": command,
            }
        )
    elif args.workflow == "sbom-inventory":
        output_path = build_output_path(workspace, args.workflow, "sbom-inventory.json")
        target_path = require_target_path(args, args.workflow)
        commands.append(
            {
                "name": "sbom-inventory",
                "output_path": str(output_path),
                "args": [
                    str(staged_binary),
                    "-o",
                    str(output_path),
                    "sbom",
                    "--path",
                    target_path,
                ],
            }
        )
    elif args.workflow == "baseline-check":
        output_path = build_output_path(workspace, args.workflow, "baseline-check.json")
        commands.append(
            {
                "name": "baseline-check",
                "output_path": str(output_path),
                "args": [
                    str(staged_binary),
                    "-o",
                    str(output_path),
                    "benchmark",
                    "--baseline-level",
                    str(args.baseline_level),
                ],
            }
        )
    else:
        raise ValueError(f"unsupported workflow '{args.workflow}'")

    return commands


def workflow_requires_elevation(workflow: str) -> bool:
    return workflow in {"host-triage", "network-inventory", "baseline-check"}


def stage_runtime(source_dir: Path, binary_name: str, runtime_dir: Path) -> Path:
    clean_dir(runtime_dir)
    shutil.copytree(source_dir, runtime_dir, dirs_exist_ok=True)
    binary_path = runtime_dir / binary_name
    if os.name != "nt":
        binary_path.chmod(binary_path.stat().st_mode | 0o111)
    return binary_path


def collect_runtime_state(runtime_dir: Path) -> list[str]:
    filenames = ("scan-cache.db", "netscan-assets.db")
    found = []
    for filename in filenames:
        candidate = runtime_dir / filename
        if candidate.exists():
            found.append(str(candidate))
    return found


def fetch_json(url: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "c-eyes-orchestrator",
        },
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def download_file(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = destination.with_suffix(destination.suffix + ".tmp")
    request = urllib.request.Request(url, headers={"User-Agent": "c-eyes-orchestrator"})
    with urllib.request.urlopen(request) as response, temp_path.open("wb") as handle:
        shutil.copyfileobj(response, handle)
    temp_path.replace(destination)


def extract_zip(archive_path: Path, dist_root: Path) -> None:
    dist_root.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive_path, "r") as archive:
        archive.extractall(dist_root)


def release_metadata_url(repo: str, tag: str | None) -> str:
    if tag:
        return f"https://api.github.com/repos/{repo}/releases/tags/{tag}"
    return f"https://api.github.com/repos/{repo}/releases/latest"


def find_release_asset(release: dict[str, Any], asset_name: str) -> dict[str, Any]:
    for asset in release.get("assets", []):
        if asset.get("name") == asset_name:
            return asset
    release_name = release.get("tag_name") or release.get("name") or "unknown"
    raise FileNotFoundError(f"release asset '{asset_name}' not found in release '{release_name}'")


def ensure_runtime_bundle(
    runtime_source: RuntimeSource,
    target: RuntimeTarget,
) -> tuple[Path, dict[str, Any]]:
    source_dir = runtime_source.dist_root / target.bundle_dir
    binary_path = source_dir / target.binary
    if binary_path.exists():
        return source_dir, {
            "kind": "local-dist",
            "dist_root": str(runtime_source.dist_root),
            "source_dir": str(source_dir),
            "bundle_dir": target.bundle_dir,
        }

    release = fetch_json(release_metadata_url(runtime_source.release_repo, runtime_source.release_tag))
    asset = find_release_asset(release, target.asset_name)
    resolved_tag = str(release.get("tag_name") or runtime_source.release_tag or "latest")
    archive_path = (
        runtime_source.cache_dir
        / sanitize_repo_name(runtime_source.release_repo)
        / resolved_tag
        / target.asset_name
    )
    if not archive_path.exists():
        download_file(str(asset["browser_download_url"]), archive_path)

    extract_zip(archive_path, runtime_source.dist_root)
    if not binary_path.exists():
        raise FileNotFoundError(f"runtime binary does not exist after extraction: {binary_path}")

    return source_dir, {
        "kind": "release-download",
        "dist_root": str(runtime_source.dist_root),
        "source_dir": str(source_dir),
        "bundle_dir": target.bundle_dir,
        "release_repo": runtime_source.release_repo,
        "release_tag": resolved_tag,
        "asset_name": target.asset_name,
        "archive_path": str(archive_path),
    }


def run_command(command: dict[str, Any], raw_dir: Path, cwd: Path) -> dict[str, Any]:
    index = command["index"]
    safe_name = command["name"].replace(" ", "-")
    stdout_path = raw_dir / f"{index:02d}-{safe_name}.stdout.log"
    stderr_path = raw_dir / f"{index:02d}-{safe_name}.stderr.log"
    started_at = utc_now()
    with stdout_path.open("w", encoding="utf-8") as stdout_handle, stderr_path.open(
        "w", encoding="utf-8"
    ) as stderr_handle:
        completed = subprocess.run(
            command["args"],
            cwd=str(cwd),
            stdout=stdout_handle,
            stderr=stderr_handle,
            text=True,
            check=False,
        )
    finished_at = utc_now()
    return {
        "index": index,
        "name": command["name"],
        "args": command["args"],
        "output_path": command["output_path"],
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "started_at": started_at,
        "finished_at": finished_at,
        "exit_code": completed.returncode,
        "status": "ok" if completed.returncode == 0 else "failed",
    }


def build_preflight(
    args: argparse.Namespace,
    runtime_source: RuntimeSource,
    target: RuntimeTarget | None,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    platform_name = args.platform
    elevated = is_elevated(platform_name)

    if target is None:
        errors.append(
            f"unsupported runtime target for platform '{platform_name}' and arch '{args.arch}'"
        )

    if runtime_source.dist_root.exists() and not runtime_source.dist_root.is_dir():
        errors.append(f"dist root is not a directory: {runtime_source.dist_root}")

    if args.workflow and workflow_requires_elevation(args.workflow) and not elevated:
        warnings.append(
            f"workflow '{args.workflow}' usually requires elevated privileges on {platform_name}"
        )
        if args.enforce_privilege:
            errors.append(
                f"elevated privileges required for workflow '{args.workflow}' on {platform_name}"
            )

    return {
        "status": "ok" if not errors else "blocked",
        "errors": errors,
        "warnings": warnings,
        "elevated": elevated,
        "requires_elevation": workflow_requires_elevation(args.workflow),
    }


def prepare_local_bundle(
    runtime_source: RuntimeSource,
    target: RuntimeTarget,
) -> tuple[Path, dict[str, Any]]:
    return ensure_runtime_bundle(runtime_source, target)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a named C-Eyes workflow.")
    parser.add_argument("--workflow", choices=WORKFLOW_NAMES)
    parser.add_argument("--workspace")
    parser.add_argument("--dist-root")
    parser.add_argument("--config")
    parser.add_argument("--platform", default=detect_platform_name())
    parser.add_argument("--arch", default=detect_arch())
    parser.add_argument("--target-path")
    parser.add_argument("--time-window", default="24h")
    parser.add_argument("--risk-mode", default="smart")
    parser.add_argument("--baseline-level", type=int, default=1)
    parser.add_argument("--reachable-segments", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--download-only", action="store_true")
    parser.add_argument("--enforce-privilege", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.download_only and not args.workflow:
        raise SystemExit("--workflow is required unless --download-only is set")
    if not args.download_only and not args.workspace:
        raise SystemExit("--workspace is required unless --download-only is set")

    skill_root = Path(__file__).resolve().parent.parent
    config: dict[str, Any] = {}
    config_dir: Path | None = None
    if args.config:
        config_path = Path(args.config).expanduser().resolve()
        config = load_json_file(config_path)
        config_dir = config_path.parent

    runtime_source = resolve_runtime_source(args, config, config_dir, skill_root)
    target = resolve_target_config(config, args.platform, args.arch)
    preflight = build_preflight(args, runtime_source, target)

    if preflight["status"] != "ok":
        if args.download_only:
            print(
                json.dumps(
                    {
                        "status": "blocked",
                        "preflight": preflight,
                    },
                    ensure_ascii=True,
                    indent=2,
                )
            )
            return 2
        workspace = Path(args.workspace).expanduser().resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        manifest = {
            "requested_at": utc_now(),
            "workflow": args.workflow,
            "skill_root": str(skill_root),
            "workspace": str(workspace),
            "runtime_target": {
                "platform": args.platform,
                "arch": args.arch,
                "bundle_dir": target.bundle_dir if target else None,
                "binary": target.binary if target else None,
                "dist_root": str(runtime_source.dist_root),
            },
            "preflight": preflight,
            "commands": [],
            "dry_run": args.dry_run,
            "download_only": args.download_only,
        }
        summary = {
            "workflow": args.workflow,
            "status": "blocked",
            "message": "preflight failed",
            "preflight": preflight,
            "outputs": [],
        }
        write_manifest_summary_and_report(workspace, manifest, summary)
        return 2

    try:
        source_dir, source_details = prepare_local_bundle(runtime_source, target)
    except Exception as exc:
        if args.download_only:
            print(
                json.dumps(
                    {
                        "status": "blocked",
                        "message": "runtime acquisition failed",
                        "error": str(exc),
                        "runtime_target": {
                            "platform": args.platform,
                            "arch": args.arch,
                            "bundle_dir": target.bundle_dir if target else None,
                            "binary": target.binary if target else None,
                            "dist_root": str(runtime_source.dist_root),
                        },
                    },
                    ensure_ascii=True,
                    indent=2,
                )
            )
            return 2

        workspace = Path(args.workspace).expanduser().resolve()
        workspace.mkdir(parents=True, exist_ok=True)
        manifest = {
            "requested_at": utc_now(),
            "workflow": args.workflow,
            "skill_root": str(skill_root),
            "workspace": str(workspace),
            "runtime_target": {
                "platform": args.platform,
                "arch": args.arch,
                "bundle_dir": target.bundle_dir if target else None,
                "binary": target.binary if target else None,
                "dist_root": str(runtime_source.dist_root),
            },
            "preflight": {
                "status": "blocked",
                "errors": [str(exc)],
                "warnings": preflight["warnings"],
                "elevated": preflight["elevated"],
                "requires_elevation": preflight["requires_elevation"],
            },
            "commands": [],
            "dry_run": args.dry_run,
            "download_only": args.download_only,
        }
        summary = {
            "workflow": args.workflow,
            "status": "blocked",
            "message": "runtime acquisition failed",
            "preflight": manifest["preflight"],
            "outputs": [],
        }
        write_manifest_summary_and_report(workspace, manifest, summary)
        return 2

    if args.download_only:
        print(
            json.dumps(
                {
                    "status": "ok",
                    "message": "runtime ready",
                    "runtime_target": {
                        "platform": args.platform,
                        "arch": args.arch,
                        "bundle_dir": target.bundle_dir,
                        "binary": target.binary,
                        "dist_root": str(runtime_source.dist_root),
                        **source_details,
                    },
                },
                ensure_ascii=True,
                indent=2,
            )
        )
        return 0

    workspace = Path(args.workspace).expanduser().resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    raw_dir = workspace / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    request_payload = {
        "workflow": args.workflow,
        "workspace": str(workspace),
        "runtime_source": {
            "dist_root": str(runtime_source.dist_root),
            "release_repo": runtime_source.release_repo,
            "release_tag": runtime_source.release_tag,
            "cache_dir": str(runtime_source.cache_dir),
        },
        "platform": args.platform,
        "arch": args.arch,
        "target_path": args.target_path,
        "time_window": args.time_window,
        "risk_mode": args.risk_mode,
        "baseline_level": args.baseline_level,
        "reachable_segments": args.reachable_segments,
        "dry_run": args.dry_run,
        "download_only": args.download_only,
        "enforce_privilege": args.enforce_privilege,
        "requested_at": utc_now(),
    }
    write_json(workspace / "run.json", request_payload)

    manifest: dict[str, Any] = {
        "requested_at": request_payload["requested_at"],
        "workflow": args.workflow,
        "skill_root": str(skill_root),
        "workspace": str(workspace),
        "runtime_target": {
            "platform": args.platform,
            "arch": args.arch,
            "bundle_dir": target.bundle_dir if target else None,
            "binary": target.binary if target else None,
            "dist_root": str(runtime_source.dist_root),
            "release_repo": runtime_source.release_repo,
            "release_tag": runtime_source.release_tag,
            "cache_dir": str(runtime_source.cache_dir),
        },
        "preflight": preflight,
        "commands": [],
        "dry_run": args.dry_run,
        "download_only": args.download_only,
    }

    runtime_dir = workspace / "runtime" / target.target_key
    staged_binary = stage_runtime(source_dir, target.binary, runtime_dir)
    manifest["runtime_target"].update(source_details)
    manifest["runtime_target"]["staged_dir"] = str(runtime_dir)
    manifest["runtime_target"]["staged_binary"] = str(staged_binary)

    try:
        commands = build_workflow_commands(args, workspace, staged_binary)
    except Exception as exc:
        manifest["preflight"] = {
            "status": "blocked",
            "errors": [str(exc)],
            "warnings": preflight["warnings"],
            "elevated": preflight["elevated"],
            "requires_elevation": preflight["requires_elevation"],
        }
        summary = {
            "workflow": args.workflow,
            "status": "blocked",
            "message": "workflow input validation failed",
            "preflight": manifest["preflight"],
            "outputs": [],
            "runtime_state_files": collect_runtime_state(runtime_dir),
        }
        write_manifest_summary_and_report(workspace, manifest, summary)
        return 2
    for index, command in enumerate(commands, start=1):
        command["index"] = index

    if args.dry_run:
        manifest["commands"] = [
            {
                "index": command["index"],
                "name": command["name"],
                "args": command["args"],
                "output_path": command["output_path"],
                "status": "planned",
            }
            for command in commands
        ]
        runtime_state = collect_runtime_state(runtime_dir)
        manifest["runtime_state_files"] = runtime_state
        summary = {
            "workflow": args.workflow,
            "status": "dry-run",
            "message": "preflight passed; commands were planned but not executed",
            "preflight": preflight,
            "outputs": [command["output_path"] for command in commands],
            "runtime_state_files": runtime_state,
        }
        write_manifest_summary_and_report(workspace, manifest, summary)
        return 0

    overall_status = "ok"
    for command in commands:
        result = run_command(command, raw_dir, runtime_dir)
        manifest["commands"].append(result)
        if result["status"] != "ok":
            overall_status = "failed"
            break

    runtime_state = collect_runtime_state(runtime_dir)
    manifest["runtime_state_files"] = runtime_state
    outputs = [
        entry["output_path"]
        for entry in manifest["commands"]
        if entry.get("output_path")
    ]
    summary = {
        "workflow": args.workflow,
        "status": overall_status,
        "message": "workflow completed" if overall_status == "ok" else "workflow failed",
        "preflight": preflight,
        "outputs": outputs,
        "runtime_state_files": runtime_state,
        "command_count": len(manifest["commands"]),
    }
    write_manifest_summary_and_report(workspace, manifest, summary)
    return 0 if overall_status == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
