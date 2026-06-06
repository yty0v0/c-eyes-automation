#!/usr/bin/env bash
set -euo pipefail

goal=""
workspace=""
dist_root=""
config=""
platform="linux"
arch="amd64"
target_path=""
time_window="24h"
risk_mode="smart"
baseline_level="1"
reachable_segments="0"
dry_run="0"
enforce_privilege="0"
python_bin="${PYTHON:-python3}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --goal)
      goal="$2"
      shift 2
      ;;
    --workspace)
      workspace="$2"
      shift 2
      ;;
    --dist-root)
      dist_root="$2"
      shift 2
      ;;
    --config)
      config="$2"
      shift 2
      ;;
    --platform)
      platform="$2"
      shift 2
      ;;
    --arch)
      arch="$2"
      shift 2
      ;;
    --target-path)
      target_path="$2"
      shift 2
      ;;
    --time-window)
      time_window="$2"
      shift 2
      ;;
    --risk-mode)
      risk_mode="$2"
      shift 2
      ;;
    --baseline-level)
      baseline_level="$2"
      shift 2
      ;;
    --reachable-segments)
      reachable_segments="1"
      shift
      ;;
    --dry-run)
      dry_run="1"
      shift
      ;;
    --enforce-privilege)
      enforce_privilege="1"
      shift
      ;;
    --python)
      python_bin="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$goal" || -z "$workspace" ]]; then
  echo "--goal and --workspace are required" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runner="$script_dir/auto_triage.py"

args=(
  "$runner"
  --goal "$goal"
  --workspace "$workspace"
  --platform "$platform"
  --arch "$arch"
  --time-window "$time_window"
  --risk-mode "$risk_mode"
  --baseline-level "$baseline_level"
)

if [[ -n "$dist_root" ]]; then
  args+=(--dist-root "$dist_root")
fi
if [[ -n "$config" ]]; then
  args+=(--config "$config")
fi
if [[ -n "$target_path" ]]; then
  args+=(--target-path "$target_path")
fi
if [[ "$reachable_segments" == "1" ]]; then
  args+=(--reachable-segments)
fi
if [[ "$dry_run" == "1" ]]; then
  args+=(--dry-run)
fi
if [[ "$enforce_privilege" == "1" ]]; then
  args+=(--enforce-privilege)
fi

"$python_bin" "${args[@]}"
