#!/usr/bin/env bash
set -euo pipefail

workflow=""
workspace=""
dist_root=""
config=""
target_path=""
time_window="24h"
risk_mode="smart"
baseline_level="1"
reachable_segments="0"
dry_run="0"
download_only="0"
enforce_privilege="0"
python_bin="${PYTHON:-python3}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workflow)
      workflow="$2"
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
    --download-only)
      download_only="1"
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

if [[ "$download_only" != "1" && ( -z "$workflow" || -z "$workspace" ) ]]; then
  echo "--workflow and --workspace are required" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runner="$script_dir/ceyes_runner.py"

args=(
  "$runner"
  --platform linux
  --time-window "$time_window"
  --risk-mode "$risk_mode"
  --baseline-level "$baseline_level"
)

if [[ "$download_only" == "1" ]]; then
  args+=(--download-only)
else
  args+=(--workflow "$workflow" --workspace "$workspace")
fi

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
