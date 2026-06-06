#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
runner="$script_dir/../../c-eyes-orchestrator/scripts/run-ceyes-linux.sh"

if [[ ! -f "$runner" ]]; then
  echo "runner not found: $runner" >&2
  exit 1
fi

exec bash "$runner" --workflow host-triage "$@"
