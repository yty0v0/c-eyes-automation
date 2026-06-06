$ErrorActionPreference = "Stop"
$runner = Join-Path $PSScriptRoot "..\..\c-eyes-orchestrator\scripts\run-ceyes-windows.ps1"
$runner = [System.IO.Path]::GetFullPath($runner)

if (-not (Test-Path $runner)) {
    throw "runner not found: $runner"
}

& $runner -Workflow host-triage @args
exit $LASTEXITCODE
