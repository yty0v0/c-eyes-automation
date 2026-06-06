param(
    [ValidateSet("host-triage", "filescan-risk", "eventlog-timeline", "network-inventory", "sbom-inventory", "baseline-check")]
    [string]$Workflow,
    [string]$Workspace,
    [string]$DistRoot,
    [string]$Config,
    [string]$TargetPath,
    [string]$TimeWindow = "24h",
    [string]$RiskMode = "smart",
    [int]$BaselineLevel = 1,
    [switch]$ReachableSegments,
    [switch]$DryRun,
    [switch]$DownloadOnly,
    [switch]$EnforcePrivilege,
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"

$runner = Join-Path $PSScriptRoot "ceyes_runner.py"
if (-not (Test-Path $runner)) {
    throw "runner not found: $runner"
}

$argsList = @(
    $runner,
    "--platform", "windows",
    "--time-window", $TimeWindow,
    "--risk-mode", $RiskMode,
    "--baseline-level", "$BaselineLevel"
)

if ($DownloadOnly) {
    $argsList += "--download-only"
}
else {
    if (-not $Workflow -or -not $Workspace) {
        throw "-Workflow and -Workspace are required unless -DownloadOnly is set"
    }
    $argsList += @("--workflow", $Workflow, "--workspace", $Workspace)
}

if ($DistRoot) {
    $argsList += @("--dist-root", $DistRoot)
}
if ($Config) {
    $argsList += @("--config", $Config)
}
if ($TargetPath) {
    $argsList += @("--target-path", $TargetPath)
}
if ($ReachableSegments) {
    $argsList += "--reachable-segments"
}
if ($DryRun) {
    $argsList += "--dry-run"
}
if ($EnforcePrivilege) {
    $argsList += "--enforce-privilege"
}

& $Python @argsList
exit $LASTEXITCODE
