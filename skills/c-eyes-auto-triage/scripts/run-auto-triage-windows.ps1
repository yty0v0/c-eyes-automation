param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("host-investigation", "file-alert-investigation", "network-investigation", "baseline-investigation")]
    [string]$Goal,
    [Parameter(Mandatory = $true)]
    [string]$Workspace,
    [string]$DistRoot,
    [string]$Config,
    [string]$Platform = "windows",
    [string]$Arch = "amd64",
    [string]$TargetPath,
    [string]$TimeWindow = "24h",
    [string]$RiskMode = "smart",
    [int]$BaselineLevel = 1,
    [switch]$ReachableSegments,
    [switch]$DryRun,
    [switch]$EnforcePrivilege,
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"

$runner = Join-Path $PSScriptRoot "auto_triage.py"
if (-not (Test-Path $runner)) {
    throw "runner not found: $runner"
}

$argsList = @(
    $runner,
    "--goal", $Goal,
    "--workspace", $Workspace,
    "--platform", $Platform,
    "--arch", $Arch,
    "--time-window", $TimeWindow,
    "--risk-mode", $RiskMode,
    "--baseline-level", "$BaselineLevel"
)

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
