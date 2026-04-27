#requires -Version 5.1
<#
.SYNOPSIS
  AzAKSAssessment orchestrator. READ-ONLY end-to-end run.

.DESCRIPTION
  Runs all phases in order:
    1. precheck.ps1                 (RBAC self-check)
    2. discover-scope.ps1           (find AKS subs + peer + connectivity)
    3. collect-data.ps1             (Phase 0+1 ARG inventory)
    4. collect-effective-routes.ps1 (effective routes + NSGs per nodepool)
    5. collect-metrics.ps1          (LB/NATGW/FW capacity metrics)
    6. collect-kql.ps1              (run Queries.kql per workspace)
    7. generate-reports.ps1         (one HTML per AKS-bearing sub)

  Skip individual phases with -Skip switches.

.PARAMETER OnpremPrefixes
  CIDR list of on-prem ranges, comma-separated.
  Example: '10.0.0.0/8,192.168.0.0/16'
.PARAMETER LookbackDays
  Time window for metrics + KQL. Default 7.
#>
[CmdletBinding()]
param(
    [string] $OnpremPrefixes       = '',
    [int]    $LookbackDays         = 7,
    [string] $TenantName           = '',
    [string] $RequiredTenantDomain = '',
    [string] $SubscriptionPrefix   = '',

    [switch] $SkipPrecheck,
    [switch] $SkipDiscover,
    [switch] $SkipCollect,
    [switch] $SkipEffective,
    [switch] $SkipMetrics,
    [switch] $SkipKql,
    [switch] $SkipReports
)

$ErrorActionPreference = "Stop"
$base = $PSScriptRoot

# Verify az CLI is available
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI (az) is required but not found. Install from https://learn.microsoft.com/cli/azure/install-azure-cli"
}

Write-Output "=========================================================="
Write-Output " AzAKSAssessment - READ-ONLY end-to-end run"
Write-Output (" Tenant required : {0}" -f $RequiredTenantDomain)
Write-Output (" Lookback        : {0} days" -f $LookbackDays)
Write-Output (" On-prem prefixes: {0}" -f $(if ($OnpremPrefixes) { $OnpremPrefixes } else { '<none>' }))
Write-Output (" Sub prefix      : {0}" -f $(if ($SubscriptionPrefix) { $SubscriptionPrefix } else { '<all>' }))
Write-Output "=========================================================="

function Step($name, [scriptblock]$body) {
    Write-Output ""
    Write-Output ("---- STEP: {0} ----" -f $name)
    $global:LASTEXITCODE = 0
    & $body
    if ($LASTEXITCODE -gt 0) {
        Write-Warning ("Step '{0}' exited with code {1} (continuing — may be az CLI warnings)." -f $name, $LASTEXITCODE)
        $global:LASTEXITCODE = 0
    }
}

if (-not $SkipPrecheck) {
    # Precheck is advisory — warn but don't abort on non-zero exit
    Write-Output ""
    Write-Output "---- STEP: 1. precheck ----"
    & (Join-Path $base "precheck.ps1") -RequiredTenantDomain $RequiredTenantDomain -SubscriptionPrefix $SubscriptionPrefix
    if ($LASTEXITCODE -gt 0) { Write-Warning ("Precheck exited with code {0} (advisory only — continuing)." -f $LASTEXITCODE) }
    $LASTEXITCODE = 0
}
if (-not $SkipDiscover) {
    Step "2. discover-scope" { & (Join-Path $base "discover-scope.ps1") -RequiredTenantDomain $RequiredTenantDomain -SubscriptionPrefix $SubscriptionPrefix }
}
if (-not $SkipCollect) {
    # Note: -SubscriptionPrefix filtering is applied only during discover-scope
    # and baked into scope.json. Downstream scripts read scope.json directly.
    Step "3. collect-data"   { & (Join-Path $base "collect-data.ps1") -RequiredTenantDomain $RequiredTenantDomain }
}
if (-not $SkipEffective) {
    Step "4. collect-effective-routes" { & (Join-Path $base "collect-effective-routes.ps1") -RequiredTenantDomain $RequiredTenantDomain }
}
if (-not $SkipMetrics) {
    Step "5. collect-metrics" { & (Join-Path $base "collect-metrics.ps1") -LookbackHours ($LookbackDays * 24) -RequiredTenantDomain $RequiredTenantDomain }
}
if (-not $SkipKql) {
    Step "6. collect-kql"     { & (Join-Path $base "collect-kql.ps1") -OnpremPrefixes $OnpremPrefixes -LookbackDays $LookbackDays -RequiredTenantDomain $RequiredTenantDomain }
}
if (-not $SkipReports) {
    Step "7. generate-reports" { & (Join-Path $base "generate-reports.ps1") -TenantName $TenantName -RequiredTenantDomain $RequiredTenantDomain }
}

Write-Output ""
Write-Output "=========================================================="
Write-Output " Done. Reports: $(Join-Path $base 'reports')"
Write-Output "=========================================================="
