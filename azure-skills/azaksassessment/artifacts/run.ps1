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
    [switch] $SkipReports,

    # Advisory by default. When set, a precheck failure aborts the run.
    [switch] $StrictPrecheck,
    # Forwarded to collect-data.ps1 — limits Phase 2 diagnostics to AKS targets only.
    [switch] $DiagAksOnly
)

$ErrorActionPreference = "Stop"
$base = $PSScriptRoot

# Verify az CLI is available
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI (az) is required but not found. Install from https://learn.microsoft.com/cli/azure/install-azure-cli"
}

# ------------------------------------------------------------------
# Per-run output layout:
#   <artifacts>/<yyyy-MM-dd>_<CustomerName>/
#       <yyyy-MM-dd>_Data/      (all collection JSON / CSV)
#       <yyyy-MM-dd>_Reports/   (HTML reports + index.html)
# CustomerName falls back to TenantName, then to RequiredTenantDomain's
# leading label, then to 'Customer'. All non-filesystem-safe chars are
# replaced with '-'.
# ------------------------------------------------------------------
$runDate = Get-Date -Format 'yyyy-MM-dd'
$rawCust = if ($TenantName)           { $TenantName }
           elseif ($RequiredTenantDomain) { ($RequiredTenantDomain -split '\.')[0] }
           else                       { 'Customer' }
$safeCust = ($rawCust -replace '[^A-Za-z0-9._-]', '-').Trim('-')
if (-not $safeCust) { $safeCust = 'Customer' }

$runRoot   = Join-Path $base    ("{0}_{1}"      -f $runDate, $safeCust)
$dataDir   = Join-Path $runRoot ("{0}_Data"     -f $runDate)
$reportDir = Join-Path $runRoot ("{0}_Reports"  -f $runDate)
New-Item -ItemType Directory -Force -Path $dataDir, $reportDir | Out-Null

Write-Output "=========================================================="
Write-Output " AzAKSAssessment - READ-ONLY end-to-end run"
Write-Output (" Tenant required : {0}" -f $RequiredTenantDomain)
Write-Output (" Lookback        : {0} days" -f $LookbackDays)
Write-Output (" On-prem prefixes: {0}" -f $(if ($OnpremPrefixes) { $OnpremPrefixes } else { '<none>' }))
Write-Output (" Sub prefix      : {0}" -f $(if ($SubscriptionPrefix) { $SubscriptionPrefix } else { '<all>' }))
Write-Output (" Run folder      : {0}" -f $runRoot)
Write-Output "=========================================================="

function Step($name, [scriptblock]$body) {
    Write-Output ""
    Write-Output ("---- STEP: {0} ----" -f $name)
    $global:LASTEXITCODE = 0
    try {
        & $body
    } catch {
        # Downgrade terminating exceptions from a child step to a warning so the
        # rest of the assessment (other steps, report generation) can proceed.
        Write-Warning ("Step '{0}' threw a terminating error and was skipped: {1}" -f $name, $_.Exception.Message)
        $global:LASTEXITCODE = 0
        return
    }
    if ($LASTEXITCODE -gt 0) {
        Write-Warning ("Step '{0}' exited with code {1} (continuing — may be az CLI warnings)." -f $name, $LASTEXITCODE)
        $global:LASTEXITCODE = 0
    }
}

if (-not $SkipPrecheck) {
    # Precheck is advisory — warn but don't abort on non-zero exit OR on a
    # terminating exception (e.g., AADSTS530004 from a tenant CA / compliance
    # restriction). Use -StrictPrecheck to opt in to abort behavior (e.g., CI).
    Write-Output ""
    Write-Output "---- STEP: 1. precheck ----"
    try {
        & (Join-Path $base "precheck.ps1") -RequiredTenantDomain $RequiredTenantDomain -SubscriptionPrefix $SubscriptionPrefix -OutputDir $dataDir
        if ($LASTEXITCODE -gt 0) { Write-Warning ("Precheck exited with code {0} (advisory only — continuing)." -f $LASTEXITCODE) }
    } catch {
        if ($StrictPrecheck) {
            throw
        } else {
            Write-Warning ("Precheck threw a terminating error and was downgraded to a warning: {0}" -f $_.Exception.Message)
            Write-Warning  "Re-run with -StrictPrecheck to abort on precheck failure."
        }
    }
    $LASTEXITCODE = 0
}
if (-not $SkipDiscover) {
    Step "2. discover-scope" { & (Join-Path $base "discover-scope.ps1") -RequiredTenantDomain $RequiredTenantDomain -SubscriptionPrefix $SubscriptionPrefix -OutputDir $dataDir }
}
if (-not $SkipCollect) {
    # Note: -SubscriptionPrefix filtering is applied only during discover-scope
    # and baked into scope.json. Downstream scripts read scope.json directly.
    Step "3. collect-data"   { & (Join-Path $base "collect-data.ps1") -RequiredTenantDomain $RequiredTenantDomain -OutputDir $dataDir -ScopeFile (Join-Path $dataDir 'scope.json') -DiagAksOnly:$DiagAksOnly }
}
if (-not $SkipEffective) {
    Step "4. collect-effective-routes" { & (Join-Path $base "collect-effective-routes.ps1") -RequiredTenantDomain $RequiredTenantDomain -OutputDir $dataDir }
}
if (-not $SkipMetrics) {
    Step "5. collect-metrics" { & (Join-Path $base "collect-metrics.ps1") -LookbackHours ($LookbackDays * 24) -RequiredTenantDomain $RequiredTenantDomain -OutputDir $dataDir }
}
if (-not $SkipKql) {
    Step "6. collect-kql"     { & (Join-Path $base "collect-kql.ps1") -OnpremPrefixes $OnpremPrefixes -LookbackDays $LookbackDays -RequiredTenantDomain $RequiredTenantDomain -OutputDir $dataDir }
}
if (-not $SkipReports) {
    Step "7. generate-reports" { & (Join-Path $base "generate-reports.ps1") -TenantName $TenantName -RequiredTenantDomain $RequiredTenantDomain -DataDir $dataDir -OutputDir $reportDir }
}

Write-Output ""
Write-Output "=========================================================="
Write-Output (" Done. Run folder : {0}" -f $runRoot)
Write-Output ("        Data       : {0}" -f $dataDir)
Write-Output ("        Reports    : {0}" -f $reportDir)
Write-Output "=========================================================="


