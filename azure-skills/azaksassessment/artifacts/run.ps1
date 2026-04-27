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
    # Explicit subscription allowlists (forwarded to discover-scope.ps1).
    # Precedence: -SubscriptionIds > -SubscriptionNames > -SubscriptionPrefix.
    [string[]] $SubscriptionIds    = @(),
    [string[]] $SubscriptionNames  = @(),

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
    [switch] $DiagAksOnly,

    # Filename mode (per-sub HTML reports). Default = stable: each rerun
    # overwrites the prior file, since the per-run dated folder already
    # provides time/scope partitioning. Opt in to legacy timestamped names
    # via -TimestampedFilenames (e.g., when piping into a shared folder).
    [switch] $TimestampedFilenames,

    # Skip a phase if its primary artifact in -OutputDir is younger than
    # this many hours. 0 disables the freshness check (always collect).
    # -ForceRefresh always re-collects regardless.
    [int]    $MaxDataAgeHours = 24,
    [switch] $ForceRefresh
)

$ErrorActionPreference = "Stop"
$base = $PSScriptRoot

# Verify az CLI is available
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI (az) is required but not found. Install from https://learn.microsoft.com/cli/azure/install-azure-cli"
}

# ------------------------------------------------------------------
# Per-run output layout (rooted at <skill>/reports/, NOT under artifacts/):
#   azaksassessment/reports/<yyyy-MM-dd>_<CustomerName>/
#       <yyyy-MM-dd>_Data/      (all collection JSON / CSV)
#       <yyyy-MM-dd>_Reports/   (HTML reports + index.html)
# Keeps the read-only toolchain (artifacts/) cleanly separated from
# customer-specific output. CustomerName falls back to TenantName, then
# to RequiredTenantDomain's leading label, then to 'Customer'. All
# non-filesystem-safe chars are replaced with '-'.
# ------------------------------------------------------------------
$runDate = Get-Date -Format 'yyyy-MM-dd'
$rawCust = if ($TenantName)           { $TenantName }
           elseif ($RequiredTenantDomain) { ($RequiredTenantDomain -split '\.')[0] }
           else                       { 'Customer' }
$safeCust = ($rawCust -replace '[^A-Za-z0-9._-]', '-').Trim('-')
if (-not $safeCust) { $safeCust = 'Customer' }

# $base = artifacts/  ->  $reportsBase = ../reports/  (i.e. azaksassessment/reports/)
$reportsBase = Join-Path (Split-Path $base -Parent) 'reports'
$runRoot   = Join-Path $reportsBase ("{0}_{1}"      -f $runDate, $safeCust)
$dataDir   = Join-Path $runRoot     ("{0}_Data"     -f $runDate)
$reportDir = Join-Path $runRoot     ("{0}_Reports"  -f $runDate)
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

# ------------------------------------------------------------------
# Freshness short-circuit. A step is skipped when its primary artifact
# already exists in $dataDir AND its LastWriteTime is within
# $MaxDataAgeHours. -ForceRefresh disables the skip. Set
# -MaxDataAgeHours 0 to always re-collect.
# ------------------------------------------------------------------
function Test-Fresh {
    param([Parameter(Mandatory)][string]$PrimaryFile)
    if ($ForceRefresh)            { return $false }
    if ($MaxDataAgeHours -le 0)   { return $false }
    if (-not (Test-Path $PrimaryFile)) { return $false }
    $age = (Get-Date) - (Get-Item $PrimaryFile).LastWriteTime
    return ($age.TotalHours -lt $MaxDataAgeHours)
}
function Skip-IfFresh {
    param([string]$Name, [string]$PrimaryFile)
    if (Test-Fresh -PrimaryFile $PrimaryFile) {
        $ageH = ((Get-Date) - (Get-Item $PrimaryFile).LastWriteTime).TotalHours
        # Write-Host so these status lines don't pollute the function's return value
        # (which is the boolean used by the caller's `if (Skip-IfFresh ...)`).
        Write-Host ""
        Write-Host ("---- STEP: {0} (SKIP - fresh data, age {1:N1}h < {2}h) ----" -f $Name, $ageH, $MaxDataAgeHours)
        Write-Host ("     primary: {0}" -f $PrimaryFile)
        return $true
    }
    return $false
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
if (-not $SkipDiscover -and -not (Skip-IfFresh '2. discover-scope' (Join-Path $dataDir 'scope.json'))) {
    Step "2. discover-scope" { & (Join-Path $base "discover-scope.ps1") -RequiredTenantDomain $RequiredTenantDomain -SubscriptionPrefix $SubscriptionPrefix -SubscriptionIds $SubscriptionIds -SubscriptionNames $SubscriptionNames -OutputDir $dataDir }
}
if (-not $SkipCollect -and -not (Skip-IfFresh '3. collect-data' (Join-Path $dataDir 'arg-aks.json'))) {
    # Note: -SubscriptionPrefix filtering is applied only during discover-scope
    # and baked into scope.json. Downstream scripts read scope.json directly.
    Step "3. collect-data"   { & (Join-Path $base "collect-data.ps1") -RequiredTenantDomain $RequiredTenantDomain -OutputDir $dataDir -ScopeFile (Join-Path $dataDir 'scope.json') -DiagAksOnly:$DiagAksOnly }
}
if (-not $SkipEffective) {
    # Effective routes write per-cluster files (effective-routes-*.json); use the
    # newest matching file as the freshness signal.
    $erNewest = Get-ChildItem -Path $dataDir -Filter 'effective-routes-*.json' -EA SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not ($erNewest -and (Skip-IfFresh '4. collect-effective-routes' $erNewest.FullName))) {
        Step "4. collect-effective-routes" { & (Join-Path $base "collect-effective-routes.ps1") -RequiredTenantDomain $RequiredTenantDomain -OutputDir $dataDir }
    }
}
if (-not $SkipMetrics) {
    $mNewest = Get-ChildItem -Path $dataDir -Filter 'metrics-*.json' -EA SilentlyContinue |
               Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not ($mNewest -and (Skip-IfFresh '5. collect-metrics' $mNewest.FullName))) {
        Step "5. collect-metrics" { & (Join-Path $base "collect-metrics.ps1") -LookbackHours ($LookbackDays * 24) -RequiredTenantDomain $RequiredTenantDomain -OutputDir $dataDir }
    }
}
if (-not $SkipKql) {
    # Use the kql/ folder modification time (newest CSV anywhere under it).
    $kqlNewest = Get-ChildItem -Path (Join-Path $dataDir 'kql') -Recurse -Filter '*.csv' -EA SilentlyContinue |
                 Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not ($kqlNewest -and (Skip-IfFresh '6. collect-kql' $kqlNewest.FullName))) {
        Step "6. collect-kql"     { & (Join-Path $base "collect-kql.ps1") -OnpremPrefixes $OnpremPrefixes -LookbackDays $LookbackDays -RequiredTenantDomain $RequiredTenantDomain -OutputDir $dataDir }
    }
}
if (-not $SkipReports) {
    # Reports are deterministic from current data; always re-render so the
    # freshly-merged inputs (e.g., arg-law-resolved.json) are reflected. The
    # -StableFilename flag (default ON in run.ps1) makes the per-sub HTML
    # overwrite cleanly instead of accumulating timestamped duplicates.
    Step "7. generate-reports" {
        & (Join-Path $base "generate-reports.ps1") `
            -TenantName $TenantName `
            -RequiredTenantDomain $RequiredTenantDomain `
            -DataDir $dataDir `
            -OutputDir $reportDir `
            -StableFilename:(-not $TimestampedFilenames)
    }
}

Write-Output ""
Write-Output "=========================================================="
Write-Output (" Done. Run folder : {0}" -f $runRoot)
Write-Output ("        Data       : {0}" -f $dataDir)
Write-Output ("        Reports    : {0}" -f $reportDir)
Write-Output "=========================================================="


