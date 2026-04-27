#requires -Version 5.1
<#
.SYNOPSIS
  AzAKSAssessment precheck. READ-ONLY self-check of prerequisites.

.DESCRIPTION
  Verifies, before the long-running collection phases:
    1. az CLI present and logged in.
    2. Tenant guard: current az context matches -RequiredTenantDomain
       (when supplied). Supports guest accounts via OIDC tenant-id resolution.
    3. At least one enabled subscription is visible in the required tenant
       (after optional -SubscriptionPrefix filter).
    4. AKS clusters exist in scope (via Resource Graph).
    5. Resource provider state for Microsoft.ContainerService /
       Microsoft.Network / Microsoft.OperationalInsights per AKS-bearing sub
       (advisory only — Reader is enough to query providers).
    6. AKS diagnostic-settings -> Log Analytics workspace coverage probe.
       This is the most common reason the KQL exfiltration hunt produces
       zero output, so we surface it BEFORE running phases 2-6.

  All findings are advisory unless run.ps1 is invoked with -StrictPrecheck.
  The script exits 0 even on warnings; non-zero only on a usage error
  (e.g., az missing entirely).

.PARAMETER RequiredTenantDomain
  Tenant domain or GUID to match against `az account show`. When empty,
  the tenant guard is skipped.
.PARAMETER SubscriptionPrefix
  Name prefix filter applied to enabled subscriptions in the tenant.
.PARAMETER OutputDir
  Where to write precheck-summary.json. Default: <script>\data
#>
[CmdletBinding()]
param(
    [string] $RequiredTenantDomain = '',
    [string] $SubscriptionPrefix   = '',
    # When empty, lazy-resolve to azaksassessment\reports\<date>_<Customer>\<date>_Data
    [string] $TenantName           = '',
    [string] $OutputDir            = ''
)

# Precheck is advisory by design. Don't auto-throw on warnings.
$ErrorActionPreference = 'Continue'

# Lazy default: when -OutputDir is not supplied, materialize the same per-run
# dated layout that run.ps1 uses: azaksassessment/reports/<date>_<Cust>/<date>_Data
if (-not $OutputDir) {
    $rawCust = if ($TenantName)            { $TenantName }
               elseif ($RequiredTenantDomain) { ($RequiredTenantDomain -split '\.')[0] }
               else                        { 'Customer' }
    $safeCust = ($rawCust -replace '[^A-Za-z0-9._-]', '-').Trim('-')
    if (-not $safeCust) { $safeCust = 'Customer' }
    $runDate     = Get-Date -Format 'yyyy-MM-dd'
    $reportsBase = Join-Path (Split-Path $PSScriptRoot -Parent) 'reports'
    $OutputDir   = Join-Path $reportsBase (("{0}_{1}" -f $runDate, $safeCust) + '\' + ("{0}_Data" -f $runDate))
}
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

Write-Output "[READ-ONLY] AzAKSAssessment precheck (no Azure writes)."
Write-Output "=== AzAKSAssessment Precheck ==="

$summary = [ordered]@{
    timestamp           = (Get-Date).ToString('o')
    tenantOk            = $false
    tenantDomain        = ''
    tenantId            = ''
    visibleSubs         = 0
    aksSubs             = 0
    aksClusters         = 0
    providerWarnings    = @()
    lawCoverage         = [ordered]@{ probedSubs=0; subsWithLaw=0; subsWithoutLaw=@() }
    warnings            = New-Object System.Collections.Generic.List[string]
}

# ── Step 1: az CLI present + logged in ───────────────────────────────
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Warning "Azure CLI (az) is required but not found. Install: https://learn.microsoft.com/cli/azure/install-azure-cli"
    $summary.warnings.Add('az-cli-missing') | Out-Null
    $summary | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputDir 'precheck-summary.json') -Encoding utf8
    exit 0
}
$ctx = az account show --only-show-errors -o json 2>$null | ConvertFrom-Json
if (-not $ctx) {
    Write-Warning "Not logged in. Run: az login --tenant $RequiredTenantDomain"
    $summary.warnings.Add('not-logged-in') | Out-Null
    $summary | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputDir 'precheck-summary.json') -Encoding utf8
    exit 0
}

# ── Step 2: Tenant guard (supports guest accounts) ───────────────────
$tenantDomain = ($ctx.user.name -replace '^[^@]+@','')
if (-not $tenantDomain) { $tenantDomain = $ctx.tenantId }
$summary.tenantId = $ctx.tenantId
$summary.tenantDomain = $tenantDomain
if ($RequiredTenantDomain -and $tenantDomain -notmatch [regex]::Escape($RequiredTenantDomain)) {
    $resolvedId = $null
    try {
        $oidc = Invoke-RestMethod "https://login.microsoftonline.com/$RequiredTenantDomain/v2.0/.well-known/openid-configuration" -ErrorAction Stop
        if ($oidc.issuer -match '/([a-f0-9-]{36})/') { $resolvedId = $matches[1] }
    } catch { }
    if ($resolvedId -and $ctx.tenantId -eq $resolvedId) {
        $tenantDomain = $RequiredTenantDomain
        $summary.tenantDomain = $tenantDomain
    } else {
        Write-Warning ("Tenant guard FAILED. Current '{0}' (id={1}) != required '{2}'. Run: az login --tenant {2}" -f $tenantDomain, $ctx.tenantId, $RequiredTenantDomain)
        $summary.warnings.Add('tenant-mismatch') | Out-Null
        $summary | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputDir 'precheck-summary.json') -Encoding utf8
        exit 0
    }
}
$summary.tenantOk = $true
Write-Output ("Tenant            : {0}  ({1})" -f $tenantDomain, $ctx.tenantId)

# ── Step 3: visible enabled subs in tenant ───────────────────────────
$allSubs = az account list --only-show-errors --query "[?state=='Enabled']" -o json 2>$null | ConvertFrom-Json
$allSubs = @($allSubs | Where-Object { $_.tenantId -eq $ctx.tenantId })
if ($SubscriptionPrefix) { $allSubs = @($allSubs | Where-Object { $_.name -like "$SubscriptionPrefix*" }) }
$summary.visibleSubs = $allSubs.Count
Write-Output ("Visible subs       : {0}{1}" -f $allSubs.Count, $(if ($SubscriptionPrefix) { " (prefix '$SubscriptionPrefix*')" } else { '' }))
if ($allSubs.Count -eq 0) {
    Write-Warning "No subscriptions visible in this tenant after filtering."
    $summary.warnings.Add('no-subs-visible') | Out-Null
    $summary | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputDir 'precheck-summary.json') -Encoding utf8
    exit 0
}

# ── Step 4: AKS clusters via ARG ─────────────────────────────────────
$subIds = @($allSubs.id)
$aksRaw = az graph query -q "resources | where type =~ 'microsoft.containerservice/managedclusters' | project id, name, subscriptionId" `
    --subscriptions $subIds --first 1000 --only-show-errors -o json 2>$null
$aksRows = if ($aksRaw) { ($aksRaw | ConvertFrom-Json).data } else { @() }
$aksSubs = @($aksRows | Select-Object -ExpandProperty subscriptionId -Unique)
$summary.aksSubs     = $aksSubs.Count
$summary.aksClusters = @($aksRows).Count
Write-Output ("AKS clusters       : {0} across {1} sub(s)" -f $summary.aksClusters, $summary.aksSubs)
if ($summary.aksClusters -eq 0) {
    Write-Warning "No AKS clusters found in scope. The assessment will produce an empty report."
    $summary.warnings.Add('no-aks-clusters') | Out-Null
    $summary | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputDir 'precheck-summary.json') -Encoding utf8
    exit 0
}

# ── Step 5: Provider state per AKS sub (advisory) ────────────────────
$requiredProviders = @('Microsoft.ContainerService','Microsoft.Network','Microsoft.OperationalInsights')
foreach ($sid in $aksSubs) {
    foreach ($prov in $requiredProviders) {
        $state = az provider show --namespace $prov --subscription $sid --query registrationState --only-show-errors -o tsv 2>$null
        if ($state -and $state -ne 'Registered') {
            $msg = ("provider {0} is '{1}' in sub {2}" -f $prov, $state, $sid)
            Write-Warning $msg
            $summary.providerWarnings += $msg
        }
    }
}
if (-not $summary.providerWarnings) {
    Write-Output "Providers          : Registered (Microsoft.ContainerService / Network / OperationalInsights)"
}

# ── Step 6: AKS diagnostic-settings -> LAW coverage probe (Gap 5) ────
# We probe a sample of up to 3 AKS resources per sub. If none have a
# workspaceId-bound diagnostic setting, the KQL exfil hunt will be a no-op.
Write-Output ""
Write-Output "Probing AKS diag settings -> Log Analytics coverage..."
$summary.lawCoverage.probedSubs = $aksSubs.Count
foreach ($sid in $aksSubs) {
    $clustersInSub = @($aksRows | Where-Object subscriptionId -eq $sid | Select-Object -First 3)
    $hasLaw = $false
    foreach ($c in $clustersInSub) {
        $diagRaw = az monitor diagnostic-settings list --resource $c.id --only-show-errors -o json 2>$null
        if ($diagRaw) {
            $diag = $diagRaw | ConvertFrom-Json
            if (@($diag.value | Where-Object { $_.workspaceId })) { $hasLaw = $true; break }
        }
    }
    if ($hasLaw) {
        $summary.lawCoverage.subsWithLaw++
        Write-Output ("  sub {0} : LAW-bound diag settings detected" -f $sid)
    } else {
        $summary.lawCoverage.subsWithoutLaw += $sid
        Write-Warning ("  sub {0} : NO Log Analytics workspace bound to AKS diag settings (sampled <=3 clusters). KQL phase will produce zero output for this sub." -f $sid)
    }
}
if ($summary.lawCoverage.subsWithoutLaw.Count -gt 0) {
    Write-Warning ""
    Write-Warning ("LAW coverage gap: {0}/{1} AKS sub(s) lack workspace-bound diagnostic settings." -f $summary.lawCoverage.subsWithoutLaw.Count, $aksSubs.Count)
    Write-Warning  "  The KQL exfiltration hunt requires AKS diag settings to forward to a Log Analytics workspace."
    Write-Warning  "  Read-only doc snippet (operator must run separately, NOT executed here):"
    Write-Warning  "    az monitor diagnostic-settings create --name aks-to-law --resource <aks-id> ``"
    Write-Warning  "        --workspace <law-id> --logs '[{`"category`":`"kube-apiserver`",`"enabled`":true},{`"category`":`"kube-audit`",`"enabled`":true},{`"category`":`"guard`",`"enabled`":true}]'"
    $summary.warnings.Add('law-coverage-gap') | Out-Null
}

# ── Persist summary ──────────────────────────────────────────────────
$summary | ConvertTo-Json -Depth 8 | Out-File (Join-Path $OutputDir 'precheck-summary.json') -Encoding utf8
Write-Output ""
Write-Output ("Precheck summary  : {0}" -f (Join-Path $OutputDir 'precheck-summary.json'))
if ($summary.warnings.Count -gt 0) {
    Write-Warning ("Precheck completed with {0} advisory warning(s). Re-run run.ps1 with -StrictPrecheck to abort on these." -f $summary.warnings.Count)
} else {
    Write-Output  "Precheck OK."
}
exit 0
