#requires -Version 5.1
<#
.SYNOPSIS
  Read-only RBAC precheck for AzAKSAssessment.
  Verifies the analyst identity has the least-privilege Reader-class roles
  required to run the assessment, and explicitly warns if any write-capable
  role is held at the same scope (so we can document the elevated risk).

.DESCRIPTION
  This script performs READ-ONLY operations only:
    - az account list (enabled subs the user can see)
    - az role assignment list (assignee = current user)
    - resource graph query for AKS-bearing subscriptions

  No resources are created, modified, or deleted.

.PARAMETER SubscriptionIds
  Optional explicit list. If omitted, every enabled subscription visible to
  the caller is checked.

.PARAMETER OutputDir
  Where to drop the precheck CSV report. Default: <script>\data.

.NOTES
  Required roles (per scope):
    Reader, Monitoring Reader, Log Analytics Reader  -- subscription
    Azure Kubernetes Service Cluster User Role       -- per AKS cluster
  Conditional:
    Storage Blob Data Reader (flow log SAs without TA)
    Reader on Azure Firewall RG, Private DNS RG
    Microsoft Sentinel Reader (TI joins)
#>
[CmdletBinding()]
param(
    [string[]] $SubscriptionIds,
    [string]   $OutputDir   = (Join-Path $PSScriptRoot "data"),
    # Tenant guard. Script aborts if the current az context is not this tenant.
    [string]   $RequiredTenantDomain = '',
    [string]   $SubscriptionPrefix   = ''
)

$ErrorActionPreference = "Stop"

# ── READ-ONLY ENFORCEMENT ────────────────────────────────────────────
# This script (and the entire AzAKSAssessment assessment) MUST NOT perform
# any write, create, update, delete, patch, or modify operation against any
# Azure resource, Kubernetes object, diagnostic setting, alert rule, or
# anything else. Only the following verbs are permitted from this tooling:
#   az ... show | list | graph query
#   Get-Az* / Search-AzGraph / Invoke-AzOperationalInsightsQuery
#   kubectl get | describe | api-resources | api-versions   (read-only)
# Any contributor reviewing changes here must reject patches that introduce
# new-/set-/remove-/update-/add-/start-/stop-/restart-/invoke-action verbs.
Write-Output "[READ-ONLY] AzAKSAssessment performs zero writes/modifications."
Write-Output ""

# ── Required / forbidden role catalog ────────────────────────────────
$requiredSubRoles = @(
    'Reader',
    'Monitoring Reader',
    'Log Analytics Reader'
)
$conditionalRoles = @(
    'Storage Blob Data Reader',
    'Microsoft Sentinel Reader'
)
$writeCapableRoles = @(
    'Owner',
    'Contributor',
    'User Access Administrator',
    'Network Contributor',
    'Log Analytics Contributor',
    'Azure Kubernetes Service Cluster Admin Role',
    'Azure Kubernetes Service RBAC Cluster Admin',
    'Storage Blob Data Contributor',
    'Storage Blob Data Owner'
)

# ── Setup ────────────────────────────────────────────────────────────
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
$reportFile = Join-Path $OutputDir "precheck-rbac.csv"

Write-Output "=== AzAKSAssessment RBAC Precheck (read-only) ==="

# Confirm az CLI session
$account = az account show -o json 2>$null | ConvertFrom-Json
if (-not $account) {
    throw "Not logged in. Run 'az login' first."
}
$me = $account.user.name
Write-Output "Signed-in identity : $me"
Write-Output "Tenant             : $($account.tenantId)"

# ── Tenant guard (supports guest/external accounts) ──────────────────
$tenantDomain = $null
try { $tenantDomain = (az account show --query 'user.name' -o tsv) -replace '^[^@]+@','' } catch { }
if (-not $tenantDomain) { $tenantDomain = $account.tenantId }
if ($RequiredTenantDomain -and $tenantDomain -notmatch [regex]::Escape($RequiredTenantDomain)) {
    # UPN domain didn't match — resolve domain -> tenant ID for guest accounts
    $resolvedId = $null
    try {
        $oidc = Invoke-RestMethod "https://login.microsoftonline.com/$RequiredTenantDomain/v2.0/.well-known/openid-configuration" -ErrorAction Stop
        if ($oidc.issuer -match '/([a-f0-9-]{36})/') { $resolvedId = $matches[1] }
    } catch { }
    if ($resolvedId -and $account.tenantId -eq $resolvedId) {
        $tenantDomain = $RequiredTenantDomain
    } else {
        throw ("Tenant guard failed. Current tenant '{0}' (id={1}) != required '{2}'. Run: az login --tenant {2}" -f $tenantDomain, $account.tenantId, $RequiredTenantDomain)
    }
}
Write-Output "Tenant domain      : $tenantDomain"

# Resolve assignee object id (works for users, SPs, MIs)
$assigneeObjectId = $null
try {
    $assigneeObjectId = (az ad signed-in-user show --query id -o tsv 2>$null)
} catch { }
if (-not $assigneeObjectId) {
    # service principal context
    $assigneeObjectId = (az ad sp show --id $account.user.name --query id -o tsv 2>$null)
}
Write-Output "Assignee object id : $assigneeObjectId"

# ── Subscription list ────────────────────────────────────────────────
if ($SubscriptionIds) {
    $subs = az account list --query "[?state=='Enabled' && contains([$(($SubscriptionIds | ForEach-Object { '''' + $_ + '''' }) -join ',')], id)]" -o json | ConvertFrom-Json
} else {
    $subs = az account list --query "[?state=='Enabled']" -o json | ConvertFrom-Json
}
# Filter by tenant + optional name prefix
$subs = @($subs | Where-Object { $_.tenantId -eq $account.tenantId })
if ($SubscriptionPrefix) {
    $subs = @($subs | Where-Object { $_.name -like "$SubscriptionPrefix*" })
    Write-Output ("Sub prefix filter    : {0}*" -f $SubscriptionPrefix)
}
Write-Output ""
Write-Output ("Subscriptions visible : {0}" -f $subs.Count)
$subs | ForEach-Object { Write-Output ("  {0}  {1}" -f $_.id, $_.name) }
Write-Output ""

# ── Discover which subs actually contain AKS clusters ────────────────
Write-Output "Discovering AKS-bearing subscriptions via Resource Graph..."
$argQuery = "resources | where type =~ 'microsoft.containerservice/managedclusters' | summarize clusters=count() by subscriptionId"
$aksSubsRaw = az graph query -q $argQuery --subscriptions ($subs.id) --first 1000 -o json 2>$null | ConvertFrom-Json
$aksSubs    = @{}
if ($aksSubsRaw -and $aksSubsRaw.data) {
    foreach ($row in $aksSubsRaw.data) { $aksSubs[$row.subscriptionId] = [int]$row.clusters }
}
Write-Output ("AKS-bearing subs      : {0}" -f $aksSubs.Count)
$aksSubs.GetEnumerator() | Sort-Object Name | ForEach-Object {
    $name = ($subs | Where-Object id -eq $_.Key).name
    Write-Output ("  {0}  {1}  clusters={2}" -f $_.Key, $name, $_.Value)
}
Write-Output ""

# ── Per-subscription role check ──────────────────────────────────────
$results = New-Object System.Collections.Generic.List[object]

foreach ($sub in $subs) {
    $isAksSub = $aksSubs.ContainsKey($sub.id)
    $subScope = "/subscriptions/$($sub.id)"
    Write-Output ("--- Sub: {0}  ({1})  AKS={2}" -f $sub.name, $sub.id, $isAksSub)

    $assignments = az role assignment list `
        --assignee $assigneeObjectId `
        --scope $subScope `
        --include-inherited `
        --include-groups `
        -o json 2>$null | ConvertFrom-Json

    $heldRoles = @($assignments | ForEach-Object { $_.roleDefinitionName } | Sort-Object -Unique)

    $missingRequired = @($requiredSubRoles | Where-Object { $heldRoles -notcontains $_ })
    $heldWrite       = @($writeCapableRoles | Where-Object { $heldRoles -contains $_ })

    $status = if ($missingRequired.Count -eq 0) { 'OK' } else { 'MISSING_REQUIRED' }
    if ($heldWrite.Count -gt 0) { $status = 'OK_WITH_WRITE_WARNING' }

    Write-Output ("    Roles held      : {0}" -f ($heldRoles -join '; '))
    if ($missingRequired) { Write-Output ("    MISSING required: {0}" -f ($missingRequired -join ', ')) }
    if ($heldWrite)       { Write-Output ("    WARN write roles: {0}" -f ($heldWrite -join ', ')) }

    $results.Add([pscustomobject]@{
        SubscriptionId   = $sub.id
        SubscriptionName = $sub.name
        IsAksBearing     = $isAksSub
        AksClusterCount  = if ($isAksSub) { $aksSubs[$sub.id] } else { 0 }
        Status           = $status
        RolesHeld        = ($heldRoles -join '; ')
        MissingRequired  = ($missingRequired -join '; ')
        WriteRolesHeld   = ($heldWrite -join '; ')
    })
}

$results | Export-Csv -Path $reportFile -NoTypeInformation -Encoding UTF8

# ── Summary ──────────────────────────────────────────────────────────
Write-Output ""
Write-Output "=== Summary ==="
$summary = $results | Group-Object Status | Select-Object Name, Count
$summary | Format-Table -AutoSize | Out-String | Write-Output

$blockingAks = $results | Where-Object { $_.IsAksBearing -and $_.Status -eq 'MISSING_REQUIRED' }
if ($blockingAks) {
    Write-Warning ("AKS-bearing subscriptions with missing required roles ({0}):" -f $blockingAks.Count)
    $blockingAks | Select-Object SubscriptionName, SubscriptionId, MissingRequired |
        Format-Table -AutoSize | Out-String | Write-Output
    Write-Warning "Grant the missing roles before running collect-data.ps1."
}

Write-Output ("Report : {0}" -f $reportFile)
Write-Output "Done."
