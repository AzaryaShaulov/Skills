#requires -Version 5.1
<#
.SYNOPSIS
  Discovers the in-scope subscriptions for AzAKSAssessment:
    1. Every subscription containing one or more AKS clusters (primary).
    2. Subscriptions of any VNets peered to a cluster VNet (auto-included).
    3. Subscriptions hosting ExpressRoute / VPN gateways referenced by those
       VNets or by remote peered VNets (connectivity / hub).

  Emits scope.json describing roles per subscription. One report will be
  generated per "primary" (AKS-bearing) subscription; "peer" and
  "connectivity" subs are collected for context only.

.DESCRIPTION
  READ-ONLY. Uses Azure Resource Graph (Reader on the visible subs is enough).
  No resources created or modified.

.PARAMETER OutputDir
  Default: <script>\data
#>
[CmdletBinding()]
param(
    [string]   $OutputDir            = '',
    [string]   $TenantName           = '',
    [string]   $RequiredTenantDomain = '',
    [string]   $SubscriptionPrefix   = '',
    # Explicit allowlists. Precedence (highest first):
    #   -SubscriptionIds  (sub GUIDs, exact match)
    #   -SubscriptionNames (display names, exact match, case-insensitive)
    #   -SubscriptionPrefix (legacy name-prefix wildcard)
    # When -SubscriptionIds is non-empty the other two are ignored.
    [string[]] $SubscriptionIds      = @(),
    [string[]] $SubscriptionNames    = @()
)

$ErrorActionPreference = "Stop"

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

# ── READ-ONLY ENFORCEMENT ────────────────────────────────────────────
# This script performs zero writes. Only Resource Graph + az ... show/list.
Write-Output "[READ-ONLY] AzAKSAssessment scope discovery (no writes performed)."

# ── Tenant guard (supports guest/external accounts) ──────────────────
$ctx = az account show --only-show-errors -o json 2>$null | ConvertFrom-Json
if (-not $ctx) { throw "Not logged in. Run: az login --tenant $RequiredTenantDomain" }
$tenantDomain = ($ctx.user.name -replace '^[^@]+@','')
if (-not $tenantDomain) { $tenantDomain = $ctx.tenantId }
if ($RequiredTenantDomain -and $tenantDomain -notmatch [regex]::Escape($RequiredTenantDomain)) {
    $resolvedId = $null
    try {
        $oidc = Invoke-RestMethod "https://login.microsoftonline.com/$RequiredTenantDomain/v2.0/.well-known/openid-configuration" -ErrorAction Stop
        if ($oidc.issuer -match '/([a-f0-9-]{36})/') { $resolvedId = $matches[1] }
    } catch { }
    if ($resolvedId -and $ctx.tenantId -eq $resolvedId) {
        $tenantDomain = $RequiredTenantDomain
    } else {
        throw ("Tenant guard failed. Current tenant '{0}' (id={1}) != required '{2}'. Run: az login --tenant {2}" -f $tenantDomain, $ctx.tenantId, $RequiredTenantDomain)
    }
}

Write-Output "=== AzAKSAssessment Scope Discovery (read-only) ==="
Write-Output ("Tenant            : {0}  ({1})" -f $tenantDomain, $ctx.tenantId)

# ── All visible enabled subs ─────────────────────────────────────────
$allSubs = az account list --only-show-errors --query "[?state=='Enabled']" -o json 2>$null | ConvertFrom-Json
if (-not $allSubs) { throw "No enabled subscriptions visible. Run 'az login'." }
# Filter by tenant + optional name prefix
$allSubs = @($allSubs | Where-Object { $_.tenantId -eq $ctx.tenantId })
if ($SubscriptionIds -and $SubscriptionIds.Count -gt 0) {
    $allSubs = @($allSubs | Where-Object { $SubscriptionIds -contains $_.id })
    Write-Output ("Sub allowlist (Ids)  : {0} entr(y/ies)" -f $SubscriptionIds.Count)
} elseif ($SubscriptionNames -and $SubscriptionNames.Count -gt 0) {
    $namesLower = $SubscriptionNames | ForEach-Object { $_.ToLower() }
    $allSubs = @($allSubs | Where-Object { $namesLower -contains $_.name.ToLower() })
    Write-Output ("Sub allowlist (Names): {0} entr(y/ies)" -f $SubscriptionNames.Count)
} elseif ($SubscriptionPrefix) {
    $allSubs = @($allSubs | Where-Object { $_.name -like "$SubscriptionPrefix*" })
    Write-Output ("Sub prefix filter    : {0}*" -f $SubscriptionPrefix)
}
if (-not $allSubs -or $allSubs.Count -eq 0) { throw "No matching subscriptions after filtering." }
$allSubIds  = @($allSubs.id)
$subNameMap = @{}
foreach ($s in $allSubs) { $subNameMap[$s.id] = $s.name }
Write-Output ("Visible enabled subs : {0}" -f $allSubs.Count)

# ── ARG helper ───────────────────────────────────────────────────────
function Invoke-Arg {
    param([string]$Query, [Parameter(Mandatory)][string[]]$Subs)
    $flatQuery = ($Query -replace '\r?\n',' ').Trim()
    $raw = az graph query -q $flatQuery --subscriptions $Subs --first 1000 --only-show-errors -o json 2>$null
    if (-not $raw) { return @() }
    $parsed = $raw | ConvertFrom-Json
    if (-not $parsed.data) { return @() }
    return $parsed.data
}

# ── 1. AKS-bearing subs ──────────────────────────────────────────────
Write-Output "`nStep 1: enumerating AKS clusters across visible subs..."
$aksRows = Invoke-Arg -Subs $allSubIds -Query @"
resources
| where type =~ 'microsoft.containerservice/managedclusters'
| project id, name, subscriptionId, resourceGroup, location,
    nodeResourceGroup = tostring(properties.nodeResourceGroup),
    networkPlugin     = tostring(properties.networkProfile.networkPlugin),
    networkPolicy     = tostring(properties.networkProfile.networkPolicy),
    outboundType      = tostring(properties.networkProfile.outboundType),
    apiServerPrivate  = tobool(properties.apiServerAccessProfile.enablePrivateCluster),
    agentPools        = properties.agentPoolProfiles
"@

if (-not $aksRows -or $aksRows.Count -eq 0) {
    Write-Warning "No AKS clusters found in any visible subscription. Nothing to do."
    @{ aksSubscriptions = @(); peerSubscriptions = @(); connectivitySubscriptions = @(); aksClusters = @() } |
        ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputDir "scope.json") -Encoding utf8
    return
}

# Filter to only subs in our visible/filtered list (drop cross-tenant phantom results)
$aksRows = @($aksRows | Where-Object { $allSubIds -contains $_.subscriptionId })
if (-not $aksRows -or $aksRows.Count -eq 0) {
    Write-Warning "ARG returned AKS clusters but none in the filtered subscription list. Nothing to do."
    @{ aksSubscriptions = @(); peerSubscriptions = @(); connectivitySubscriptions = @(); aksClusters = @() } |
        ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputDir "scope.json") -Encoding utf8
    return
}

$aksSubIds = @($aksRows | Select-Object -ExpandProperty subscriptionId -Unique)
Write-Output ("  AKS-bearing subs   : {0}" -f $aksSubIds.Count)
foreach ($id in $aksSubIds) {
    $count = ($aksRows | Where-Object subscriptionId -eq $id).Count
    Write-Output ("    {0}  {1}  clusters={2}" -f $id, $subNameMap[$id], $count)
}

# Cluster -> VNet ID(s) (each agent pool can have its own subnet)
$clusterVnetSet = New-Object System.Collections.Generic.HashSet[string]
$clusterMeta    = New-Object System.Collections.Generic.List[object]
foreach ($c in $aksRows) {
    $vnetIds = New-Object System.Collections.Generic.HashSet[string]
    foreach ($pool in @($c.agentPools)) {
        foreach ($subnetProp in 'vnetSubnetID','podSubnetID') {
            $sid = $pool.$subnetProp
            if ($sid) {
                # subnet id pattern: /subscriptions/.../virtualNetworks/<vnet>/subnets/<s>
                if ($sid -match '^(?<vnet>/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Network/virtualNetworks/[^/]+)/subnets/') {
                    [void]$vnetIds.Add($matches.vnet)
                    [void]$clusterVnetSet.Add($matches.vnet)
                }
            }
        }
    }
    $clusterMeta.Add([pscustomobject]@{
        id               = $c.id
        name             = $c.name
        subscriptionId   = $c.subscriptionId
        resourceGroup    = $c.resourceGroup
        location         = $c.location
        nodeResourceGroup= $c.nodeResourceGroup
        networkPlugin    = $c.networkPlugin
        networkPolicy    = $c.networkPolicy
        outboundType     = $c.outboundType
        apiServerPrivate = $c.apiServerPrivate
        vnetIds          = @($vnetIds)
    })
}
Write-Output ("  Cluster VNets seen : {0}" -f $clusterVnetSet.Count)

# ── 2. Peered VNets (auto-include their subs as "peer") ──────────────
Write-Output "`nStep 2: discovering peerings off cluster VNets..."
$peerRows = Invoke-Arg -Subs $allSubIds -Query @"
resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand peering=properties.virtualNetworkPeerings
| where isnotnull(peering)
| project sourceVnetId=id, sourceSub=subscriptionId,
    peeringName=tostring(peering.name),
    peeringState=tostring(peering.properties.peeringState),
    allowGatewayTransit=tobool(peering.properties.allowGatewayTransit),
    useRemoteGateways=tobool(peering.properties.useRemoteGateways),
    remoteVnetId=tostring(peering.properties.remoteVirtualNetwork.id)
"@

# Walk peerings starting from cluster VNets, collect remote VNets and their subs
$peerVnetSet = New-Object System.Collections.Generic.HashSet[string]
$peerSubSet  = New-Object System.Collections.Generic.HashSet[string]
$transitFlags = @{}   # remote sub -> any peering used remote gateways?

foreach ($p in $peerRows) {
    if ($clusterVnetSet.Contains($p.sourceVnetId) -and $p.remoteVnetId) {
        [void]$peerVnetSet.Add($p.remoteVnetId)
        if ($p.remoteVnetId -match '^/subscriptions/(?<sub>[^/]+)/') {
            $rsub = $matches.sub
            if ($aksSubIds -notcontains $rsub) { [void]$peerSubSet.Add($rsub) }
            if ($p.useRemoteGateways) { $transitFlags[$rsub] = $true }
        }
    }
}
Write-Output ("  Peered VNets       : {0}" -f $peerVnetSet.Count)
Write-Output ("  Peer subs (new)    : {0}" -f $peerSubSet.Count)
foreach ($id in $peerSubSet) {
    $name = $subNameMap[$id]
    if (-not $name) { $name = '<not visible>' }
    $hg = if ($transitFlags[$id]) { '  (useRemoteGateways=true)' } else { '' }
    Write-Output ("    {0}  {1}{2}" -f $id, $name, $hg)
}

# ── 3. Connectivity subs (gateways that any cluster/peer VNet uses) ─
Write-Output "`nStep 3: discovering ER / VPN gateways in cluster + peer VNets..."
$gwSearchSubs = @($aksSubIds + @($peerSubSet)) | Sort-Object -Unique
$gwRows = Invoke-Arg -Subs $gwSearchSubs -Query @"
resources
| where type =~ 'microsoft.network/virtualnetworkgateways'
   or type =~ 'microsoft.network/expressroutegateways'
   or type =~ 'microsoft.network/expressroutecircuits'
   or type =~ 'microsoft.network/virtualhubs'
| project id, name, type, subscriptionId, resourceGroup, location
"@

$connectivitySubSet = New-Object System.Collections.Generic.HashSet[string]
foreach ($g in $gwRows) {
    if ($g.subscriptionId -and -not ($aksSubIds -contains $g.subscriptionId)) {
        [void]$connectivitySubSet.Add($g.subscriptionId)
    }
}
Write-Output ("  Gateway/circuit res: {0}" -f $gwRows.Count)
Write-Output ("  Connectivity subs  : {0}" -f $connectivitySubSet.Count)
foreach ($id in $connectivitySubSet) {
    Write-Output ("    {0}  {1}" -f $id, $subNameMap[$id])
}

# ── Emit scope.json ─────────────────────────────────────────────────
$scope = [pscustomobject]@{
    generatedAt              = (Get-Date).ToString("o")
    aksSubscriptions         = @($aksSubIds | ForEach-Object {
        [pscustomobject]@{ id = $_; name = $subNameMap[$_]; role = 'aks' }
    })
    peerSubscriptions        = @($peerSubSet | ForEach-Object {
        [pscustomobject]@{ id = $_; name = $subNameMap[$_]; role = 'peer' }
    })
    connectivitySubscriptions= @($connectivitySubSet | ForEach-Object {
        [pscustomobject]@{ id = $_; name = $subNameMap[$_]; role = 'connectivity' }
    })
    clusterVnets             = @($clusterVnetSet)
    peerVnets                = @($peerVnetSet)
    aksClusters              = $clusterMeta
    gateways                 = $gwRows
}
$scopeFile = Join-Path $OutputDir "scope.json"
$scope | ConvertTo-Json -Depth 30 | Out-File $scopeFile -Encoding utf8
Write-Output ""
Write-Output ("Scope file : {0}" -f $scopeFile)
Write-Output ("Reports planned (one per AKS sub): {0}" -f $aksSubIds.Count)
Write-Output "Done."
