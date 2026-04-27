#requires -Version 5.1
<#
.SYNOPSIS
  AzAKSAssessment Phase 0+1 ARG inventory collector. READ-ONLY.

.DESCRIPTION
  Reads scope.json (produced by discover-scope.ps1) and collects an ARG-based
  inventory across all in-scope subscriptions (AKS + peer + connectivity):
    - AKS managed clusters (full networkProfile + agent pools)
    - VNets + subnets + peerings
    - NSGs + route tables (with effective routes pulled separately)
    - Load Balancers (external + internal)
    - NAT Gateways + Public IPs / IP Prefixes
    - Azure Firewalls + policies
    - Private Endpoints + Private DNS Zones + Service Endpoints (subnet-level)
    - VPN / ExpressRoute gateways + circuits + Virtual Hubs
    - Network Watchers + VNet flow logs + legacy NSG flow logs
    - Log Analytics workspaces (candidate sinks for KQL)
    - Diagnostic settings on AKS, LBs, NAT GW, Firewall, Public IPs

  No write operations. Only az ... show|list|graph query.

.PARAMETER OutputDir
  Default: <script>\data
.PARAMETER ScopeFile
  Default: <OutputDir>\scope.json (from discover-scope.ps1).
#>
[CmdletBinding()]
param(
    [string] $OutputDir            = (Join-Path $PSScriptRoot "data"),
    [string] $ScopeFile            = (Join-Path $PSScriptRoot "data\scope.json"),
    [string] $RequiredTenantDomain = ''
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

# ── READ-ONLY ENFORCEMENT ────────────────────────────────────────────
# Allowed verbs only: az ... show|list|graph query, Get-Az*, Search-AzGraph,
# Invoke-AzOperationalInsightsQuery, kubectl get|describe.
# Disallowed: any new-/set-/remove-/update-/add-/start-/stop-/restart-/etc.
Write-Output "[READ-ONLY] AzAKSAssessment data collection (no writes performed)."

# ── Tenant guard (supports guest/external accounts) ──────────────────
$ctx = az account show -o json 2>$null | ConvertFrom-Json
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
Write-Output ("Tenant            : {0}" -f $tenantDomain)

# ── Load scope ───────────────────────────────────────────────────────
if (-not (Test-Path $ScopeFile)) {
    throw "Scope file not found: $ScopeFile. Run .\discover-scope.ps1 first."
}
$scope = Get-Content $ScopeFile -Raw | ConvertFrom-Json
$aksSubs    = @($scope.aksSubscriptions          | Select-Object -ExpandProperty id)
$peerSubs   = @($scope.peerSubscriptions         | Select-Object -ExpandProperty id)
$connSubs   = @($scope.connectivitySubscriptions | Select-Object -ExpandProperty id)
$allSubs    = @($aksSubs + $peerSubs + $connSubs) | Sort-Object -Unique
if (-not $allSubs) { throw "Scope is empty (no AKS-bearing subscriptions found)." }

Write-Output ("In-scope subs      : {0} (aks={1}, peer={2}, conn={3})" -f $allSubs.Count, $aksSubs.Count, $peerSubs.Count, $connSubs.Count)

# ── ARG helper ───────────────────────────────────────────────────────
function Invoke-Arg {
    param(
        [Parameter(Mandatory)] [string]   $Name,
        [Parameter(Mandatory)] [string]   $Query,
        [Parameter(Mandatory)] [string[]] $Subs
    )
    Write-Output ("  ARG {0} ({1} subs)..." -f $Name, $Subs.Count)
    $outFile  = Join-Path $OutputDir ("arg-{0}.json" -f $Name)
    $flatQuery = ($Query -replace '\r?\n',' ').Trim()
    try {
        $raw = az graph query -q $flatQuery --subscriptions $Subs --first 1000 -o json 2>$null
        if ($raw) {
            $raw | Out-File $outFile -Encoding utf8
            $parsed = $raw | ConvertFrom-Json
            $rowCount = if ($parsed.data) { @($parsed.data).Count } else { 0 }
            Write-Output ("    -> {0} rows" -f $rowCount)
        } else {
            '{"count":0,"data":[]}' | Out-File $outFile -Encoding utf8
            Write-Output "    -> (empty)"
        }
    } catch {
        Write-Warning ("  ARG '{0}' failed: {1}" -f $Name, $_.Exception.Message)
        '{"count":0,"data":[]}' | Out-File $outFile -Encoding utf8
    }
}

Write-Output ""
Write-Output "=== Phase 1: ARG inventory ==="

# ── Subscriptions metadata ──────────────────────────────────────────
$subMeta = az account list --query "[?state=='Enabled']" -o json | ConvertFrom-Json |
    Where-Object { $allSubs -contains $_.id }
$subMeta | ConvertTo-Json -Depth 10 | Out-File (Join-Path $OutputDir "scoped-subscriptions.json") -Encoding utf8

# ── AKS clusters (full) ──────────────────────────────────────────────
Invoke-Arg -Name "aks" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.containerservice/managedclusters'
| project id, name, location, subscriptionId, resourceGroup, tags,
    nodeResourceGroup           = tostring(properties.nodeResourceGroup),
    kubernetesVersion           = tostring(properties.kubernetesVersion),
    fqdn                        = tostring(properties.fqdn),
    privateFqdn                 = tostring(properties.privateFqdn),
    apiServerAccessProfile      = properties.apiServerAccessProfile,
    networkPlugin               = tostring(properties.networkProfile.networkPlugin),
    networkPluginMode           = tostring(properties.networkProfile.networkPluginMode),
    networkPolicy               = tostring(properties.networkProfile.networkPolicy),
    networkDataplane            = tostring(properties.networkProfile.networkDataplane),
    outboundType                = tostring(properties.networkProfile.outboundType),
    serviceCidr                 = tostring(properties.networkProfile.serviceCidr),
    podCidr                     = tostring(properties.networkProfile.podCidr),
    dnsServiceIP                = tostring(properties.networkProfile.dnsServiceIP),
    loadBalancerSku             = tostring(properties.networkProfile.loadBalancerSku),
    loadBalancerProfile         = properties.networkProfile.loadBalancerProfile,
    natGatewayProfile           = properties.networkProfile.natGatewayProfile,
    addonProfiles               = properties.addonProfiles,
    securityProfile             = properties.securityProfile,
    aadProfile                  = properties.aadProfile,
    identity                    = identity,
    agentPoolProfiles           = properties.agentPoolProfiles
"@

# ── VNets + subnets ──────────────────────────────────────────────────
Invoke-Arg -Name "vnets" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/virtualnetworks'
| project id, name, location, subscriptionId, resourceGroup,
    addressPrefixes = properties.addressSpace.addressPrefixes,
    dnsServers      = properties.dhcpOptions.dnsServers,
    enableDdos      = tobool(properties.enableDdosProtection),
    ddosPlan        = properties.ddosProtectionPlan,
    subnets         = properties.subnets
"@

Invoke-Arg -Name "peerings" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/virtualnetworks'
| mv-expand peering=properties.virtualNetworkPeerings
| where isnotnull(peering)
| project sourceVnetId=id, sourceSubscriptionId=subscriptionId, sourceResourceGroup=resourceGroup,
    peeringName=tostring(peering.name),
    peeringState=tostring(peering.properties.peeringState),
    allowForwardedTraffic=tobool(peering.properties.allowForwardedTraffic),
    allowGatewayTransit=tobool(peering.properties.allowGatewayTransit),
    useRemoteGateways=tobool(peering.properties.useRemoteGateways),
    allowVirtualNetworkAccess=tobool(peering.properties.allowVirtualNetworkAccess),
    remoteVnetId=tostring(peering.properties.remoteVirtualNetwork.id),
    remoteAddressSpace=peering.properties.remoteAddressSpace.addressPrefixes
"@

# ── NSGs + Route Tables ──────────────────────────────────────────────
Invoke-Arg -Name "nsgs" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| project id, name, location, subscriptionId, resourceGroup,
    securityRules         = properties.securityRules,
    defaultSecurityRules  = properties.defaultSecurityRules,
    subnets               = properties.subnets,
    networkInterfaces     = properties.networkInterfaces
"@

Invoke-Arg -Name "routetables" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/routetables'
| project id, name, location, subscriptionId, resourceGroup,
    routes                          = properties.routes,
    subnets                         = properties.subnets,
    disableBgpRoutePropagation      = tobool(properties.disableBgpRoutePropagation)
"@

# ── Load Balancers (external + internal) ─────────────────────────────
Invoke-Arg -Name "loadbalancers" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/loadbalancers'
| project id, name, location, subscriptionId, resourceGroup,
    sku                  = sku.name,
    tier                 = sku.tier,
    frontendIpConfigs    = properties.frontendIPConfigurations,
    backendAddressPools  = properties.backendAddressPools,
    loadBalancingRules   = properties.loadBalancingRules,
    outboundRules        = properties.outboundRules,
    inboundNatRules      = properties.inboundNatRules,
    probes               = properties.probes
"@

# ── NAT Gateways + Public IPs / Prefixes ─────────────────────────────
Invoke-Arg -Name "natgateways" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/natgateways'
| project id, name, location, subscriptionId, resourceGroup,
    sku                = sku.name,
    idleTimeoutInMinutes = toint(properties.idleTimeoutInMinutes),
    publicIpAddresses  = properties.publicIpAddresses,
    publicIpPrefixes   = properties.publicIpPrefixes,
    subnets            = properties.subnets
"@

Invoke-Arg -Name "publicips" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/publicipaddresses'
| project id, name, location, subscriptionId, resourceGroup,
    sku                 = sku.name,
    allocationMethod    = tostring(properties.publicIPAllocationMethod),
    addressVersion      = tostring(properties.publicIPAddressVersion),
    ipAddress           = tostring(properties.ipAddress),
    fqdn                = tostring(properties.dnsSettings.fqdn),
    ipConfiguration     = properties.ipConfiguration,
    natGateway          = properties.natGateway,
    publicIpPrefix      = properties.publicIPPrefix
"@

Invoke-Arg -Name "publicipprefixes" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/publicipprefixes'
| project id, name, location, subscriptionId, resourceGroup,
    sku             = sku.name,
    prefixLength    = toint(properties.prefixLength),
    ipPrefix        = tostring(properties.ipPrefix),
    publicIPAddresses = properties.publicIPAddresses
"@

# ── Azure Firewall + policies ────────────────────────────────────────
Invoke-Arg -Name "firewalls" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/azurefirewalls'
| project id, name, location, subscriptionId, resourceGroup,
    sku                          = properties.sku,
    threatIntelMode              = tostring(properties.threatIntelMode),
    firewallPolicy               = properties.firewallPolicy,
    networkRuleCollections       = properties.networkRuleCollections,
    applicationRuleCollections   = properties.applicationRuleCollections,
    natRuleCollections           = properties.natRuleCollections,
    ipConfigurations             = properties.ipConfigurations,
    additionalProperties         = properties.additionalProperties
"@

Invoke-Arg -Name "firewallpolicies" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/firewallpolicies'
| project id, name, location, subscriptionId, resourceGroup,
    sku             = properties.sku.tier,
    threatIntelMode = tostring(properties.threatIntelMode),
    dnsSettings     = properties.dnsSettings,
    childPolicies   = properties.childPolicies,
    firewalls       = properties.firewalls
"@

# ── Private Endpoints + Private DNS ──────────────────────────────────
Invoke-Arg -Name "privateendpoints" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/privateendpoints'
| project id, name, location, subscriptionId, resourceGroup,
    subnet                 = properties.subnet.id,
    networkInterfaces      = properties.networkInterfaces,
    privateLinkServiceConnections          = properties.privateLinkServiceConnections,
    manualPrivateLinkServiceConnections    = properties.manualPrivateLinkServiceConnections,
    customDnsConfigs       = properties.customDnsConfigs
"@

Invoke-Arg -Name "privatednszones" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/privatednszones'
| project id, name, location, subscriptionId, resourceGroup,
    numberOfRecordSets             = toint(properties.numberOfRecordSets),
    numberOfVirtualNetworkLinks    = toint(properties.numberOfVirtualNetworkLinks),
    provisioningState              = tostring(properties.provisioningState)
"@

Invoke-Arg -Name "privatednslinks" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/privatednszones/virtualnetworklinks'
| project id, name, location, subscriptionId, resourceGroup,
    virtualNetwork                  = properties.virtualNetwork.id,
    registrationEnabled             = tobool(properties.registrationEnabled)
"@

# ── Gateways (VPN, ER) + Circuits + vWAN hubs ───────────────────────
Invoke-Arg -Name "vnetgateways" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/virtualnetworkgateways'
| project id, name, location, subscriptionId, resourceGroup,
    gatewayType    = tostring(properties.gatewayType),
    activeActive   = tobool(properties.activeActive),
    enableBgp      = tobool(properties.enableBgp),
    sku            = properties.sku,
    vpnGatewayGeneration = tostring(properties.vpnGatewayGeneration),
    bgpSettings    = properties.bgpSettings,
    ipConfigurations = properties.ipConfigurations
"@

Invoke-Arg -Name "ergateways" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/expressroutegateways'
| project id, name, location, subscriptionId, resourceGroup,
    autoScaleConfiguration = properties.autoScaleConfiguration,
    virtualHub             = properties.virtualHub
"@

Invoke-Arg -Name "ercircuits" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/expressroutecircuits'
| project id, name, location, subscriptionId, resourceGroup,
    sku                                       = sku,
    circuitProvisioningState                  = tostring(properties.circuitProvisioningState),
    serviceProviderProvisioningState          = tostring(properties.serviceProviderProvisioningState),
    serviceProviderProperties                 = properties.serviceProviderProperties,
    bandwidthInGbps                           = toint(properties.bandwidthInGbps),
    peerings                                  = properties.peerings
"@

Invoke-Arg -Name "virtualhubs" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/virtualhubs'
| project id, name, location, subscriptionId, resourceGroup,
    addressPrefix    = tostring(properties.addressPrefix),
    sku              = tostring(properties.sku),
    virtualWan       = properties.virtualWan,
    expressRouteGateway = properties.expressRouteGateway,
    vpnGateway       = properties.vpnGateway,
    azureFirewall    = properties.azureFirewall,
    routeTable       = properties.routeTable
"@

# ── Network Watchers + Flow Logs ─────────────────────────────────────
Invoke-Arg -Name "networkwatchers" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/networkwatchers'
| project id, name, location, subscriptionId, resourceGroup,
    provisioningState = tostring(properties.provisioningState)
"@

Invoke-Arg -Name "flowlogs" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/networkwatchers/flowlogs'
| project id, name, location, subscriptionId, resourceGroup,
    enabled                       = tobool(properties.enabled),
    targetResourceId              = tostring(properties.targetResourceId),
    storageId                     = tostring(properties.storageId),
    flowAnalyticsConfiguration    = properties.flowAnalyticsConfiguration,
    retentionPolicy               = properties.retentionPolicy,
    format                        = properties.format
"@

# ── Log Analytics workspaces ─────────────────────────────────────────
Invoke-Arg -Name "law" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.operationalinsights/workspaces'
| project id, name, location, subscriptionId, resourceGroup,
    sku                = tostring(properties.sku.name),
    customerId         = tostring(properties.customerId),
    retentionInDays    = toint(properties.retentionInDays),
    publicNetworkAccessForIngestion = tostring(properties.publicNetworkAccessForIngestion),
    publicNetworkAccessForQuery     = tostring(properties.publicNetworkAccessForQuery)
"@

# ── Application Gateways / Front Door (north-south ingress) ─────────
Invoke-Arg -Name "appgateways" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/applicationgateways'
| project id, name, location, subscriptionId, resourceGroup,
    sku                = properties.sku,
    operationalState   = tostring(properties.operationalState),
    httpListeners      = properties.httpListeners,
    backendAddressPools= properties.backendAddressPools,
    backendHttpSettingsCollection = properties.backendHttpSettingsCollection,
    webApplicationFirewallConfiguration = properties.webApplicationFirewallConfiguration
"@

Invoke-Arg -Name "frontdoors" -Subs $allSubs -Query @"
resources
| where type =~ 'microsoft.network/frontdoors'
   or type =~ 'microsoft.cdn/profiles'
| project id, name, location, type, subscriptionId, resourceGroup, properties
"@

# ── Diagnostic settings on key resources (per-resource ARM call) ────
Write-Output ""
Write-Output "=== Phase 2: Diagnostic settings on AKS / LB / NAT GW / FW / Public IPs ==="

# Build target resource list from earlier inventories
function Load-Arg($name) {
    $f = Join-Path $OutputDir ("arg-{0}.json" -f $name)
    if (-not (Test-Path $f)) { return @() }
    $j = Get-Content $f -Raw | ConvertFrom-Json
    if ($j.data) { return @($j.data) } else { return @() }
}

$diagTargets = @()
$diagTargets += Load-Arg "aks"            | Select-Object @{n='id';e={$_.id}}, @{n='kind';e={'aks'}}
$diagTargets += Load-Arg "loadbalancers"  | Select-Object @{n='id';e={$_.id}}, @{n='kind';e={'lb'}}
$diagTargets += Load-Arg "natgateways"    | Select-Object @{n='id';e={$_.id}}, @{n='kind';e={'natgw'}}
$diagTargets += Load-Arg "firewalls"      | Select-Object @{n='id';e={$_.id}}, @{n='kind';e={'fw'}}
$diagTargets += Load-Arg "publicips"      | Select-Object @{n='id';e={$_.id}}, @{n='kind';e={'pip'}}

$diagSettingsAll = New-Object System.Collections.Generic.List[object]
$idx = 0; $tot = $diagTargets.Count
foreach ($t in $diagTargets) {
    $idx++
    if (($idx % 25) -eq 0) { Write-Output ("  diag {0}/{1}" -f $idx, $tot) }
    try {
        $diag = az monitor diagnostic-settings list --resource $t.id -o json 2>$null | ConvertFrom-Json
        if ($diag -and $diag.value) {
            foreach ($d in $diag.value) {
                $diagSettingsAll.Add([pscustomobject]@{
                    targetId        = $t.id
                    targetKind      = $t.kind
                    name            = $d.name
                    workspaceId     = $d.workspaceId
                    storageAccountId= $d.storageAccountId
                    eventHubAuthorizationRuleId = $d.eventHubAuthorizationRuleId
                    logs            = $d.logs
                    metrics         = $d.metrics
                })
            }
        }
    } catch { }
}
$diagSettingsAll | ConvertTo-Json -Depth 12 | Out-File (Join-Path $OutputDir "diagnostic-settings.json") -Encoding utf8
Write-Output ("  diag settings rows: {0}" -f $diagSettingsAll.Count)

# ── Storage accounts that hold flow logs (for SAS-less blob discovery) ─
Write-Output ""
Write-Output "=== Phase 3: Storage accounts referenced by flow logs ==="
$flowLogs = Load-Arg "flowlogs"
$flowStorageIds = @($flowLogs | Where-Object { $_.storageId } | Select-Object -ExpandProperty storageId -Unique)
Write-Output ("  flow log storage accounts: {0}" -f $flowStorageIds.Count)
$flowStorageIds | ConvertTo-Json | Out-File (Join-Path $OutputDir "flowlog-storage-accounts.json") -Encoding utf8

Write-Output ""
Write-Output ("Output dir: {0}" -f $OutputDir)
Write-Output "Done."

