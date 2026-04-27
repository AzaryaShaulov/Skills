#requires -Version 5.1
<#
.SYNOPSIS
  Collect Azure Monitor metrics for the L4/L7 devices in each AKS egress path.
  READ-ONLY (only az monitor metrics list).

.DESCRIPTION
  For each AKS cluster, collects metrics from:
    - The cluster's standard Load Balancer ("kubernetes" in MC_*) - SNAT health
    - Internal Load Balancer ("kubernetes-internal", if present)
    - NAT Gateway (if outboundType uses NAT)
    - Azure Firewall in the path (if outboundType=userDefinedRouting)

  Output: data\metrics-<aks>.json with one entry per source resource.

.PARAMETER LookbackHours
  How many hours to query. Default 168 (7 days).
.PARAMETER Interval
  Aggregation interval. Default PT1H.
#>
[CmdletBinding()]
param(
    [int]    $LookbackHours        = 168,
    [string] $Interval             = 'PT1H',
    [string] $OutputDir            = '',
    [string] $TenantName           = '',
    [string] $RequiredTenantDomain = ''
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

Write-Output "[READ-ONLY] AzAKSAssessment metrics collection (no writes performed)."

# Tenant guard (supports guest/external accounts)
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

$startTime = (Get-Date).ToUniversalTime().AddHours(-$LookbackHours).ToString("yyyy-MM-ddTHH:mm:ssZ")
$endTime   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
Write-Output ("Window: {0} -> {1}  interval={2}" -f $startTime, $endTime, $Interval)

function Load-Arg($name) {
    $f = Join-Path $OutputDir ("arg-{0}.json" -f $name)
    if (-not (Test-Path $f)) { return @() }
    $j = Get-Content $f -Raw | ConvertFrom-Json
    if ($j.data) { return @($j.data) } else { return @() }
}
function Sanitize($s) { ($s -replace '[^A-Za-z0-9._-]','-') }

$aksList = Load-Arg "aks"
$lbs     = Load-Arg "loadbalancers"
$natgws  = Load-Arg "natgateways"
$fws     = Load-Arg "firewalls"

# Metric catalog (resource type -> list of metric names)
$metricCatalog = @{
    'lb'    = 'SnatConnectionCount,UsedSnatPorts,AllocatedSnatPorts,VipAvailability,DipAvailability,ByteCount,PacketCount,SYNCount'
    'natgw' = 'SNATConnectionCount,DatapathAvailability,TotalConnectionCount,TotalSnatConnectionCount,DroppedPacketCount,SnatConnectionCount,PacketCount,ByteCount'
    'fw'    = 'ApplicationRuleHit,NetworkRuleHit,DnsProxyRequests,DnsProxyRequestsFailureRate,Throughput,SNATPortUtilization,FirewallHealth'
}

function Get-Metrics {
    param(
        [string] $ResourceId,
        [string] $Kind
    )
    $names = $metricCatalog[$Kind]
    if (-not $names) { return $null }
    try {
        $raw = az monitor metrics list `
            --resource $ResourceId `
            --metrics $names `
            --interval $Interval `
            --start-time $startTime `
            --end-time   $endTime `
            --only-show-errors `
            -o json 2>$null
        if ($raw) { return ($raw | ConvertFrom-Json) }
    } catch {
        Write-Warning ("metrics fetch failed for {0}: {1}" -f $ResourceId, $_.Exception.Message)
    }
    return $null
}

foreach ($aks in $aksList) {
    Write-Output ""
    Write-Output ("--- AKS: {0}  (sub={1}  outboundType={2})" -f $aks.name, $aks.subscriptionId, $aks.outboundType)

    az account set --subscription $aks.subscriptionId --only-show-errors 2>$null | Out-Null

    $bundle = [ordered]@{
        aks            = @{ id=$aks.id; name=$aks.name; sub=$aks.subscriptionId; outboundType=$aks.outboundType }
        window         = @{ start=$startTime; end=$endTime; interval=$Interval }
        loadBalancers  = @()
        natGateways    = @()
        firewalls      = @()
    }

    # LBs in node RG
    $clusterLbs = $lbs | Where-Object {
        $_.subscriptionId -eq $aks.subscriptionId -and $_.resourceGroup -ieq $aks.nodeResourceGroup
    }
    foreach ($lb in $clusterLbs) {
        Write-Output ("    LB    : {0}  ({1})" -f $lb.name, $lb.sku)
        $m = Get-Metrics -ResourceId $lb.id -Kind 'lb'
        $bundle.loadBalancers += @{ id=$lb.id; name=$lb.name; sku=$lb.sku; metrics=$m }
    }

    # NAT GW (if attached to any node-subnet)
    $clusterNats = $natgws | Where-Object { $_.subscriptionId -eq $aks.subscriptionId }
    foreach ($natgw in $clusterNats) {
        Write-Output ("    NATGW : {0}" -f $natgw.name)
        $m = Get-Metrics -ResourceId $natgw.id -Kind 'natgw'
        $bundle.natGateways += @{ id=$natgw.id; name=$natgw.name; metrics=$m }
    }

    # Firewalls only relevant when outboundType=userDefinedRouting OR FW exists in any peer/hub sub
    if ($aks.outboundType -ieq 'userDefinedRouting') {
        foreach ($fw in $fws) {
            Write-Output ("    FW    : {0}  (sub={1})" -f $fw.name, $fw.subscriptionId)
            az account set --subscription $fw.subscriptionId --only-show-errors 2>$null | Out-Null
            $m = Get-Metrics -ResourceId $fw.id -Kind 'fw'
            $bundle.firewalls += @{ id=$fw.id; name=$fw.name; sub=$fw.subscriptionId; metrics=$m }
        }
        az account set --subscription $aks.subscriptionId --only-show-errors 2>$null | Out-Null
    }

    $tag  = "{0}-{1}" -f $aks.subscriptionId.Substring(0,8), (Sanitize $aks.name)
    $file = Join-Path $OutputDir ("metrics-{0}.json" -f $tag)
    $bundle | ConvertTo-Json -Depth 30 | Out-File $file -Encoding utf8
    Write-Output ("      -> {0}" -f $file)
}

Write-Output ""
Write-Output "Done."
