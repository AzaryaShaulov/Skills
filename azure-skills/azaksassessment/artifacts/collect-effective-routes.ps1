#requires -Version 5.1
<#
.SYNOPSIS
  Collect effective routes + effective NSGs for one node NIC per AKS nodepool.
  READ-ONLY (uses Network Watcher's get-effective-* operations which are
  read-only on the target NIC).

.DESCRIPTION
  For each AKS cluster discovered in arg-aks.json, walks the node resource
  group ("MC_*"), picks one VMSS instance NIC per nodepool, and pulls:
    - effective route table  (az network nic show-effective-route-table)
    - effective NSG rules    (az network nic list-effective-nsg)

  These are GET operations that return what the Azure SDN currently programs
  for the NIC. They never modify state.

  Output:
    data\effective-routes-<sub>-<aks>-<pool>.json
    data\effective-nsgs-<sub>-<aks>-<pool>.json

.PARAMETER OutputDir
  Default: <script>\data
#>
[CmdletBinding()]
param(
    [string] $OutputDir            = (Join-Path $PSScriptRoot "data"),
    [string] $RequiredTenantDomain = ''
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

Write-Output "[READ-ONLY] AzAKSAssessment effective routes / NSGs (no writes performed)."

# Tenant guard (supports guest/external accounts)
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

# Load AKS inventory
$aksFile = Join-Path $OutputDir "arg-aks.json"
if (-not (Test-Path $aksFile)) { throw "Missing $aksFile. Run collect-data.ps1 first." }
$aksList = (Get-Content $aksFile -Raw | ConvertFrom-Json).data
Write-Output ("AKS clusters in scope: {0}" -f @($aksList).Count)

function Sanitize($s) { ($s -replace '[^A-Za-z0-9._-]','-') }

foreach ($aks in $aksList) {
    $shortSub = $aks.subscriptionId.Substring(0,8)
    Write-Output ""
    Write-Output ("--- AKS: {0}  ({1})  outboundType={2}" -f $aks.name, $aks.subscriptionId, $aks.outboundType)

    # Switch context to the AKS subscription (read-only context change)
    az account set --subscription $aks.subscriptionId | Out-Null

    # Enumerate VMSSes in the node RG
    $nodeRg = $aks.nodeResourceGroup
    if (-not $nodeRg) {
        Write-Warning ("  No nodeResourceGroup for {0}; skipping." -f $aks.name)
        continue
    }
    $vmsses = az vmss list -g $nodeRg -o json 2>$null | ConvertFrom-Json
    if (-not $vmsses) {
        Write-Warning ("  No VMSS found in {0}; skipping." -f $nodeRg)
        continue
    }

    foreach ($vmss in $vmsses) {
        $poolName = if ($vmss.tags.'aks-managed-poolName') { $vmss.tags.'aks-managed-poolName' } else { $vmss.name }
        Write-Output ("    pool {0}: vmss={1}" -f $poolName, $vmss.name)

        # Find one running instance
        $instances = az vmss list-instances -g $nodeRg -n $vmss.name --query "[?provisioningState=='Succeeded'] | [0]" -o json 2>$null | ConvertFrom-Json
        if (-not $instances) {
            Write-Warning ("      no instances in vmss {0}" -f $vmss.name); continue
        }
        $instanceId = $instances.instanceId

        # Get NIC for that instance
        $nics = az vmss nic list-vm-nics -g $nodeRg --vmss-name $vmss.name --instance-id $instanceId -o json 2>$null | ConvertFrom-Json
        if (-not $nics -or $nics.Count -eq 0) {
            Write-Warning ("      no NICs for instance {0}" -f $instanceId); continue
        }
        $nic = $nics[0]
        $nicId = $nic.id

        $tag = "{0}-{1}-{2}" -f (Sanitize $shortSub), (Sanitize $aks.name), (Sanitize $poolName)

        # Effective routes (READ-ONLY GET on Network Watcher)
        try {
            Write-Output ("      get-effective-route-table ...")
            $routes = az network nic show-effective-route-table --ids $nicId -o json 2>$null
            if ($routes) {
                $routes | Out-File (Join-Path $OutputDir ("effective-routes-{0}.json" -f $tag)) -Encoding utf8
            }
        } catch { Write-Warning "      effective routes failed: $_" }

        # Effective NSG (READ-ONLY GET)
        try {
            Write-Output ("      list-effective-nsg ...")
            $nsg = az network nic list-effective-nsg --ids $nicId -o json 2>$null
            if ($nsg) {
                $nsg | Out-File (Join-Path $OutputDir ("effective-nsgs-{0}.json" -f $tag)) -Encoding utf8
            }
        } catch { Write-Warning "      effective NSG failed: $_" }
    }
}

Write-Output ""
Write-Output "Done."
