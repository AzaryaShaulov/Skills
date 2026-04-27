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

Write-Output "[READ-ONLY] AzAKSAssessment effective routes / NSGs (no writes performed)."

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

# Load AKS inventory
$aksFile = Join-Path $OutputDir "arg-aks.json"
if (-not (Test-Path $aksFile)) { throw "Missing $aksFile. Run collect-data.ps1 first." }
$aksList = (Get-Content $aksFile -Raw | ConvertFrom-Json).data
Write-Output ("AKS clusters in scope: {0}" -f @($aksList).Count)

function Sanitize($s) { ($s -replace '[^A-Za-z0-9._-]','-') }

# Per-run counters for the RBAC-gap summary / sentinel.
$script:totalNicAttempts  = 0
$script:routesWritten     = 0
$script:nsgsWritten       = 0
$script:authFailures      = 0
$script:authFailureScopes = New-Object System.Collections.Generic.List[string]

foreach ($aks in $aksList) {
    $shortSub = $aks.subscriptionId.Substring(0,8)
    Write-Output ""
    Write-Output ("--- AKS: {0}  ({1})  outboundType={2}" -f $aks.name, $aks.subscriptionId, $aks.outboundType)

    # Switch context to the AKS subscription (read-only context change)
    az account set --subscription $aks.subscriptionId --only-show-errors 2>$null | Out-Null

    # Enumerate VMSSes in the node RG
    $nodeRg = $aks.nodeResourceGroup
    if (-not $nodeRg) {
        Write-Warning ("  No nodeResourceGroup for {0}; skipping." -f $aks.name)
        continue
    }
    $vmsses = az vmss list -g $nodeRg --only-show-errors -o json 2>$null | ConvertFrom-Json
    if (-not $vmsses) {
        Write-Warning ("  No VMSS found in {0}; skipping." -f $nodeRg)
        continue
    }

    foreach ($vmss in $vmsses) {
        $poolName = if ($vmss.tags.'aks-managed-poolName') { $vmss.tags.'aks-managed-poolName' } else { $vmss.name }
        Write-Output ("    pool {0}: vmss={1}" -f $poolName, $vmss.name)

        # Find one running instance
        $instances = az vmss list-instances -g $nodeRg -n $vmss.name --query "[?provisioningState=='Succeeded'] | [0]" --only-show-errors -o json 2>$null | ConvertFrom-Json
        if (-not $instances) {
            Write-Warning ("      no instances in vmss {0}" -f $vmss.name); continue
        }
        $instanceId = $instances.instanceId

        # Get NIC for that instance
        $nics = az vmss nic list-vm-nics -g $nodeRg --vmss-name $vmss.name --instance-id $instanceId --only-show-errors -o json 2>$null | ConvertFrom-Json
        if (-not $nics -or $nics.Count -eq 0) {
            Write-Warning ("      no NICs for instance {0}" -f $instanceId); continue
        }
        $nic = $nics[0]
        $nicId = $nic.id
        $script:totalNicAttempts++

        $tag = "{0}-{1}-{2}" -f (Sanitize $shortSub), (Sanitize $aks.name), (Sanitize $poolName)

        # Effective routes (READ-ONLY GET on Network Watcher)
        Write-Output ("      get-effective-route-table ...")
        $routesErr = ''
        $routes = az network nic show-effective-route-table --ids $nicId --only-show-errors -o json 2>&1
        if ($LASTEXITCODE -ne 0) {
            $routesErr = ($routes | Out-String)
            if ($routesErr -match 'AuthorizationFailed') {
                $script:authFailures++
                $script:authFailureScopes.Add(("nic={0}" -f $nicId)) | Out-Null
                Write-Warning "      AuthorizationFailed on get-effective-route-table"
            } else {
                Write-Warning ("      effective routes failed: {0}" -f ($routesErr.Trim() -split "`n" | Select-Object -First 1))
            }
        } elseif ($routes) {
            $routes | Out-File (Join-Path $OutputDir ("effective-routes-{0}.json" -f $tag)) -Encoding utf8
            $script:routesWritten++
        }

        # Effective NSG (READ-ONLY GET)
        Write-Output ("      list-effective-nsg ...")
        $nsg = az network nic list-effective-nsg --ids $nicId --only-show-errors -o json 2>&1
        if ($LASTEXITCODE -ne 0) {
            $nsgErr = ($nsg | Out-String)
            if ($nsgErr -match 'AuthorizationFailed') {
                # Already counted under routes auth-failure above for this NIC,
                # but track NSG-only denials separately too.
                if ($routesErr -notmatch 'AuthorizationFailed') {
                    $script:authFailures++
                    $script:authFailureScopes.Add(("nic={0}" -f $nicId)) | Out-Null
                }
                Write-Warning "      AuthorizationFailed on list-effective-nsg"
            } else {
                Write-Warning ("      effective NSG failed: {0}" -f ($nsgErr.Trim() -split "`n" | Select-Object -First 1))
            }
        } elseif ($nsg) {
            $nsg | Out-File (Join-Path $OutputDir ("effective-nsgs-{0}.json" -f $tag)) -Encoding utf8
            $script:nsgsWritten++
        }
    }
}

# ── Summary + RBAC-gap sentinel ──────────────────────────────────────
Write-Output ""
Write-Output ("Summary: NICs probed={0}, routes written={1}, NSGs written={2}, AuthorizationFailed NICs={3}" `
    -f $script:totalNicAttempts, $script:routesWritten, $script:nsgsWritten, $script:authFailures)

if ($script:totalNicAttempts -gt 0 -and $script:routesWritten -eq 0 -and $script:authFailures -gt 0) {
    Write-Warning ("effective-routes: 0 of {0} NICs returned data; {1} AuthorizationFailed." -f $script:totalNicAttempts, $script:authFailures)
    Write-Warning  "-> Likely RBAC gap. Network Watcher effective-* APIs require 'Network Contributor' (or equivalent)"
    Write-Warning  "   on each MC_* node resource group, plus 'Reader' on the parent AKS RG."
    Write-Warning  "   See README.md / SKILL.md 'Required permissions'."
    $sentinel = [ordered]@{
        timestamp        = (Get-Date).ToString('o')
        gap              = 'effective-routes-rbac-denied'
        totalNicAttempts = $script:totalNicAttempts
        routesWritten    = $script:routesWritten
        nsgsWritten      = $script:nsgsWritten
        authFailures     = $script:authFailures
        affectedScopes   = @($script:authFailureScopes | Select-Object -Unique)
        remediation      = 'Grant Network Contributor on each MC_* node RG, then re-run.'
    }
    $sentinel | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputDir 'effective-routes-rbac-gap.json') -Encoding utf8
}

Write-Output ""
Write-Output "Done."
