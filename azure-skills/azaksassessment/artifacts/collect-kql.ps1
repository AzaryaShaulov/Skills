#requires -Version 5.1
<#
.SYNOPSIS
  Run Queries.kql against every relevant Log Analytics workspace per AKS sub.
  READ-ONLY (only az monitor log-analytics query).

.DESCRIPTION
  For each AKS-bearing subscription:
    1. Find every workspace referenced by AKS / LB / NAT GW / Firewall
       diagnostic settings (collected by collect-data.ps1).
    2. Resolve the node-subnet IDs and onprem prefix list.
    3. Parse Queries.kql, substitute placeholders, run each query against
       each workspace, and save CSV per (sub, workspace, query).

  Output:
    data\kql\<sub>\<workspace>\<query>.csv

.PARAMETER OnpremPrefixes
  CIDR list of on-prem ranges to flag in EXFIL queries. Comma-separated
  string. Example: "10.0.0.0/8,192.168.0.0/16"
.PARAMETER LookbackDays
  Default 7.
#>
[CmdletBinding()]
param(
    [string]   $OnpremPrefixes       = '',
    [int]      $LookbackDays         = 7,
    [string]   $OutputDir            = '',
    [string]   $QueriesFile          = (Join-Path $PSScriptRoot "Queries.kql"),
    [string]   $TenantName           = '',
    [string]   $RequiredTenantDomain = ''
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

Write-Output "[READ-ONLY] AzAKSAssessment KQL collection (no writes performed)."

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

function Load-Arg($name) {
    $f = Join-Path $OutputDir ("arg-{0}.json" -f $name)
    if (-not (Test-Path $f)) { return @() }
    $j = Get-Content $f -Raw | ConvertFrom-Json
    if ($j.data) { return @($j.data) } else { return @() }
}
function Sanitize($s) { ($s -replace '[^A-Za-z0-9._-]','-') }

# ── Parse Queries.kql into named blocks ─────────────────────────────
if (-not (Test-Path $QueriesFile)) { throw "Missing $QueriesFile" }
$raw = Get-Content $QueriesFile -Raw
$queries = [ordered]@{}
$current = $null
$buffer  = New-Object System.Text.StringBuilder
foreach ($line in ($raw -split "`r?`n")) {
    if ($line -match '^//\s*===([A-Za-z0-9_]+)===\s*$') {
        if ($current -and $buffer.Length -gt 0) { $queries[$current] = $buffer.ToString().Trim() }
        $current = $matches[1]
        $buffer  = New-Object System.Text.StringBuilder
        continue
    }
    if ($current) { [void]$buffer.AppendLine($line) }
}
if ($current -and $buffer.Length -gt 0) { $queries[$current] = $buffer.ToString().Trim() }
Write-Output ("Queries parsed: {0}" -f $queries.Count)

# ── Inventory ────────────────────────────────────────────────────────
$aksList    = Load-Arg "aks"
$diagFile   = Join-Path $OutputDir "diagnostic-settings.json"
$diag       = if (Test-Path $diagFile) { Get-Content $diagFile -Raw | ConvertFrom-Json } else { @() }
$lawList    = Load-Arg "law"

# Map workspaceResourceId -> customerId (GUID needed for the query API)
$lawByResId = @{}
foreach ($w in $lawList) { $lawByResId[$w.id.ToLower()] = $w }

# Collects workspaces resolved on-the-fly via direct ARM (cross-sub LAW fallback,
# Bug 2). Persisted to arg-law-resolved.json so the report and subsequent runs
# can treat them as part of the inventory.
$resolvedLaw = New-Object System.Collections.Generic.List[object]

# Group AKS by subscription
$aksBySub = $aksList | Group-Object subscriptionId

# Per-run counters for end-of-phase summary.
$script:subsWithLaw    = 0
$script:subsWithoutLaw = 0
$script:queriesRun     = 0
$script:queriesPlanned = 0

foreach ($subGroup in $aksBySub) {
    $subId = $subGroup.Name
    Write-Output ""
    Write-Output ("=== Sub: {0}  AKS clusters: {1} ===" -f $subId, $subGroup.Count)

    # Node subnets across all clusters in this sub
    $nodeSubnets = New-Object System.Collections.Generic.HashSet[string]
    foreach ($aks in $subGroup.Group) {
        foreach ($pool in @($aks.agentPoolProfiles)) {
            foreach ($p in 'vnetSubnetID','podSubnetID') {
                if ($pool.$p) { [void]$nodeSubnets.Add($pool.$p.ToLower()) }
            }
        }
    }
    if ($nodeSubnets.Count -eq 0) {
        Write-Warning "  No node subnets resolved; skipping."
        continue
    }
    $nodeSubnetCsv = (($nodeSubnets | ForEach-Object { "'" + $_ + "'" }) -join ',')

    # Workspaces referenced by diagnostic settings on this sub's AKS/LB/NATGW/FW/PIP
    $relevantTargetIds = @()
    $relevantTargetIds += $subGroup.Group.id
    $lbs = (Load-Arg "loadbalancers") | Where-Object { $_.subscriptionId -eq $subId -and ($subGroup.Group.nodeResourceGroup -contains $_.resourceGroup) }
    $relevantTargetIds += $lbs.id
    $relevantTargetIds += (Load-Arg "natgateways" | Where-Object subscriptionId -eq $subId).id
    $workspaces = $diag |
        Where-Object { $_.workspaceId -and ($relevantTargetIds -contains $_.targetId) } |
        Select-Object -ExpandProperty workspaceId -Unique

    if (-not $workspaces) {
        Write-Warning ("  No Log Analytics workspaces found in diagnostic settings for sub {0}." -f $subId)
        Write-Warning  "  KQL phase will be skipped for this sub. (Coverage gap will be flagged in the report.)"
        $script:subsWithoutLaw++
        continue
    }
    $script:subsWithLaw++

    # OnPrem prefixes -> KQL array literal (sanitized)
    $onpremCsv = if ($OnpremPrefixes) {
        $validated = $OnpremPrefixes.Split(',') | ForEach-Object {
            $t = $_.Trim()
            if ($t -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') { Write-Warning "Skipping invalid CIDR: $t"; return }
            "'$t'"
        }
        $validated -join ','
    } else { '' }

    foreach ($wsResId in $workspaces) {
        $ws = $lawByResId[$wsResId.ToLower()]
        if (-not $ws) {
            # Cross-subscription LAW fallback: workspace was referenced by a
            # diagnostic setting but isn't in our local arg-law.json (e.g., it
            # lives in a subscription outside the assessment scope, like a
            # central observability sub). Try to resolve directly via ARM.
            $wsSubId = if ($wsResId -match '/subscriptions/([0-9a-fA-F-]{36})/') { $matches[1] } else { $null }
            if (-not $wsSubId) {
                Write-Warning ("  Workspace {0} could not be parsed; skipping." -f $wsResId)
                continue
            }
            Write-Output ("  Resolving cross-sub workspace {0} ..." -f $wsResId)
            $prevSub = (az account show --query id --only-show-errors -o tsv 2>$null)
            try {
                az account set --subscription $wsSubId --only-show-errors 2>$null | Out-Null
                $wsRaw = az monitor log-analytics workspace show --ids $wsResId --only-show-errors -o json 2>$null
                if (-not $wsRaw) { throw "az returned no data" }
                $wsObj = $wsRaw | ConvertFrom-Json
                $ws = [pscustomobject]@{
                    id             = $wsObj.id
                    name           = $wsObj.name
                    customerId     = $wsObj.customerId
                    subscriptionId = $wsSubId
                    resourceGroup  = ($wsObj.id -split '/')[4]
                    location       = $wsObj.location
                }
                $lawByResId[$wsResId.ToLower()] = $ws
                $resolvedLaw.Add($ws) | Out-Null
                Write-Output ("    -> resolved: {0} customerId={1}" -f $ws.name, $ws.customerId)
            } catch {
                Write-Warning ("  Workspace {0} unresolvable (RBAC / cross-tenant?); skipping. {1}" -f $wsResId, $_.Exception.Message)
                if ($prevSub) { az account set --subscription $prevSub --only-show-errors 2>$null | Out-Null }
                continue
            }
        }
        Write-Output ("  Workspace: {0}  ({1})" -f $ws.name, $ws.customerId)

        # READ-ONLY context switch to the workspace's sub
        az account set --subscription $ws.subscriptionId --only-show-errors 2>$null | Out-Null

        $outDir = Join-Path $OutputDir ("kql\{0}\{1}" -f $subId, (Sanitize $ws.name))
        if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

        foreach ($kv in $queries.GetEnumerator()) {
            $script:queriesPlanned++
            $qname  = $kv.Key
            $qbody  = $kv.Value
            $qbody  = $qbody -replace '\{\{NODE_SUBNETS\}\}',    $nodeSubnetCsv
            $qbody  = $qbody -replace '\{\{ONPREM_PREFIXES\}\}', $onpremCsv
            $qbody  = $qbody -replace '\{\{LOOKBACK\}\}',        ("{0}d" -f $LookbackDays)

            Write-Output ("    {0} ..." -f $qname)
            try {
                $resp = az monitor log-analytics query `
                    --workspace $ws.customerId `
                    --analytics-query $qbody `
                    --timespan ("P{0}D" -f $LookbackDays) `
                    --only-show-errors `
                    -o json 2>$null
                if ($resp) {
                    $script:queriesRun++
                    $rows = $resp | ConvertFrom-Json
                    if (@($rows).Count -gt 0) {
                        $csvFile = Join-Path $outDir ("{0}.csv" -f $qname)
                        $rows | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
                        Write-Output ("      -> {0} rows" -f @($rows).Count)
                    } else {
                        Write-Output "      (0 rows)"
                    }
                }
            } catch {
                Write-Warning ("      query failed: {0}" -f $_.Exception.Message)
            }
        }
    }
}

Write-Output ""
if ($resolvedLaw.Count -gt 0) {
    $resolvedFile = Join-Path $OutputDir "arg-law-resolved.json"
    $resolvedLaw | ConvertTo-Json -Depth 6 | Out-File $resolvedFile -Encoding utf8
    Write-Output ("Cross-sub workspaces resolved: {0} -> {1}" -f $resolvedLaw.Count, $resolvedFile)
}

# ── End-of-phase coverage summary (Gap 5) ────────────────────────────
$totalAksSubs = @($aksBySub).Count
Write-Output ""
Write-Output ("KQL phase: {0} of {1} AKS sub(s) had LAW-bound diagnostic settings; queries executed: {2} of {3}" `
    -f $script:subsWithLaw, $totalAksSubs, $script:queriesRun, $script:queriesPlanned)
if ($script:subsWithoutLaw -gt 0) {
    Write-Warning ("{0} sub(s) had no LAW binding -> exfiltration hunt produced no data for them. See per-report 'Diagnostic coverage' banner." -f $script:subsWithoutLaw)
    $kqlGap = [ordered]@{
        timestamp        = (Get-Date).ToString('o')
        gap              = 'kql-law-coverage-gap'
        totalAksSubs     = $totalAksSubs
        subsWithLaw      = $script:subsWithLaw
        subsWithoutLaw   = $script:subsWithoutLaw
        queriesPlanned   = $script:queriesPlanned
        queriesRun       = $script:queriesRun
        remediation      = 'Bind a Log Analytics workspace to AKS diagnostic settings (kube-apiserver, kube-audit, guard categories).'
    }
    $kqlGap | ConvertTo-Json -Depth 6 | Out-File (Join-Path $OutputDir 'kql-law-gap.json') -Encoding utf8
}
Write-Output "Done."
