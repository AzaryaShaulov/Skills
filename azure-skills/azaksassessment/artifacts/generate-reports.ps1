#requires -Version 5.1
<#
.SYNOPSIS
  AzAKSAssessment report generator. Produces one HTML per AKS-bearing subscription + index.
.DESCRIPTION
  Consumes data\* artifacts from previous collection steps and generates
  self-contained HTML reports with SVG topology diagrams, gap analysis,
  AKS version lifecycle assessment, and linked recommendations.
  READ-ONLY â€” no Azure writes.
.PARAMETER DataDir
  Path to collected data artifacts. Default: <script>\data
.PARAMETER OutputDir
  Path for HTML output. Default: <script>\reports
.PARAMETER TenantName
  Display name for the tenant (shown in report headers).
.PARAMETER RequiredTenantDomain
  Not used by this script (reports are generated from local data).
#>
[CmdletBinding()]
param(
    [string] $DataDir              = (Join-Path $PSScriptRoot "data"),
    [string] $OutputDir            = (Join-Path $PSScriptRoot "reports"),
    [string] $TenantName           = '',
    [string] $RequiredTenantDomain = '',

    # When set, per-subscription HTML files are named
    # "<sub>-AKSAssessment.html" (no timestamp) so reruns into the same
    # -OutputDir overwrite cleanly. Default keeps the legacy timestamped
    # name for back-compat with operators piping into shared folders.
    [switch] $StableFilename
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
Write-Output "[READ-ONLY] AzAKSAssessment report generation (no Azure writes)."

function Load-Arg($name) {
    $f = Join-Path $DataDir ("arg-{0}.json" -f $name)
    if (-not (Test-Path $f)) { return @() }
    $j = Get-Content $f -Raw | ConvertFrom-Json
    if ($j.data) { return @($j.data) } else { return @() }
}
$scope = Get-Content (Join-Path $DataDir "scope.json") -Raw | ConvertFrom-Json
$subsMeta = if (Test-Path (Join-Path $DataDir "scoped-subscriptions.json")) { Get-Content (Join-Path $DataDir "scoped-subscriptions.json") -Raw | ConvertFrom-Json } else { @() }
$subNameMap = @{}; foreach ($s in $subsMeta) { $subNameMap[$s.id] = $s.name }
$aks = Load-Arg "aks"; $vnets = Load-Arg "vnets"; $peerings = Load-Arg "peerings"
$nsgs = Load-Arg "nsgs"; $rts = Load-Arg "routetables"; $lbs = Load-Arg "loadbalancers"
$natgws = Load-Arg "natgateways"; $pips = Load-Arg "publicips"; $pes = Load-Arg "privateendpoints"
$pdns = Load-Arg "privatednszones"; $pdnsLinks = Load-Arg "privatednslinks"
$flowlogs = Load-Arg "flowlogs"; $law = Load-Arg "law"; $agws = Load-Arg "appgateways"
$fws = Load-Arg "firewalls"
# Merge in any cross-sub workspaces resolved by collect-kql.ps1 (Bug 2 fix).
$resolvedLawFile = Join-Path $DataDir "arg-law-resolved.json"
if (Test-Path $resolvedLawFile) {
    $resolved = Get-Content $resolvedLawFile -Raw | ConvertFrom-Json
    if ($resolved) { $law = @($law) + @($resolved) | Sort-Object id -Unique }
}
$diag = if (Test-Path (Join-Path $DataDir "diagnostic-settings.json")) { Get-Content (Join-Path $DataDir "diagnostic-settings.json") -Raw | ConvertFrom-Json } else { @() }

# ----------------------------------------------------------------------
# Diagnostic-coverage helper (Bug 3 fix).
# Coverage = distinct target resources WITH workspaceId / distinct evaluated
# target resources, mirroring the universe collect-data.ps1 actually scans:
# AKS + LB + NAT GW + Firewalls + Public IPs.
# ----------------------------------------------------------------------
$diagTargetIdsAll = @(
    @($aks    | Select-Object -ExpandProperty id)
    @($lbs    | Select-Object -ExpandProperty id)
    @($natgws | Select-Object -ExpandProperty id)
    @($fws    | Select-Object -ExpandProperty id)
    @($pips   | Select-Object -ExpandProperty id)
) | Where-Object { $_ } | Sort-Object -Unique
$diagTargetIdsWithLaw = @($diag | Where-Object { $_.workspaceId } | Select-Object -ExpandProperty targetId -Unique)
$diagCoveredCount     = (@($diagTargetIdsAll) | Where-Object { $diagTargetIdsWithLaw -contains $_ }).Count
$diagTotalCount       = @($diagTargetIdsAll).Count
function Get-KindCoverage($kind, $items) {
    $total = @($items | Select-Object -ExpandProperty id -Unique).Count
    $covered = @($diag | Where-Object { $_.targetKind -eq $kind -and $_.workspaceId } | Select-Object -ExpandProperty targetId -Unique).Count
    return [pscustomobject]@{ kind=$kind; total=$total; covered=$covered }
}
$diagBreakdown = @(
    Get-KindCoverage 'aks'   $aks
    Get-KindCoverage 'lb'    $lbs
    Get-KindCoverage 'natgw' $natgws
    Get-KindCoverage 'fw'    $fws
    Get-KindCoverage 'pip'   $pips
)

function Sanitize($s) { ($s -replace '[^A-Za-z0-9._-]','-') }
function Esc($s) { if ($null -eq $s) { return '' }; ([string]$s).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;') }
function ShortId($id) { if ($id) { ($id -split '/')[-1] } else { '' } }
function PillFor($v) { if ($v) { '<span class="pill ok">YES</span>' } else { '<span class="pill warn">NO</span>' } }
function SevPill($sev) { $cls = switch($sev){'High'{'crit'}'Medium'{'warn'}'Low'{'info'}default{'muted'}}; "<span class='pill $cls'>$sev</span>" }
function CsvAsTable { param([string]$Path,[int]$MaxRows=25)
    if (-not (Test-Path $Path)) { return '<p class="muted">No data.</p>' }
    $rows = Import-Csv $Path; if ($rows.Count -eq 0) { return '<p class="muted">0 rows.</p>' }
    $cols = $rows[0].PSObject.Properties.Name; $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<table class="smallTable"><thead><tr>')
    foreach ($c in $cols) { [void]$sb.AppendLine("<th>$(Esc $c)</th>") }
    [void]$sb.AppendLine('</tr></thead><tbody>'); $n=0
    foreach ($r in $rows) { [void]$sb.Append('<tr>'); foreach ($c in $cols) { [void]$sb.Append("<td>$(Esc $r.$c)</td>") }; [void]$sb.AppendLine('</tr>'); $n++; if($n -ge $MaxRows){break} }
    [void]$sb.AppendLine('</tbody></table>')
    if ($rows.Count -gt $MaxRows) { [void]$sb.AppendLine("<p class='muted'>Showing $MaxRows of $($rows.Count).</p>") }
    return $sb.ToString()
}

$css = @'
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',system-ui,sans-serif;background:#fff;color:#0f172a;line-height:1.6}
code,pre{font-family:'Cascadia Code','Consolas',monospace;font-size:.85rem}
.nav{position:sticky;top:0;z-index:50;background:rgba(255,255,255,.92);backdrop-filter:blur(8px);border-bottom:1px solid #e2e8f0;padding:.5rem 1.5rem;display:flex;gap:1rem;flex-wrap:wrap;align-items:center}
.nav a{color:#2563eb;text-decoration:none;font-size:.875rem;font-weight:500}.nav a:hover{text-decoration:underline}
.container{max-width:1400px;margin:0 auto;padding:1.5rem}
h1{font-size:1.75rem;font-weight:700;margin-bottom:.25rem}h2{font-size:1.35rem;font-weight:600;margin:2rem 0 .75rem;padding-bottom:.5rem;border-bottom:2px solid #e2e8f0}
h3{font-size:1.05rem;font-weight:600;margin:1.25rem 0 .5rem}h4{font-size:.95rem;font-weight:600;margin:1rem 0 .4rem;color:#334155}
.muted{color:#475569;font-size:.875rem}
.banner{background:#fef3c7;border:1px solid #f59e0b;color:#92400e;padding:.5rem 1rem;border-radius:.5rem;margin:.5rem 0;font-size:.85rem}
.bannerOk{background:#dcfce7;border:1px solid #16a34a;color:#14532d;padding:.5rem 1rem;border-radius:.5rem;margin:.5rem 0;font-size:.85rem;font-weight:600}
.disclaimer{background:#f0f4ff;border:1px solid #6366f1;color:#312e81;padding:.6rem 1rem;border-radius:.5rem;margin:.5rem 0;font-size:.8rem;line-height:1.5}
.card{background:#f8fafc;border:1px solid #e2e8f0;border-radius:.75rem;padding:1.25rem;margin-bottom:1rem}
.grid4{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:.5rem}
table{width:100%;border-collapse:collapse;margin:.75rem 0;font-size:.85rem}
th{background:#f1f5f9;text-align:left;padding:.4rem .75rem;font-weight:600;border-bottom:2px solid #e2e8f0}
td{padding:.4rem .75rem;border-bottom:1px solid #e2e8f0;vertical-align:top}tr:hover{background:#f8fafc}
.pill{display:inline-block;padding:1px 9px;border-radius:9999px;font-size:.7rem;font-weight:600;border:1.5px solid;margin-right:.25rem}
.pill.ok{color:#15803d;border-color:#15803d;background:#dcfce7}.pill.warn{color:#a16207;border-color:#a16207;background:#fef9c3}
.pill.crit{color:#b91c1c;border-color:#b91c1c;background:#fee2e2}.pill.info{color:#1d4ed8;border-color:#1d4ed8;background:#dbeafe}
.pill.muted{color:#475569;border-color:#cbd5e1;background:#f1f5f9}
.kbd{font-family:monospace;background:#f1f5f9;border:1px solid #cbd5e1;border-radius:4px;padding:1px 6px;font-size:.78rem}
.findingHigh{border-left:4px solid #b91c1c;padding-left:.75rem}.findingMed{border-left:4px solid #ea580c;padding-left:.75rem}.findingLow{border-left:4px solid #2563eb;padding-left:.75rem}
.smallTable td,.smallTable th{font-size:.8rem;padding:.25rem .5rem}
.indexCard{background:#f8fafc;border:1px solid #e2e8f0;border-radius:.75rem;padding:1rem 1.25rem;margin-bottom:.75rem;display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}
.indexCard:hover{border-color:#93c5fd;background:#eff6ff}
.tocList{list-style:none;padding:0;margin:.5rem 0;display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:.35rem .75rem}
.tocList li{font-size:.85rem;line-height:1.4;border-left:3px solid #cbd5e1;padding:.15rem .5rem;background:#f8fafc;border-radius:0 .25rem .25rem 0}
.tocList li:hover{border-left-color:#2563eb;background:#eff6ff}
.tocList a{text-decoration:none;color:#1e40af;font-weight:600}
.tocList a:hover{text-decoration:underline}
.tocList .tocMeta{color:#64748b;font-weight:400;font-size:.75rem;margin-left:.35rem}
.issueCard{border-left:4px solid #b91c1c;background:#fef2f2;border:1px solid #fecaca;border-left:4px solid #b91c1c;border-radius:.5rem;padding:.75rem 1rem;margin-bottom:.5rem}
.issueCardMed{border-left-color:#ea580c;background:#fff7ed;border-color:#fed7aa}
.stat{text-align:center}.stat .num{font-size:1.5rem;font-weight:700;color:#1e40af}.stat .lbl{font-size:.75rem;color:#64748b}
details{margin:.5rem 0}details summary{cursor:pointer;font-weight:600;font-size:.9rem;color:#334155}details summary:hover{color:#1d4ed8}
.svgDiag{background:#fff;border:1px solid #e2e8f0;border-radius:.5rem;padding:1rem;margin:.75rem 0;overflow-x:auto;position:relative}
.svgDiag svg{max-width:100%;height:auto}
.exportBtn{position:absolute;top:.5rem;right:.5rem;background:#2563eb;color:#fff;border:none;border-radius:4px;padding:4px 12px;font-size:.75rem;cursor:pointer;font-weight:600}
.exportBtn:hover{background:#1d4ed8}
@media print{.nav,.exportBtn{display:none!important}.container{padding:0}.card{break-inside:avoid}body{font-size:11pt}}
</style>
'@
$jsScript = @'
<script>
function exportSvg(id,name){var s=document.getElementById(id);if(!s)return;var d=new XMLSerializer().serializeToString(s);var b=new Blob([d],{type:'image/svg+xml'});var u=URL.createObjectURL(b);var a=document.createElement('a');a.href=u;a.download=name+'.svg';a.click();URL.revokeObjectURL(u)}
function exportPage(){window.print()}
function toggleAll(){var d=document.querySelectorAll('details');var open=d[0]&&d[0].open;d.forEach(function(e){e.open=!open})}
</script>
'@

$ts = (Get-Date).ToString("yyyy-MM-dd_HHmm")
$aksBySub = $aks | Group-Object subscriptionId
$indexEntries = [System.Collections.Generic.List[object]]::new()

# AKS version lifecycle â€” LAST UPDATED: April 2026
# Source: https://learn.microsoft.com/en-us/azure/aks/supported-kubernetes-versions
# Update this table when new K8s versions reach GA in AKS.
# GA supported: 1.33, 1.34, 1.35 (N-2, N-1, N)
# Platform support (N-3): 1.32
# EOL: 1.31 (Nov 2025), 1.30 (Aug 2025), 1.29 (Mar 2025), <=1.28 unsupported
function Get-K8sVersionStatus {
    param([string]$ver)
    if (-not $ver) { return @{status='Unknown';pill='muted';msg='Version not reported'} }
    $minor = 0; if ($ver -match '^1\.(\d+)') { $minor = [int]$matches[1] }
    if ($minor -ge 35) { return @{status='Current (GA)';pill='ok';msg="1.$minor is the latest GA release"} }
    if ($minor -ge 33) { return @{status='Supported (GA)';pill='ok';msg="1.$minor is within the N-2 support window"} }
    if ($minor -eq 32) { return @{status='Platform support only';pill='warn';msg='1.32 EOL Mar 2026. Platform support until 1.36 GA. Upgrade recommended.'} }
    if ($minor -eq 31) { return @{status='End of life';pill='crit';msg='1.31 EOL Nov 2025. No patches or security fixes. Upgrade immediately.'} }
    if ($minor -eq 30) { return @{status='End of life';pill='crit';msg='1.30 EOL Aug 2025. No patches or security fixes. Upgrade immediately.'} }
    if ($minor -eq 29) { return @{status='End of life';pill='crit';msg='1.29 EOL Mar 2025. Exposed to unpatched CVEs. Upgrade immediately.'} }
    return @{status='Unsupported';pill='crit';msg="1.$minor is unsupported and may have critical unpatched vulnerabilities (CVEs). Azure may force-upgrade clusters >3 minor versions behind."}
}

foreach ($g in $aksBySub) {
    $subId=$g.Name; $subName=$subNameMap[$subId]; if(-not $subName){$subName=$subId}
    $clusters=$g.Group
    Write-Output ("Building report: {0} ({1})  clusters={2}" -f $subName,$subId,$clusters.Count)

    $subVnets=@($vnets|Where-Object subscriptionId -eq $subId)
    $subPeers=@($peerings|Where-Object sourceSubscriptionId -eq $subId)
    $subLbs=@($lbs|Where-Object subscriptionId -eq $subId)
    $subPips=@($pips|Where-Object subscriptionId -eq $subId)
    $subPes=@($pes|Where-Object subscriptionId -eq $subId)
    $subNsgs=@($nsgs|Where-Object subscriptionId -eq $subId)
    $subRts=@($rts|Where-Object subscriptionId -eq $subId)
    $subFlows=@($flowlogs|Where-Object subscriptionId -eq $subId)
    $subDiag=@($diag|Where-Object{$_.targetId -like "/subscriptions/$subId/*"})
    $subAgws=@($agws|Where-Object subscriptionId -eq $subId)
    $subPdns2=@($pdns|Where-Object subscriptionId -eq $subId)
    $kqlSubDir=Join-Path $DataDir "kql\$subId"; $kqlPresent=Test-Path $kqlSubDir

    # â”€â”€ Cluster cards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $sbC=[System.Text.StringBuilder]::new()
    foreach($c in $clusters){
        $vSt = Get-K8sVersionStatus $c.kubernetesVersion
        [void]$sbC.AppendLine("<div class='card'><h3>$(Esc $c.name) <span class='muted'>$(Esc $c.resourceGroup)</span></h3><div class='grid4'>")
        foreach($kv in @(@('K8s',"<code>$(Esc $c.kubernetesVersion)</code> <span class='pill $($vSt.pill)'>$($vSt.status)</span>"),@('Plugin',"$(Esc $c.networkPlugin) $(Esc $c.networkPluginMode)"),@('Policy',$(if($c.networkPolicy-and$c.networkPolicy-ine'none'){"<span class='kbd'>$(Esc $c.networkPolicy)</span>"}else{"<span class='pill warn'>NONE</span>"})),@('Outbound',"<span class='kbd'>$(Esc $c.outboundType)</span>"),@('Svc CIDR',"<code>$(Esc $c.serviceCidr)</code>"),@('Pod CIDR',"<code>$(Esc $c.podCidr)</code>"),@('DNS IP',"<code>$(Esc $c.dnsServiceIP)</code>"),@('Private',$(if($c.apiServerAccessProfile.enablePrivateCluster){"<span class='pill ok'>YES</span>"}else{"<span class='pill warn'>NO</span>"})),@('API',"<code>$(Esc $(if($c.apiServerAccessProfile.enablePrivateCluster){$c.privateFqdn}else{$c.fqdn}))</code>"),@('Node RG',"<code>$(Esc $c.nodeResourceGroup)</code>"))) { [void]$sbC.AppendLine("<div><div class='muted'>$($kv[0])</div><div>$($kv[1])</div></div>") }
        [void]$sbC.AppendLine("</div><h4>Node pools</h4><table class='smallTable'><thead><tr><th>Pool</th><th>Mode</th><th>VM size</th><th>Count</th><th>OS</th><th>Subnet</th><th>Pod subnet</th></tr></thead><tbody>")
        foreach($p in @($c.agentPoolProfiles)){$podSn=if($p.podSubnetID){ShortId $p.podSubnetID}else{'-'}
            [void]$sbC.AppendLine("<tr><td><strong>$(Esc $p.name)</strong></td><td>$(Esc $p.mode)</td><td><code>$(Esc $p.vmSize)</code></td><td>$(Esc $p.count)</td><td>$(Esc $p.osType)</td><td><code>$(ShortId $p.vnetSubnetID)</code></td><td><code>$(Esc $podSn)</code></td></tr>")}
        [void]$sbC.AppendLine('</tbody></table></div>')
    }

    # â”€â”€ VNets â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $sbV=[System.Text.StringBuilder]::new()
    foreach($v in $subVnets){
        $dns=if($v.dnsServers-and@($v.dnsServers).Count-gt0){"<code>$(($v.dnsServers-join'</code>, <code>'))</code>"}else{'<span class="muted">Azure DNS</span>'}
        [void]$sbV.AppendLine("<div class='card'><h3>$(Esc $v.name)</h3><div class='grid4'><div><div class='muted'>CIDR</div><div><code>$(($v.addressPrefixes-join', '))</code></div></div><div><div class='muted'>DNS</div><div>$dns</div></div></div>")
        if($v.subnets){[void]$sbV.AppendLine('<table class="smallTable"><thead><tr><th>Subnet</th><th>CIDR</th><th>NSG</th><th>RT</th><th>Svc EP</th></tr></thead><tbody>')
            foreach($sn in @($v.subnets)){$nsg2=if($sn.properties.networkSecurityGroup.id){ShortId $sn.properties.networkSecurityGroup.id}else{"<span class='pill warn'>NONE</span>"};$rt2=if($sn.properties.routeTable.id){ShortId $sn.properties.routeTable.id}else{'-'};$se2=if($sn.properties.serviceEndpoints){($sn.properties.serviceEndpoints|ForEach-Object{$_.service-replace'Microsoft\.',''})-join', '}else{'-'}
                [void]$sbV.AppendLine("<tr><td><strong>$(Esc $sn.name)</strong></td><td><code>$(Esc $sn.properties.addressPrefix)</code></td><td><code>$nsg2</code></td><td><code>$(Esc $rt2)</code></td><td>$se2</td></tr>")}
            [void]$sbV.AppendLine('</tbody></table>')}
        [void]$sbV.AppendLine('</div>')
    }

    # â”€â”€ LBs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $sbL=[System.Text.StringBuilder]::new()
    foreach($lb in $subLbs){
        $hp=($lb.frontendIpConfigs|Where-Object{$_.properties.privateIPAddress})-ne$null;$hpub=($lb.frontendIpConfigs|Where-Object{$_.properties.publicIPAddress})-ne$null
        $lt=if($hp-and-not $hpub){'Internal'}elseif($hp){'Dual'}else{'External'}
        [void]$sbL.AppendLine("<div class='card'><h3>$(Esc $lb.name) <span class='pill muted'>$lt $(Esc $lb.sku)</span></h3>")
        # Frontend IPs
        [void]$sbL.AppendLine("<h4>Frontend IPs</h4><table class='smallTable'><thead><tr><th>Name</th><th>Private IP</th><th>Public IP</th><th>Subnet</th></tr></thead><tbody>")
        foreach($fe in @($lb.frontendIpConfigs)){$priv2=$fe.properties.privateIPAddress;if(-not$priv2){$priv2='-'};$pub2=if($fe.properties.publicIPAddress.id){$po2=$subPips|Where-Object id -eq $fe.properties.publicIPAddress.id;if($po2){$po2.ipAddress}else{ShortId $fe.properties.publicIPAddress.id}}else{'-'};$sn2=if($fe.properties.subnet.id){ShortId $fe.properties.subnet.id}else{'-'}
            [void]$sbL.AppendLine("<tr><td>$(Esc $fe.name)</td><td><code>$(Esc $priv2)</code></td><td><code>$(Esc $pub2)</code></td><td><code>$(Esc $sn2)</code></td></tr>")}
        [void]$sbL.AppendLine('</tbody></table>')
        # LB Rules detail
        if($lb.loadBalancingRules -and @($lb.loadBalancingRules).Count -gt 0){
            [void]$sbL.AppendLine("<h4>Load Balancing Rules ($(@($lb.loadBalancingRules).Count))</h4><table class='smallTable'><thead><tr><th>Rule</th><th>Protocol</th><th>FE port</th><th>BE port</th><th>Frontend</th><th>Backend pool</th><th>Probe</th><th>Idle</th><th>Float</th></tr></thead><tbody>")
            foreach($r in @($lb.loadBalancingRules)){
                $feName=if($r.properties.frontendIPConfiguration.id){($r.properties.frontendIPConfiguration.id-split'/')[-1]}else{'-'}
                $beName=if($r.properties.backendAddressPool.id){($r.properties.backendAddressPool.id-split'/')[-1]}else{'-'}
                $probe=if($r.properties.probe.id){($r.properties.probe.id-split'/')[-1]}else{'-'}
                $fePort=if($r.properties.frontendPort-eq0){'HA ports'}else{$r.properties.frontendPort}
                $bePort=if($r.properties.backendPort-eq0){'HA ports'}else{$r.properties.backendPort}
                [void]$sbL.AppendLine("<tr><td>$(Esc $r.name)</td><td>$(Esc $r.properties.protocol)</td><td>$(Esc $fePort)</td><td>$(Esc $bePort)</td><td><code>$(Esc $feName)</code></td><td><code>$(Esc $beName)</code></td><td><code>$(Esc $probe)</code></td><td>$($r.properties.idleTimeoutInMinutes)m</td><td>$(Esc $r.properties.enableFloatingIP)</td></tr>")}
            [void]$sbL.AppendLine('</tbody></table>')}
        # Outbound rules
        if($lb.outboundRules -and @($lb.outboundRules).Count -gt 0){
            [void]$sbL.AppendLine("<h4>Outbound Rules ($(@($lb.outboundRules).Count))</h4><table class='smallTable'><thead><tr><th>Rule</th><th>Protocol</th><th>Allocated ports</th><th>Idle timeout</th><th>TCP reset</th></tr></thead><tbody>")
            foreach($or in @($lb.outboundRules)){
                $allocPorts=if($or.properties.allocatedOutboundPorts){$or.properties.allocatedOutboundPorts}else{'auto'}
                [void]$sbL.AppendLine("<tr><td>$(Esc $or.name)</td><td>$(Esc $or.properties.protocol)</td><td>$(Esc $allocPorts)</td><td>$($or.properties.idleTimeoutInMinutes)m</td><td>$(Esc $or.properties.enableTcpReset)</td></tr>")}
            [void]$sbL.AppendLine('</tbody></table>')}
        # Inbound NAT rules
        if($lb.inboundNatRules -and @($lb.inboundNatRules).Count -gt 0){
            [void]$sbL.AppendLine("<h4>Inbound NAT Rules ($(@($lb.inboundNatRules).Count))</h4><table class='smallTable'><thead><tr><th>Rule</th><th>Protocol</th><th>FE port</th><th>BE port</th><th>Frontend</th></tr></thead><tbody>")
            foreach($nr in @($lb.inboundNatRules)){
                $nrFe=if($nr.properties.frontendIPConfiguration.id){($nr.properties.frontendIPConfiguration.id-split'/')[-1]}else{'-'}
                [void]$sbL.AppendLine("<tr><td>$(Esc $nr.name)</td><td>$(Esc $nr.properties.protocol)</td><td>$(Esc $nr.properties.frontendPort)</td><td>$(Esc $nr.properties.backendPort)</td><td><code>$(Esc $nrFe)</code></td></tr>")}
            [void]$sbL.AppendLine('</tbody></table>')}
        # Summary stats
        [void]$sbL.AppendLine("<div class='grid4' style='margin-top:.5rem'><div><div class='muted'>Backend pools</div><div>$(@($lb.backendAddressPools).Count)</div></div><div><div class='muted'>Probes</div><div>$(@($lb.probes).Count)</div></div></div></div>")
    }

    # â”€â”€ App Gateways â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $sbAG=[System.Text.StringBuilder]::new()
    foreach($ag in $subAgws){
        $skuName=if($ag.sku.name){$ag.sku.name}else{'-'}; $skuTier=if($ag.sku.tier){$ag.sku.tier}else{'-'}
        $opState=if($ag.operationalState){$ag.operationalState}else{'-'}
        $wafOn=if($ag.webApplicationFirewallConfiguration.enabled){$true}else{$false}
        $wafMode=if($ag.webApplicationFirewallConfiguration.firewallMode){$ag.webApplicationFirewallConfiguration.firewallMode}else{'-'}
        [void]$sbAG.AppendLine("<div class='card'><h3>$(Esc $ag.name) <span class='pill muted'>$(Esc $skuTier)</span> $(if($wafOn){"<span class='pill ok'>WAF $wafMode</span>"}else{"<span class='pill warn'>No WAF</span>"})</h3>")
        [void]$sbAG.AppendLine("<div class='grid4'><div><div class='muted'>SKU</div><div>$(Esc $skuName)</div></div><div><div class='muted'>State</div><div>$(Esc $opState)</div></div><div><div class='muted'>RG</div><div>$(Esc $ag.resourceGroup)</div></div><div><div class='muted'>Location</div><div>$(Esc $ag.location)</div></div></div>")
        # Listeners
        if($ag.httpListeners -and @($ag.httpListeners).Count -gt 0){
            [void]$sbAG.AppendLine("<h4>HTTP Listeners ($(@($ag.httpListeners).Count))</h4><table class='smallTable'><thead><tr><th>Listener</th><th>Protocol</th><th>Host</th><th>Port config</th></tr></thead><tbody>")
            foreach($hl in @($ag.httpListeners)){
                $host2=if($hl.properties.hostName){$hl.properties.hostName}elseif($hl.properties.hostNames){$hl.properties.hostNames-join', '}else{'*'}
                $portRef=if($hl.properties.frontendPort.id){($hl.properties.frontendPort.id-split'/')[-1]}else{'-'}
                [void]$sbAG.AppendLine("<tr><td>$(Esc $hl.name)</td><td>$(Esc $hl.properties.protocol)</td><td><code>$(Esc $host2)</code></td><td><code>$(Esc $portRef)</code></td></tr>")}
            [void]$sbAG.AppendLine('</tbody></table>')}
        # Backend pools
        if($ag.backendAddressPools -and @($ag.backendAddressPools).Count -gt 0){
            [void]$sbAG.AppendLine("<h4>Backend Pools ($(@($ag.backendAddressPools).Count))</h4><table class='smallTable'><thead><tr><th>Pool</th><th>Backend addresses</th></tr></thead><tbody>")
            foreach($bp in @($ag.backendAddressPools)){
                $addrs=if($bp.properties.backendAddresses){($bp.properties.backendAddresses|ForEach-Object{if($_.ipAddress){$_.ipAddress}elseif($_.fqdn){$_.fqdn}else{'-'}})-join', '}else{'(empty)'}
                [void]$sbAG.AppendLine("<tr><td><strong>$(Esc $bp.name)</strong></td><td><code>$(Esc $addrs)</code></td></tr>")}
            [void]$sbAG.AppendLine('</tbody></table>')}
        # Backend HTTP settings
        if($ag.backendHttpSettingsCollection -and @($ag.backendHttpSettingsCollection).Count -gt 0){
            [void]$sbAG.AppendLine("<h4>Backend HTTP Settings ($(@($ag.backendHttpSettingsCollection).Count))</h4><table class='smallTable'><thead><tr><th>Name</th><th>Port</th><th>Protocol</th><th>Cookie affinity</th><th>Timeout</th><th>Probe</th></tr></thead><tbody>")
            foreach($bs in @($ag.backendHttpSettingsCollection)){
                $probeName=if($bs.properties.probe.id){($bs.properties.probe.id-split'/')[-1]}else{'-'}
                [void]$sbAG.AppendLine("<tr><td>$(Esc $bs.name)</td><td>$(Esc $bs.properties.port)</td><td>$(Esc $bs.properties.protocol)</td><td>$(Esc $bs.properties.cookieBasedAffinity)</td><td>$($bs.properties.requestTimeout)s</td><td><code>$(Esc $probeName)</code></td></tr>")}
            [void]$sbAG.AppendLine('</tbody></table>')}
        # Summary
        $listenerCount=@($ag.httpListeners).Count; $poolCount=@($ag.backendAddressPools).Count; $settingsCount=@($ag.backendHttpSettingsCollection).Count
        [void]$sbAG.AppendLine("<div class='grid4' style='margin-top:.5rem'><div><div class='muted'>Listeners</div><div>$listenerCount</div></div><div><div class='muted'>Pools</div><div>$poolCount</div></div><div><div class='muted'>Settings</div><div>$settingsCount</div></div></div></div>")
    }

    # â”€â”€ PIPs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $sbP=[System.Text.StringBuilder]::new()
    if($subPips.Count-gt0){[void]$sbP.AppendLine('<table class="smallTable"><thead><tr><th>Name</th><th>IP</th><th>SKU</th><th>Alloc</th><th>Attached</th></tr></thead><tbody>')
        foreach($p in $subPips){$att2=if($p.ipConfiguration.id){($p.ipConfiguration.id-split'/')[-3,-1]-join'/'}else{'-'}
            [void]$sbP.AppendLine("<tr><td>$(Esc $p.name)</td><td><code>$(Esc $p.ipAddress)</code></td><td>$(Esc $p.sku)</td><td>$(Esc $p.allocationMethod)</td><td><code>$(Esc $att2)</code></td></tr>")}
        [void]$sbP.AppendLine('</tbody></table>')}else{[void]$sbP.AppendLine('<p class="muted">None.</p>')}

    # â”€â”€ PEs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $sbE=[System.Text.StringBuilder]::new()
    if($subPes.Count-gt0){[void]$sbE.AppendLine('<table class="smallTable"><thead><tr><th>PE</th><th>Target</th><th>Group</th><th>Status</th><th>Subnet</th></tr></thead><tbody>')
        foreach($pe in $subPes){$conn2=if($pe.privateLinkServiceConnections){$pe.privateLinkServiceConnections[0]}elseif($pe.manualPrivateLinkServiceConnections){$pe.manualPrivateLinkServiceConnections[0]}else{$null};$tgt2=if($conn2){ShortId $conn2.properties.privateLinkServiceId}else{'-'};$grp2=if($conn2.properties.groupIds){$conn2.properties.groupIds-join','}else{'-'};$st2=if($conn2.properties.privateLinkServiceConnectionState.status){$conn2.properties.privateLinkServiceConnectionState.status}else{'-'}
            [void]$sbE.AppendLine("<tr><td><strong>$(Esc $pe.name)</strong></td><td><code>$(Esc $tgt2)</code></td><td>$(Esc $grp2)</td><td>$(Esc $st2)</td><td><code>$(ShortId $pe.subnet)</code></td></tr>")}
        [void]$sbE.AppendLine('</tbody></table>')}else{[void]$sbE.AppendLine('<p class="muted">None.</p>')}

    # â”€â”€ UDRs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $sbR=[System.Text.StringBuilder]::new()
    foreach($rt in $subRts){$att3=if($rt.subnets){(@($rt.subnets)|ForEach-Object{ShortId $_.id})-join', '}else{'unattached'};$bgp2=if($rt.disableBgpRoutePropagation){'disabled'}else{'enabled'}
        [void]$sbR.AppendLine("<details><summary>$(Esc $rt.name) <span class='pill muted'>BGP=$bgp2</span> <span class='muted'>$att3</span></summary>")
        if($rt.routes-and@($rt.routes).Count-gt0){[void]$sbR.AppendLine('<table class="smallTable"><thead><tr><th>Route</th><th>Prefix</th><th>Next hop</th><th>IP</th></tr></thead><tbody>')
            foreach($r in @($rt.routes)){$nhCls2=switch($r.properties.nextHopType){'VirtualAppliance'{'info'}'Internet'{'warn'}'None'{'crit'}default{'muted'}}
                [void]$sbR.AppendLine("<tr><td>$(Esc $r.name)</td><td><code>$(Esc $r.properties.addressPrefix)</code></td><td><span class='pill $nhCls2'>$(Esc $r.properties.nextHopType)</span></td><td><code>$(Esc $r.properties.nextHopIpAddress)</code></td></tr>")}
            [void]$sbR.AppendLine('</tbody></table>')}
        [void]$sbR.AppendLine('</details>')}

    # â”€â”€ Peerings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $sbPR=[System.Text.StringBuilder]::new()
    if($subPeers.Count-gt0){[void]$sbPR.AppendLine('<table class="smallTable"><thead><tr><th>Local</th><th>Remote</th><th>State</th><th>Fwd</th><th>GW</th><th>Prefixes</th></tr></thead><tbody>')
        foreach($p in $subPeers){$stCls2=if($p.peeringState-eq'Connected'){'ok'}else{'crit'};$rpfx2=if($p.remoteAddressSpace){$p.remoteAddressSpace-join', '}else{'-'}
            [void]$sbPR.AppendLine("<tr><td><code>$(ShortId $p.sourceVnetId)</code></td><td><code>$(ShortId $p.remoteVnetId)</code></td><td><span class='pill $stCls2'>$(Esc $p.peeringState)</span></td><td>$(Esc $p.allowForwardedTraffic)</td><td>$(Esc $p.useRemoteGateways)</td><td><code>$(Esc $rpfx2)</code></td></tr>")}
        [void]$sbPR.AppendLine('</tbody></table>')}else{[void]$sbPR.AppendLine('<p class="muted">None.</p>')}

    # â”€â”€ NSGs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $sbN=[System.Text.StringBuilder]::new(); $nsgIssues=0; $nsgHighlightCount=0
    foreach($nsg in $subNsgs){
        $interesting=@($nsg.securityRules)|Where-Object{
            $_.properties.access-eq'Deny' -or
            $_.properties.sourceAddressPrefix-in@('*','Internet','0.0.0.0/0') -or
            $_.properties.destinationAddressPrefix-in@('*','Internet','0.0.0.0/0') -or
            ($_.properties.sourceAddressPrefixes -and ($_.properties.sourceAddressPrefixes|Where-Object{$_-in@('*','Internet','0.0.0.0/0')})) -or
            ($_.properties.destinationAddressPrefixes -and ($_.properties.destinationAddressPrefixes|Where-Object{$_-in@('*','Internet','0.0.0.0/0')}))
        }
        if($interesting.Count-eq0){continue}
        $nsgHighlightCount+=$interesting.Count
        $att4=if($nsg.subnets){(@($nsg.subnets)|ForEach-Object{ShortId $_.id})-join', '}elseif($nsg.networkInterfaces){"$(@($nsg.networkInterfaces).Count) NIC(s)"}else{'unattached'}
        [void]$sbN.AppendLine("<details><summary>$(Esc $nsg.name) <span class='muted'>($att4)</span> <span class='pill muted'>$($interesting.Count) rules</span></summary>")
        [void]$sbN.AppendLine("<table class='smallTable'><thead><tr><th>Prio</th><th>Name</th><th>Dir</th><th>Access</th><th>Proto</th><th>Src</th><th>Dst</th><th>Port</th></tr></thead><tbody>")
        foreach($r in ($interesting|Sort-Object{[int]$_.properties.priority})){
            $ac2=if($r.properties.access-eq'Deny'){'crit'}else{'warn'}
            $srcP=if($r.properties.sourceAddressPrefix){$r.properties.sourceAddressPrefix}elseif($r.properties.sourceAddressPrefixes){$r.properties.sourceAddressPrefixes-join', '}else{'-'}
            $dstP=if($r.properties.destinationAddressPrefix){$r.properties.destinationAddressPrefix}elseif($r.properties.destinationAddressPrefixes){$r.properties.destinationAddressPrefixes-join', '}else{'-'}
            $port=if($r.properties.destinationPortRange){$r.properties.destinationPortRange}elseif($r.properties.destinationPortRanges){$r.properties.destinationPortRanges-join', '}else{'*'}
            if($r.properties.access-eq'Allow'-and$srcP-match'\*|Internet|0\.0\.0\.0'-and$r.properties.direction-eq'Inbound'){$nsgIssues++}
            [void]$sbN.AppendLine("<tr><td>$($r.properties.priority)</td><td>$(Esc $r.name)</td><td>$($r.properties.direction)</td><td><span class='pill $ac2'>$($r.properties.access)</span></td><td>$(Esc $r.properties.protocol)</td><td><code>$(Esc $srcP)</code></td><td><code>$(Esc $dstP)</code></td><td>$(Esc $port)</td></tr>")}
        [void]$sbN.AppendLine('</tbody></table></details>')}

    # â”€â”€ Telemetry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $hasFlow=$false;$hasTA=$false
    foreach($fl in $subFlows){if($fl.enabled){$hasFlow=$true};if($fl.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.enabled){$hasTA=$true}}
    $hasFw=($subDiag|Where-Object{$_.targetKind-eq'fw'-and$_.workspaceId}).Count-gt0
    $hasAks=($subDiag|Where-Object{$_.targetKind-eq'aks'-and$_.workspaceId}).Count-gt0
    $hasLb=($subDiag|Where-Object{$_.targetKind-eq'lb'-and$_.workspaceId}).Count-gt0

    # â”€â”€ Findings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $findings=[System.Collections.Generic.List[object]]::new()
    foreach($c in $clusters){
        if(-not $c.networkPolicy-or$c.networkPolicy-ieq'none'){$findings.Add([pscustomobject]@{sev='High';cat='Egress control';cluster=$c.name;msg='No Kubernetes NetworkPolicy enforced. All pods can reach the entire internet and any peered/on-prem destination by default.'})}
        if($c.outboundType-ieq'loadBalancer'){$findings.Add([pscustomobject]@{sev='Info';cat='Egress path';cluster=$c.name;msg='outboundType=loadBalancer. SNAT through standard LB. Validate UsedSnatPorts trend and consider NAT Gateway for higher port ceiling or UDR for firewall inspection.'})}
        if($c.outboundType-ieq'userDefinedRouting'){$findings.Add([pscustomobject]@{sev='Info';cat='Egress path';cluster=$c.name;msg='outboundType=userDefinedRouting. Egress forced through NVA/firewall. Verify 0.0.0.0/0 -> VirtualAppliance in route table.'})}
        if(-not $c.apiServerAccessProfile-or-not $c.apiServerAccessProfile.enablePrivateCluster){$findings.Add([pscustomobject]@{sev='Medium';cat='Control plane';cluster=$c.name;msg='Public API server. Authorized IP ranges are the only network control. Prefer private cluster for production workloads.'})}
        # Version lifecycle check
        $vStatus = Get-K8sVersionStatus $c.kubernetesVersion
        if($vStatus.pill -eq 'crit'){$findings.Add([pscustomobject]@{sev='High';cat='Version lifecycle';cluster=$c.name;msg="K8s $($c.kubernetesVersion): $($vStatus.msg)"})}
        elseif($vStatus.pill -eq 'warn'){$findings.Add([pscustomobject]@{sev='Medium';cat='Version lifecycle';cluster=$c.name;msg="K8s $($c.kubernetesVersion): $($vStatus.msg)"})}
    }
    if($nsgIssues-gt0){$findings.Add([pscustomobject]@{sev='Medium';cat='NSG';cluster='(sub)';msg="$nsgIssues rule(s) allow inbound from Internet."})}
    if(-not $hasFlow){$findings.Add([pscustomobject]@{sev='Medium';cat='Telemetry';cluster='(sub)';msg='No flow logs enabled.'})}

    $sbF=[System.Text.StringBuilder]::new();$highC=0;$medC=0
    foreach($f in ($findings|Sort-Object @{e={switch($_.sev){'High'{0}'Medium'{1}default{2}}}})){if($f.sev-eq'High'){$highC++}elseif($f.sev-eq'Medium'){$medC++}
        $cls2=switch($f.sev){'High'{'findingHigh'}'Medium'{'findingMed'}default{'findingLow'}}
        [void]$sbF.AppendLine("<div class='card $cls2'><div>$(SevPill $f.sev)<span class='pill muted'>$(Esc $f.cat)</span> <strong>$(Esc $f.cluster)</strong></div><p>$(Esc $f.msg)</p></div>")}

    # â”€â”€ KQL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $sbK=[System.Text.StringBuilder]::new()
    if($kqlPresent){$wsDirs=Get-ChildItem -Path $kqlSubDir -Directory -EA SilentlyContinue
        if($wsDirs.Count-eq0){[void]$sbK.AppendLine('<p class="muted">No KQL workspaces ran.</p>')}
        foreach($wsd in $wsDirs){[void]$sbK.AppendLine("<div class='card'><h3>Workspace: $(Esc $wsd.Name)</h3>")
            foreach($q in @('TELEMETRY_INVENTORY','NS_INTERNET_EGRESS_TOP','NS_INTERNET_EGRESS_BY_ASN','NS_INTERNET_INGRESS_UNSOLICITED','EW_INTRA_VNET','CROSS_VNET_PEERING','ONPREM_TRAFFIC','PAAS_PE_BYPASS','PER_NODE_ATTRIBUTION','EXFIL_VOLUME_OUTLIERS','EXFIL_BEACONING','EXFIL_LONG_LIVED','EXFIL_UNUSUAL_PORTS','EXFIL_TI_MATCHES','AZFW_APP_RULE_HITS','AZFW_DNS_QUERIES','AZFW_DNS_TUNNELING','AKS_AUDIT_SECRET_READS','CONTAINER_LOG_DNS_FORWARDER')){$csv=Join-Path $wsd.FullName "$q.csv";if(Test-Path $csv){[void]$sbK.AppendLine("<h4>$q</h4>");[void]$sbK.AppendLine((CsvAsTable $csv))}}
            [void]$sbK.AppendLine('</div>')}
    }else{[void]$sbK.AppendLine('<div class="banner">No KQL ran.</div>')}

    # â”€â”€ SVG topology (no-crossing: all arrows Lâ†’R, attached below) â”€
    $svgColors=@{aks=@{f='#e3f2fd';s='#1565c0';t='#0d47a1'};vnet=@{f='#fff3e0';s='#ef6c00';t='#e65100'};lb=@{f='#ede7f6';s='#5e35b1';t='#311b92'};pe=@{f='#e0f7fa';s='#00838f';t='#006064'};ext=@{f='#e8f5e9';s='#2e7d32';t='#1b5e20'};peer=@{f='#f3e5f5';s='#6a1b9a';t='#4a148c'};agw=@{f='#fff8e1';s='#f57f17';t='#e65100'};nsg=@{f='#fce4ec';s='#c62828';t='#b71c1c'};udr=@{f='#efebe9';s='#795548';t='#4e342e'};dns=@{f='#e8eaf6';s='#283593';t='#1a237e'};mon=@{f='#f1f8e9';s='#558b2f';t='#33691e'};gap=@{f='#fff5f5';s='#c62828';t='#b71c1c'}}
    $ci=0;$vnetClusters=[ordered]@{}
    foreach($c in $clusters){$cv=$null;foreach($p in @($c.agentPoolProfiles)){if($p.vnetSubnetID-and$p.vnetSubnetID-match'/virtualNetworks/([^/]+)/'){$cv=$matches[1];break}};if($cv){if(-not $vnetClusters.Contains($cv)){$vnetClusters[$cv]=[System.Collections.Generic.List[object]]::new()};$vnetClusters[$cv].Add($c)}}
    $eLbs=@($subLbs|Where-Object{$_.frontendIpConfigs|Where-Object{$_.properties.publicIPAddress}})
    $iLbs=@($subLbs|Where-Object{($_.frontendIpConfigs|Where-Object{$_.properties.privateIPAddress})-and-not($_.frontendIpConfigs|Where-Object{$_.properties.publicIPAddress})})
    $pvn=@($subPeers|ForEach-Object{ShortId $_.remoteVnetId}|Sort-Object -Unique)
    $nsgAtt=@($subNsgs|Where-Object{$_.subnets-or$_.networkInterfaces}).Count
    $udrNva=@($subRts|Where-Object{$_.routes|Where-Object{$_.properties.nextHopType-eq'VirtualAppliance'}}).Count
    $enFlow=@($subFlows|Where-Object{$_.enabled}).Count

    # Layout
    $bx=@{};$pad=40;$gap=60;$aksW=260;$aksH=64;$vp=14;$sW=220;$sH=58;$smW=140;$smH=52;$aW=160;$aH=42
    $x0=$pad;$x1=$x0+$smW+$gap;$x2=$x1+$sW+$gap;$vnW=$aksW+$vp*2;$x3=$x2+$vnW+$gap+30;$x4=$x3+$sW+$gap
    $curY=$pad+35;$vids=[System.Collections.Generic.List[string]]::new()
    foreach($vn in $vnetClusters.Keys){
        $vid="VN$($vn-replace'[^A-Za-z0-9]','')";$vids.Add($vid)
        $vO=$subVnets|Where-Object name -eq $vn|Select-Object -First 1
        $vC2=if($vO.addressPrefixes){$vO.addressPrefixes-join', '}else{''}
        $vD2=if($vO.dnsServers-and@($vO.dnsServers).Count-gt0){$vO.dnsServers-join', '}else{'Azure DNS'}
        $nC=$vnetClusters[$vn].Count;$iH=$nC*($aksH+12)-12;$vH=$iH+$vp*2+26
        $bx[$vid]=@{x=$x2;y=$curY;w=$vnW;h=$vH;tp='vnet';ln=@("VNet: $vn",$vC2,"DNS: $vD2")}
        $ay=$curY+$vp+22
        foreach($cl in $vnetClusters[$vn]){$ci++;$cid="AKS$ci";$pl=@($cl.agentPoolProfiles).Count;$pr=if($cl.apiServerAccessProfile.enablePrivateCluster){'Private'}else{'Public'}
            $bx[$cid]=@{x=$x2+$vp;y=$ay;w=$aksW;h=$aksH;tp='aks';ln=@($cl.name,"$($cl.networkPlugin) | $($cl.outboundType)","$pr | $pl pool(s)")}
            $ay+=$aksH+12}
        $curY+=$vH+16}
    $r1B=$curY;$mid=($pad+35+$r1B)/2
    # Internet + AGW centered
    $bx['INET']=@{x=$x0;y=[Math]::Max($pad+10,$mid-$smH/2);w=$smW;h=$smH;tp='ext';ln=@('Internet')}
    if($subAgws.Count-gt0){$bx['AGW']=@{x=$x1;y=$mid-$sH/2;w=$sW;h=$sH;tp='agw';ln=@("App GW ($($subAgws.Count))")}}
    # Forward targets (col3) centered
    $fwd=[System.Collections.Generic.List[hashtable]]::new()
    if($eLbs.Count-gt0){$eI=@($eLbs|ForEach-Object{$_.frontendIpConfigs}|Where-Object{$_.properties.publicIPAddress}|ForEach-Object{$po=$subPips|Where-Object id -eq $_.properties.publicIPAddress.id;if($po){$po.ipAddress}else{'PIP'}}|Select-Object -Unique -First 3);$fwd.Add(@{id='LBE';tp='lb';ln=@("Ext LBs ($($eLbs.Count))",($eI-join', '))})}
    if($iLbs.Count-gt0){$iI=@($iLbs|ForEach-Object{$_.frontendIpConfigs}|Where-Object{$_.properties.privateIPAddress}|ForEach-Object{$_.properties.privateIPAddress}|Select-Object -Unique -First 3);$fwd.Add(@{id='LBI';tp='lb';ln=@("Int LBs ($($iLbs.Count))",($iI-join', '))})}
    if($subPes.Count-gt0){$peT=@($subPes|ForEach-Object{$cc=$null;if($_.privateLinkServiceConnections){$cc=$_.privateLinkServiceConnections[0]};if($cc.properties.groupIds){$cc.properties.groupIds[0]}else{'svc'}}|Group-Object|Sort-Object Count -Desc|Select-Object -First 3|ForEach-Object{"$($_.Name)($($_.Count))"});$fwd.Add(@{id='PES';tp='pe';ln=@("PEs ($($subPes.Count))",($peT-join', '))})}
    $fTot=$fwd.Count*($sH+14)-14;$fY=$pad+35+[Math]::Max(0,($r1B-$pad-35-$fTot)/2)
    foreach($fi in $fwd){$bx[$fi.id]=@{x=$x3;y=$fY;w=$sW;h=$sH;tp=$fi.tp;ln=$fi.ln};$fY+=$sH+14}
    # Peers col4
    if($pvn.Count-gt0){$pvL=if($pvn.Count-le2){$pvn-join', '}else{($pvn[0..1]-join', ')+" +$($pvn.Count-2)"};$bx['PEERS']=@{x=$x4;y=$pad+35;w=$smW;h=$smH;tp='peer';ln=@("Peers ($($pvn.Count))",$pvL)}}

    $svgW=$x4+$smW+$pad+20;$svgH=[Math]::Max($r1B,$fY)+50
    $svg=[System.Text.StringBuilder]::new()
    # Render boxes
    foreach($id in $bx.Keys){$b=$bx[$id];$sc=$svgColors[$b.tp];$rx=if($b.tp-eq'ext'){[Math]::Min($b.w,$b.h)/2}else{7};$sw2=if($b.tp-eq'aks'){2}elseif($b.tp-eq'vnet'){1.5}else{1.2};$da=if($b.tp-eq'gap'){'stroke-dasharray="6 3" '}else{''};$op=if($b.tp-eq'vnet'){'fill-opacity=".3" '}else{''}
        [void]$svg.AppendLine("<rect x='$($b.x)' y='$($b.y)' width='$($b.w)' height='$($b.h)' rx='$rx' fill='$($sc.f)' stroke='$($sc.s)' stroke-width='$sw2' $da$op/>")
        $ty=if($b.tp-eq'vnet'){$b.y+15}else{$b.y+16+[Math]::Max(0,($b.h-10-$b.ln.Count*15)/2)};$tli=0
        foreach($tl in $b.ln){if(-not $tl){$tli++;continue};$tfs=if($tli-eq0){'font-weight:600;font-size:12px'}else{'font-size:10px'}
            [void]$svg.AppendLine("<text x='$($b.x+$b.w/2)' y='$ty' text-anchor='middle' fill='$($sc.t)' style='$tfs'>$(Esc $tl)</text>");$ty+=15;$tli++}}
    # Render edges â€” ALL left-to-right, no crossings
    $edg=[System.Collections.Generic.List[object]]::new()
    if($subAgws.Count-gt0){$edg.Add(@{f='INET';t='AGW';l='HTTPS ingress';d=$false})}
    foreach($vid in $vids){
        if($subAgws.Count-gt0){$edg.Add(@{f='AGW';t=$vid;l='ingress';d=$false})}
        if($eLbs.Count-gt0){$edg.Add(@{f=$vid;t='LBE';l='N/S egress';d=$false})}
        if($iLbs.Count-gt0){$edg.Add(@{f=$vid;t='LBI';l='E/W';d=$false})}
        if($subPes.Count-gt0){$edg.Add(@{f=$vid;t='PES';l='PaaS PE';d=$false})}
        if($pvn.Count-gt0){$edg.Add(@{f=$vid;t='PEERS';l='peering';d=$false})}
    }
    # LBEâ†’Internet: arc over top to avoid crossing
    if($eLbs.Count-gt0){$edg.Add(@{f='LBE';t='INET';l='SNAT egress';d=$false;arc=$true})}

    $pc=@{}
    foreach($e in $edg){$fb=$bx[$e.f];$tb=$bx[$e.t];if(-not $fb-or-not $tb){continue}
        $ek="$($e.f)>$($e.t)";if(-not $pc[$ek]){$pc[$ek]=0};$off=$pc[$ek]*7;$pc[$ek]++
        if($e.arc){
            $x1=$fb.x;$y1=$fb.y+6;$x2=$tb.x+$tb.w;$y2=$tb.y+6;$arcY=[Math]::Min($y1,$y2)-35-$off
            [void]$svg.AppendLine("<path d='M$x1,$y1 C$x1,$arcY $x2,$arcY $x2,$y2' fill='none' stroke='#546e7a' stroke-width='.9' marker-end='url(#arr)'/>")
            $mx=[Math]::Round(($x1+$x2)/2);$my=$arcY+8;$tw=[Math]::Max($e.l.Length*6.5,40)
            [void]$svg.AppendLine("<rect x='$($mx-$tw/2)' y='$($my-9)' width='$tw' height='14' rx='4' fill='#fff' fill-opacity='.92'/><text x='$mx' y='$($my+2)' text-anchor='middle' fill='#546e7a' style='font-size:9px'>$(Esc $e.l)</text>")
        }elseif($e.vert){
            $x1=$fb.x+$fb.w/2+$off;$y1=$fb.y+$fb.h;$x2=$tb.x+$tb.w/2;$y2=$tb.y;$my=[Math]::Round(($y1+$y2)/2)
            [void]$svg.AppendLine("<path d='M$x1,$y1 L$x1,$my L$x2,$my L$x2,$y2' fill='none' stroke='#b0bec5' stroke-width='.7' stroke-dasharray='4 3' marker-end='url(#arr)'/>")
        }else{
            $x1=$fb.x+$fb.w;$y1=$fb.y+[Math]::Min($fb.h/2+$off,$fb.h-5);$x2=$tb.x;$y2=$tb.y+[Math]::Min($tb.h/2+$off,$tb.h-5)
            $cx1=[Math]::Round($x1+($x2-$x1)*.35);$cx2=[Math]::Round($x1+($x2-$x1)*.65)
            $dc=if($e.d){'#b0bec5'}else{'#546e7a'};$ds=if($e.d){'.7'}else{'.9'};$dd=if($e.d){'stroke-dasharray="5 3" '}else{''}
            [void]$svg.AppendLine("<path d='M$x1,$y1 C$cx1,$y1 $cx2,$y2 $x2,$y2' fill='none' stroke='$dc' stroke-width='$ds' $dd marker-end='url(#arr)'/>")
            if($e.l){$mx=[Math]::Round(($x1+$x2)/2);$my=[Math]::Round(($y1+$y2)/2)-3;$tw=[Math]::Max($e.l.Length*5,30)
                [void]$svg.AppendLine("<rect x='$($mx-$tw/2)' y='$($my-7)' width='$tw' height='11' rx='3' fill='#fff' fill-opacity='.92'/><text x='$mx' y='$($my+1)' text-anchor='middle' fill='#78909c' style='font-size:6.5px'>$(Esc $e.l)</text>")}
        }}
    # Legend
    $ly=$svgH-38;$legI=@(@('AKS','aks'),@('VNet','vnet'),@('LB','lb'),@('PE','pe'),@('Peer','peer'),@('Internet','ext'))
    [void]$svg.AppendLine("<rect x='$pad' y='$($ly-8)' width='$($svgW-$pad*2)' height='28' rx='5' fill='#f8fafc' stroke='#e2e8f0'/>")
    $lx=$pad+10;foreach($li in $legI){$sc=$svgColors[$li[1]]
        [void]$svg.AppendLine("<rect x='$lx' y='$($ly+1)' width='10' height='10' rx='2' fill='$($sc.f)' stroke='$($sc.s)'/><text x='$($lx+14)' y='$($ly+9)' fill='$($sc.t)' style='font-size:9px'>$($li[0])</text>");$lx+=60+($li[0].Length*3)}

    $svgDiagram = @"
<div class='svgDiag'>
<button class='exportBtn' onclick="exportSvg('topo-$subId','AKSAssessment-$(Sanitize $subName)')">Export SVG</button>
<button class='exportBtn' style='right:100px' onclick='exportPage()'>Print</button>
<svg id='topo-$subId' xmlns='http://www.w3.org/2000/svg' viewBox='0 0 $svgW $svgH' style='font-family:Segoe UI,system-ui,sans-serif'>
<defs><marker id='arr' markerWidth='6' markerHeight='5' refX='6' refY='2.5' orient='auto'><path d='M0,0 L6,2.5 L0,5 Z' fill='#546e7a'/></marker></defs>
<rect width='$svgW' height='$svgH' fill='#fff' rx='8'/>
<text x='$($svgW/2)' y='18' text-anchor='middle' fill='#1e293b' style='font-size:12px;font-weight:700'>AKS Network Topology - $(Esc $subName)</text>
$($svg.ToString())
</svg>
</div>
"@

    # â”€â”€ Gap analysis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $hasPrivC=($clusters|Where-Object{$_.apiServerAccessProfile.enablePrivateCluster}).Count
    $hasNP=($clusters|Where-Object{$_.networkPolicy-and$_.networkPolicy-ine'none'}).Count
    $hasUdrC=($clusters|Where-Object{$_.outboundType-ieq'userDefinedRouting'}).Count
    $noNsg=@($subVnets|ForEach-Object{@($_.subnets)}|Where-Object{-not $_.properties.networkSecurityGroup}).Count
    $customDns=@($subVnets|Where-Object{$_.dnsServers-and@($_.dnsServers).Count-gt0}).Count
    $gapHtml = @"
<div class='card'><h3>Gap analysis</h3><table class='smallTable'><thead><tr><th>Area</th><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>
<tr><td>Security</td><td>Private clusters</td><td>$(if($hasPrivC-eq$clusters.Count){PillFor $true}else{PillFor $false})</td><td>$hasPrivC/$($clusters.Count)</td></tr>
<tr><td>Security</td><td>NetworkPolicy</td><td>$(if($hasNP-eq$clusters.Count){PillFor $true}else{PillFor $false})</td><td>$hasNP/$($clusters.Count)</td></tr>
<tr><td>Security</td><td>Egress via FW</td><td>$(if($hasUdrC-gt0){PillFor $true}else{PillFor $false})</td><td>$hasUdrC/$($clusters.Count) UDR</td></tr>
<tr><td>Security</td><td>NSG coverage</td><td>$(if($noNsg-eq0){PillFor $true}else{PillFor $false})</td><td>$(if($noNsg-gt0){"$noNsg without NSG"}else{'All covered'})</td></tr>
<tr><td>Observe</td><td>Flow logs</td><td>$(PillFor $hasFlow)</td><td>$enFlow/$($subFlows.Count)</td></tr>
<tr><td>Observe</td><td>Traffic Analytics</td><td>$(PillFor $hasTA)</td><td>$(if($hasTA){'On'}else{'Off'})</td></tr>
<tr><td>Observe</td><td>AKS diag</td><td>$(PillFor $hasAks)</td><td>$(if($hasAks){'Yes'}else{'No'})</td></tr>
<tr><td>DNS</td><td>Custom DNS</td><td><span class='pill muted'>INFO</span></td><td>$customDns/$($subVnets.Count)</td></tr>
<tr><td>DNS</td><td>Private DNS</td><td>$(PillFor($subPdns2.Count-gt0))</td><td>$($subPdns2.Count) zones</td></tr>
</tbody></table></div>
"@

    # â”€â”€ Compose HTML â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    $reportFile = if ($StableFilename) {
        "{0}-AKSAssessment.html" -f (Sanitize $subName)
    } else {
        "{0}-AKSAssessment-{1}.html" -f (Sanitize $subName), $ts
    }
    @"
<!doctype html><html lang='en'><head><meta charset='utf-8'><title>AKS Traffic Flow - $(Esc $subName)</title>$css</head><body>
<div class='nav'><strong>AKS Traffic Flow</strong><a href='index.html'>&larr; Index</a><span class='muted'>|</span><span class='muted'>$(Esc $subName)</span><span class='muted'>$ts</span><span style='flex:1'></span>
<a href='#summary'>Summary</a><a href='#topology'>Topology</a><a href='#coverage'>Coverage</a><a href='#versions'>Versions</a><a href='#clusters'>Clusters</a><a href='#vnets'>VNets</a><a href='#lbs'>LBs</a><a href='#agw'>AGW</a><a href='#pips'>PIPs</a><a href='#pes'>PEs</a><a href='#routes'>UDR</a><a href='#peerings'>Peerings</a><a href='#nsgs'>NSGs</a><a href='#findings'>Findings</a><a href='#recs'>Recs</a><a href='#kql'>KQL</a><a href='javascript:void(0)' onclick='toggleAll()' style='background:#f1f5f9;padding:2px 8px;border-radius:4px;font-size:.75rem'>Collapse/Expand All</a></div>
<div class='container'>
<div class='disclaimer'><strong>Disclaimer:</strong> This is an <strong>unofficial</strong> community report, <strong>not</strong> a Microsoft product. Provided <strong>as-is</strong>. See repository for source.</div>
<div class='bannerOk'>READ-ONLY &mdash; zero writes.</div>
<h1 id='summary'>$(Esc $subName)</h1><p class='muted'><code>$subId</code> &middot; $(Esc $TenantName) &middot; $ts</p>
<div class='card'><div class='grid4' style='text-align:center'>
<div class='stat'><div class='num'>$($clusters.Count)</div><div class='lbl'>Clusters</div></div>
<div class='stat'><div class='num'>$($subVnets.Count)</div><div class='lbl'>VNets</div></div>
<div class='stat'><div class='num'>$($subPeers.Count)</div><div class='lbl'>Peerings</div></div>
<div class='stat'><div class='num'>$($subLbs.Count)</div><div class='lbl'>LBs</div></div>
<div class='stat'><div class='num'>$($subPips.Count)</div><div class='lbl'>PIPs</div></div>
<div class='stat'><div class='num'>$($subPes.Count)</div><div class='lbl'>PEs</div></div>
<div class='stat'><div class='num'>$($subRts.Count)</div><div class='lbl'>UDRs</div></div>
<div class='stat'><div class='num'>$($subNsgs.Count)</div><div class='lbl'>NSGs</div></div>
<div class='stat'><div class='num'>$($subFlows.Count)</div><div class='lbl'>Flows</div></div>
<div class='stat'><div class='num'>$($subAgws.Count)</div><div class='lbl'>AGWs</div></div>
</div></div>
<h2 id='topology'>AKS network design</h2>
$svgDiagram
$gapHtml
<h2 id='coverage'>Telemetry</h2><details open><summary>Telemetry coverage</summary><div class='card'><table><thead><tr><th>Source</th><th>OK</th><th>For</th></tr></thead><tbody>
<tr><td>Flow logs</td><td>$(PillFor $hasFlow)</td><td>Traffic</td></tr>
<tr><td>Traffic Analytics</td><td>$(PillFor $hasTA)</td><td>KQL</td></tr>
<tr><td>AKS diag</td><td>$(PillFor $hasAks)</td><td>Audit</td></tr>
<tr><td>LB diag</td><td>$(PillFor $hasLb)</td><td>SNAT</td></tr>
<tr><td>FW logs</td><td>$(PillFor $hasFw)</td><td>FQDN</td></tr>
</tbody></table></div></details>
<h2 id='versions'>AKS version assessment</h2>
<details open><summary>Version lifecycle status</summary>
<div class='card'>
<table class='smallTable'>
<thead><tr><th>Cluster</th><th>Version</th><th>Status</th><th>Detail</th><th>Action</th></tr></thead>
<tbody>
$(foreach($c in $clusters){ $vs=Get-K8sVersionStatus $c.kubernetesVersion; "<tr><td><strong>$(Esc $c.name)</strong></td><td><code>$(Esc $c.kubernetesVersion)</code></td><td><span class='pill $($vs.pill)'>$($vs.status)</span></td><td>$($vs.msg)</td><td>$(if($vs.pill-eq'crit'){"<a href='https://learn.microsoft.com/en-us/azure/aks/upgrade-aks-cluster' target='_blank'>Upgrade now</a>"}elseif($vs.pill-eq'warn'){"<a href='https://learn.microsoft.com/en-us/azure/aks/upgrade-aks-cluster' target='_blank'>Plan upgrade</a>"}else{'Current'})</td></tr>"})
</tbody></table>
<p class='muted' style='margin-top:.5rem'>AKS GA supported: 1.33, 1.34, 1.35 | Platform support: 1.32 | Source: <a href='https://learn.microsoft.com/en-us/azure/aks/supported-kubernetes-versions' target='_blank'>AKS supported versions</a> | <a href='https://releases.aks.azure.com/' target='_blank'>AKS release tracker</a></p>
</div></details>
<h2 id='clusters'>Clusters ($($clusters.Count))</h2><details open><summary>$($clusters.Count) AKS cluster(s)</summary>$($sbC.ToString())</details>
<h2 id='vnets'>VNets ($($subVnets.Count))</h2><details open><summary>$($subVnets.Count) VNet(s)</summary>$($sbV.ToString())</details>
<h2 id='lbs'>Load Balancers ($($subLbs.Count))</h2><details open><summary>$($subLbs.Count) load balancer(s)</summary>$($sbL.ToString())</details>
$(if($subAgws.Count-gt0){"<h2 id='agw'>App Gateways ($($subAgws.Count))</h2><details open><summary>$($subAgws.Count) app gateway(s)</summary>$($sbAG.ToString())</details>"})
<h2 id='pips'>Public IPs ($($subPips.Count))</h2><details><summary>$($subPips.Count) public IP(s)</summary>$($sbP.ToString())</details>
<h2 id='pes'>Private Endpoints ($($subPes.Count))</h2><details><summary>$($subPes.Count) private endpoint(s)</summary>$($sbE.ToString())</details>
<h2 id='routes'>Route Tables ($($subRts.Count))</h2><details open><summary>$($subRts.Count) route table(s)</summary>$($sbR.ToString())</details>
<h2 id='peerings'>Peerings ($($subPeers.Count))</h2><details><summary>$($subPeers.Count) peering(s)</summary>$($sbPR.ToString())</details>
<h2 id='nsgs'>NSGs ($($subNsgs.Count))</h2><details open><summary>$($nsgHighlightCount) highlighted rule(s) across $($subNsgs.Count) NSG(s)</summary>$($sbN.ToString())</details>
<h2 id='findings'>Findings ($($findings.Count))</h2><details open><summary>$($findings.Count) finding(s)</summary>$($sbF.ToString())</details>
<h2 id='recs'>Recommendations <span class='muted'>(linked to official AKS docs)</span></h2>
<div class='card'>
<h3>Networking &amp; egress control</h3>
<table class='smallTable'>
<thead><tr><th>Recommendation</th><th>Applies when</th><th>Official doc</th></tr></thead>
<tbody>
<tr><td><strong>Enable NetworkPolicy</strong> &mdash; restrict pod-to-pod + pod-to-internet traffic</td><td>networkPolicy = none</td><td><a href='https://learn.microsoft.com/en-us/azure/aks/use-network-policies' target='_blank'>Secure traffic between pods</a></td></tr>
<tr><td><strong>Use private clusters</strong> &mdash; API server on private IP</td><td>enablePrivateCluster = false</td><td><a href='https://learn.microsoft.com/en-us/azure/aks/private-clusters' target='_blank'>Create a private AKS cluster</a></td></tr>
<tr><td><strong>Control egress with Azure Firewall</strong> &mdash; UDR + FQDN allow rules</td><td>outboundType = loadBalancer</td><td><a href='https://learn.microsoft.com/en-us/azure/aks/limit-egress-traffic' target='_blank'>Control egress traffic</a></td></tr>
<tr><td><strong>Network-isolated clusters</strong> &mdash; private ACR, no public MCR</td><td>High-security environments</td><td><a href='https://learn.microsoft.com/en-us/azure/aks/concepts-network-isolated' target='_blank'>Network-isolated cluster</a></td></tr>
<tr><td><strong>Azure CNI Overlay</strong> &mdash; simplified IP planning</td><td>IP address exhaustion</td><td><a href='https://learn.microsoft.com/en-us/azure/aks/azure-cni-overlay' target='_blank'>Azure CNI Overlay</a></td></tr>
<tr><td><strong>Enable LocalDNS</strong> &mdash; reduce CoreDNS bottleneck</td><td>Large clusters / high DNS QPS</td><td><a href='https://learn.microsoft.com/en-us/azure/aks/localdns-custom' target='_blank'>Configure LocalDNS</a></td></tr>
<tr><td><strong>WAF for ingress</strong> &mdash; App Gateway for Containers</td><td>Public-facing workloads</td><td><a href='https://learn.microsoft.com/en-us/azure/application-gateway/for-containers/overview' target='_blank'>App Gateway for Containers</a></td></tr>
<tr><td><strong>App routing add-on</strong> &mdash; managed NGINX + DNS + TLS</td><td>Need ingress controller</td><td><a href='https://learn.microsoft.com/en-us/azure/aks/app-routing' target='_blank'>App routing add-on</a></td></tr>
</tbody></table>
<h3 style='margin-top:1.25rem'>Security &amp; operations</h3>
<table class='smallTable'>
<thead><tr><th>Recommendation</th><th>Applies when</th><th>Official doc</th></tr></thead>
<tbody>
<tr><td><strong>Required outbound FQDNs</strong> &mdash; MCR, management.azure.com, login.microsoftonline.com</td><td>Egress restricted clusters</td><td><a href='https://learn.microsoft.com/en-us/azure/aks/outbound-rules-control-egress' target='_blank'>Required outbound FQDNs</a></td></tr>
<tr><td><strong>Bastion host for nodes</strong> &mdash; never expose nodes directly</td><td>All clusters</td><td><a href='https://learn.microsoft.com/en-us/azure/aks/operator-best-practices-network#securely-connect-to-nodes-through-a-bastion-host' target='_blank'>Connect via bastion</a></td></tr>
<tr><td><strong>Defender for Containers</strong> &mdash; runtime threat detection</td><td>Production clusters</td><td><a href='https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction' target='_blank'>Defender for Containers</a></td></tr>
<tr><td><strong>Diagnostic settings to LAW</strong> &mdash; required for SNAT + audit + KQL</td><td>Diagnostics missing</td><td><a href='https://learn.microsoft.com/en-us/azure/aks/monitor-aks' target='_blank'>Monitor AKS</a></td></tr>
<tr><td><strong>VNet flow logs + Traffic Analytics</strong></td><td>Flow logs disabled</td><td><a href='https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview' target='_blank'>VNet flow logs</a></td></tr>
<tr><td><strong>Plan cluster upgrades</strong> &mdash; Azure Linux 2.0 EOL March 2026</td><td>All clusters</td><td><a href='https://learn.microsoft.com/en-us/azure/aks/upgrade-aks-cluster' target='_blank'>Upgrade AKS cluster</a></td></tr>
</tbody></table>
<h3 style='margin-top:1.25rem'>Additional best practices</h3>
<ul>
<li><a href='https://learn.microsoft.com/en-us/azure/aks/best-practices' target='_blank'>AKS best practices overview</a></li>
<li><a href='https://learn.microsoft.com/en-us/azure/aks/operator-best-practices-network' target='_blank'>Network connectivity &amp; security</a></li>
<li><a href='https://learn.microsoft.com/en-us/azure/aks/concepts-network' target='_blank'>Networking concepts</a></li>
<li><a href='https://learn.microsoft.com/en-us/azure/aks/operator-best-practices-cluster-security' target='_blank'>Cluster security &amp; upgrades</a></li>
<li><a href='https://learn.microsoft.com/en-us/azure/architecture/reference-architectures/containers/aks-start-here' target='_blank'>Plan your AKS design</a></li>
</ul>
</div>
<h2 id='kql'>KQL evidence</h2>$($sbK.ToString())
</div>$jsScript</body></html>
"@ | Out-File (Join-Path $OutputDir $reportFile) -Encoding utf8
    Write-Output "  -> $reportFile"
    # Version status summary for index
    $verEol=@($clusters|Where-Object{$vs2=Get-K8sVersionStatus $_.kubernetesVersion;$vs2.pill-eq'crit'}).Count
    $verWarn=@($clusters|Where-Object{$vs2=Get-K8sVersionStatus $_.kubernetesVersion;$vs2.pill-eq'warn'}).Count
    $verOk=@($clusters|Where-Object{$vs2=Get-K8sVersionStatus $_.kubernetesVersion;$vs2.pill-eq'ok'}).Count
    $indexEntries.Add([pscustomobject]@{subName=$subName;subId=$subId;clusters=$clusters.Count;vnets=$subVnets.Count;pes=$subPes.Count;lbs=$subLbs.Count;pips=$subPips.Count;rts=$subRts.Count;highFinds=$highC;medFinds=$medC;totalFinds=$findings.Count;fileName=$reportFile;findings=$findings;k8sVersions=@($clusters.kubernetesVersion|Sort-Object -Unique);verEol=$verEol;verWarn=$verWarn;verOk=$verOk})
}

# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# INDEX.HTML
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
Write-Output "Building index.html..."
$tC=$aks.Count;$tV=$vnets.Count;$tP=$pes.Count;$tL=$lbs.Count;$tI=$pips.Count;$tN=$nsgs.Count;$tR=$rts.Count;$tF=$flowlogs.Count
$tH=($indexEntries|Measure-Object -Property highFinds -Sum).Sum;$tM=($indexEntries|Measure-Object -Property medFinds -Sum).Sum;$tA=($indexEntries|Measure-Object -Property totalFinds -Sum).Sum
$tocList=[System.Text.StringBuilder]::new()
$idx=0
foreach($e in ($indexEntries|Sort-Object subName)){
    $idx++
    $sevPill=if($e.highFinds-gt0){"<span class='pill crit' style='font-size:.65rem;padding:0 5px'>$($e.highFinds)H</span>"}elseif($e.medFinds-gt0){"<span class='pill warn' style='font-size:.65rem;padding:0 5px'>$($e.medFinds)M</span>"}else{"<span class='pill ok' style='font-size:.65rem;padding:0 5px'>OK</span>"}
    [void]$tocList.AppendLine("<li><span class='muted' style='font-size:.7rem'>$idx.</span> <a href='$($e.fileName)'>$(Esc $e.subName)</a> $sevPill<span class='tocMeta'>$($e.clusters) cluster$(if($e.clusters-ne1){'s'})</span></li>")
}
$tocRows=[System.Text.StringBuilder]::new()
foreach($e in ($indexEntries|Sort-Object subName)){$hp=if($e.highFinds-gt0){"<span class='pill crit'>$($e.highFinds) High</span>"}else{''};$mp=if($e.medFinds-gt0){"<span class='pill warn'>$($e.medFinds) Med</span>"}else{''}
    # Version status pills per version
    $verPills=[System.Text.StringBuilder]::new()
    foreach($v in $e.k8sVersions){
        $vs3=Get-K8sVersionStatus $v
        [void]$verPills.Append("<span class='pill $($vs3.pill)' title='$($vs3.status)'>$v</span> ")
    }
    [void]$tocRows.AppendLine("<a href='$($e.fileName)' style='text-decoration:none;color:inherit'><div class='indexCard'><div><strong>$($e.subName)</strong><br><span class='muted'><code>$($e.subId)</code></span><br><span style='font-size:.75rem'>$($verPills.ToString())</span></div><div class='grid4' style='gap:.5rem;text-align:center'><div><div style='font-weight:700'>$($e.clusters)</div><div class='muted' style='font-size:.7rem'>clusters</div></div><div><div style='font-weight:700'>$($e.vnets)</div><div class='muted' style='font-size:.7rem'>VNets</div></div><div><div style='font-weight:700'>$($e.pes)</div><div class='muted' style='font-size:.7rem'>PEs</div></div><div><div style='font-weight:700'>$($e.lbs)</div><div class='muted' style='font-size:.7rem'>LBs</div></div></div><div>$hp $mp</div></div></a>")}
$issueCards=[System.Text.StringBuilder]::new()
foreach($e in ($indexEntries|Sort-Object subName)){foreach($f in @($e.findings)){if($f.sev-in@('High','Medium')){$cc=if($f.sev-eq'High'){'issueCard'}else{'issueCard issueCardMed'};[void]$issueCards.AppendLine("<div class='$cc'><div>$(SevPill $f.sev)<span class='pill muted'>$(Esc $f.cat)</span> <strong>$(Esc $f.cluster)</strong> &mdash; <a href='$($e.fileName)#findings'>$(Esc $e.subName)</a></div><p class='muted'>$(Esc $f.msg)</p></div>")}}}
@"
<!doctype html><html lang='en'><head><meta charset='utf-8'><title>AKS Traffic Flow - $(Esc $TenantName)</title>$css</head><body>
<div class='nav'><strong>AKS Traffic Flow</strong><span class='muted'>$(Esc $TenantName)</span><span class='muted'>$ts</span><span style='flex:1'></span>
<a href='#summary'>Summary</a><a href='#reports'>Reports</a><a href='#subscriptions'>Subs</a><a href='#issues'>Issues</a><a href='#limitations'>Limits</a></div>
<div class='container'>
<div class='disclaimer'><strong>Disclaimer:</strong> Unofficial community report, <strong>not</strong> Microsoft. Provided <strong>as-is</strong>. See repository for source.</div>
<div class='bannerOk'>READ-ONLY &mdash; zero writes.</div>
<h1 id='summary'>AKS Traffic Flow</h1><p class='muted'>$(Esc $TenantName) &middot; $ts</p>
<div class='card'><h3>Summary</h3><div class='grid4' style='text-align:center;margin-top:.5rem'>
<div class='stat'><div class='num'>$($indexEntries.Count)</div><div class='lbl'>Subs</div></div>
<div class='stat'><div class='num'>$tC</div><div class='lbl'>Clusters</div></div>
<div class='stat'><div class='num'>$tV</div><div class='lbl'>VNets</div></div>
<div class='stat'><div class='num'>$tP</div><div class='lbl'>PEs</div></div>
<div class='stat'><div class='num'>$tL</div><div class='lbl'>LBs</div></div>
<div class='stat'><div class='num'>$tI</div><div class='lbl'>PIPs</div></div>
<div class='stat'><div class='num'>$tN</div><div class='lbl'>NSGs</div></div>
<div class='stat'><div class='num'>$tR</div><div class='lbl'>UDRs</div></div>
<div class='stat'><div class='num'>$tF</div><div class='lbl'>Flows</div></div>
</div>
<div style='margin-top:.75rem;display:flex;gap:1rem;justify-content:center'>
$(if($tH-gt0){"<span class='pill crit' style='font-size:.85rem;padding:3px 14px'>$tH High</span>"}else{""})
$(if($tM-gt0){"<span class='pill warn' style='font-size:.85rem;padding:3px 14px'>$tM Medium</span>"}else{""})
<span class='pill muted' style='font-size:.85rem;padding:3px 14px'>$tA total</span>
</div></div>
<h2 id='reports'>Reports index</h2>
<div class='card'><p class='muted' style='margin-top:0'>Jump directly to a per-subscription report. <strong>$($indexEntries.Count)</strong> subscription$(if($indexEntries.Count-ne1){'s'}) with AKS clusters.</p>
<ol class='tocList'>$($tocList.ToString())</ol></div>
<h2 id='subscriptions'>Subscriptions ($($indexEntries.Count))</h2>
$($tocRows.ToString())
<h2 id='issues'>Issues</h2>
$($issueCards.ToString())$(if($tH-eq0-and$tM-eq0){"<p class='muted'>None.</p>"})
<h2 id='limitations'>Known limitations</h2><div class='card'><table class='smallTable'>
<thead><tr><th>Gap</th><th>Impact</th><th>Fix</th></tr></thead><tbody>
<tr><td>Pod attribution (CNI Overlay)</td><td>Node IP only</td><td>ACNS/Retina/Hubble</td></tr>
<tr><td>FQDN attribution</td><td>IP only</td><td>CoreDNS logging or FW FQDN</td></tr>
<tr><td>Encrypted payloads</td><td>No inspection</td><td>TLS termination</td></tr>
<tr><td>Intra-pod flows</td><td>Not captured</td><td>APM/OTel</td></tr>
<tr><td>Guest RBAC check</td><td>False negatives</td><td>Informational</td></tr>
<tr><td>Diag coverage</td><td>$diagCoveredCount/$diagTotalCount have LAW</td><td>Enable diag settings</td></tr>
$(foreach($k in $diagBreakdown){ "<tr><td class='muted' style='padding-left:1.5rem'>&nbsp;&nbsp;$($k.kind)</td><td class='muted'>$($k.covered)/$($k.total)</td><td class='muted'>per resource kind</td></tr>" })
</tbody></table></div></div></body></html>
"@ | Out-File (Join-Path $OutputDir "index.html") -Encoding utf8
Write-Output "  -> index.html"
Write-Output "Done."

