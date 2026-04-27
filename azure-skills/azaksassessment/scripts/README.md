# AzAKSAssessment â€” Read-Only AKS Traffic Discovery & Exfiltration Hunt

> **Disclaimer:** This is an **unofficial** community tool and is **not** an official Microsoft product, service, or recommendation. It is provided **as-is**, without warranty of any kind, express or implied. Use at your own risk. Source: the upstream repository

Discovery and analysis of **all directions** of AKS traffic â€” north/south internet, east/west, cross-VNet via peering / hub / vWAN, on-prem via VPN/ExpressRoute, PaaS via Service Endpoints vs Private Endpoints â€” plus an in-depth exfiltration hunt against existing telemetry.

## Absolute read-only guarantee

This assessment performs **zero writes / modifications / updates / changes / deletes** of **any** kind, against **any** Azure resource, Kubernetes object, diagnostic setting, alert rule, NSG, NetworkPolicy, CoreDNS ConfigMap, route table, firewall rule, or anything else.

Only these verbs are permitted from any script in this folder:

- `az ... show | list | graph query`
- `Get-Az*` / `Search-AzGraph` / `Invoke-AzOperationalInsightsQuery`
- `kubectl get | describe | api-resources | api-versions` (read-only)

Disallowed (must never appear): `new-`, `set-`, `remove-`, `update-`, `add-`, `start-`, `stop-`, `restart-`, `invoke-azrest` with non-GET method, `kubectl exec | debug | port-forward | apply | patch | delete | cp | edit | replace | scale | rollout | label | annotate | taint | drain | cordon | uncordon`, `helm install | upgrade | uninstall | rollback`, `tcpdump`, any data-plane upload, any diagnostic-setting / flow-log / alert / workbook creation. Reviewers must reject patches that introduce any of these.

## Tenant binding

Pass your tenant domain via `-RequiredTenantDomain <domain>`. Every script enforces this with a tenant guard and aborts if the current az context doesn't match. If omitted, the tenant guard is skipped.

```powershell
az login --tenant <your-tenant>.onmicrosoft.com
```

## Scope rule

For the target tenant, the assessment **discovers every subscription that contains at least one AKS cluster** (`microsoft.containerservice/managedclusters`). For each such "AKS-bearing" subscription it automatically pulls in:

- the subscriptions of any VNets peered to a cluster VNet (typical hub spokes),
- the connectivity subscription(s) hosting ExpressRoute / VPN gateways,
- on-prem prefix correlation (you supply the RFC1918 ranges considered "on-prem").

**One HTML report is emitted per AKS-bearing subscription.** Hub / connectivity subs are read for context only and do not get a standalone report.

## Required permissions (least-privilege, read-only)

See `precheck.ps1` for an automated check. Summary:

| Role | Scope | Why |
|---|---|---|
| `Reader` | every in-scope subscription (AKS subs + hub + connectivity) | Enumerate AKS, VNets, subnets, NSGs, route tables, LBs, NAT GW, peerings, gateways, PEs, Private DNS, Network Watcher, flow logs, Azure Firewall. |
| `Azure Kubernetes Service Cluster User Role` | each AKS cluster | kubeconfig for read-only `kubectl get/describe`. **Not** cluster-admin. |
| `Monitoring Reader` | each AKS sub + workspace + LB/NAT GW/FW resources | Read metrics on every device in the path. |
| `Log Analytics Reader` | each Log Analytics workspace holding flow logs / firewall logs / Container Insights | Run the Phase 3+4 KQL library. |

Conditional (only if the source exists): `Storage Blob Data Reader` on flow-log storage (when no Traffic Analytics), `Reader` on Azure Firewall RG, `Reader` on Private DNS zones RG, `Microsoft Sentinel Reader` for TI joins.

**Deliberately not requested:** `Contributor`, `Network Contributor`, `*Cluster Admin*`, `Log Analytics Contributor`, `Owner`, `Storage Blob Data Contributor`.

## Run order

```
1. precheck.ps1              # confirm read-only RBAC across all in-scope subs
2. discover-scope.ps1        # find AKS-bearing subs + auto-include peers/hub/connectivity
3. collect-data.ps1          # ARG inventory of AKS, networking, telemetry surfaces
4. collect-effective-routes.ps1   # per-pool node NIC effective routes + NSGs (ground truth)
5. collect-metrics.ps1       # LB SNAT, NAT GW, FW capacity metrics
6. collect-kql.ps1           # run Queries.kql against each detected workspace
7. generate-reports.ps1      # one HTML report per AKS-bearing subscription
```

Or run all via `run.ps1`.

## Output layout

```
<TenantOrCustomer>/<yyyy-MM-dd_HHmm>-AKSAssessment/
  data/
    scoped-subscriptions.json
    arg-aks.json
    arg-vnets.json
    arg-peerings.json
    arg-nsgs.json
    arg-routetables.json
    arg-loadbalancers.json
    arg-natgateways.json
    arg-firewalls.json
    arg-privateendpoints.json
    arg-privatednszones.json
    arg-publicips.json
    arg-gateways.json
    arg-flowlogs.json
    arg-networkwatchers.json
    arg-law.json
    effective-routes-<aksname>.json   # per AKS cluster
    effective-nsgs-<aksname>.json
    metrics-<aksname>.json
    kql-<workspace>-<query>.csv
  reports/
    <subname>-AKSAssessment-<ts>.html  # ONE per AKS-bearing sub
```

