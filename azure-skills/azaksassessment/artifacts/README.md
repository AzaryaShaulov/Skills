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

Run `precheck.ps1` for an automated check. The whole toolchain is **read-only** — no built-in role with write capability is requested.

### Built-in roles

| Role | Scope | Used by | Why |
|---|---|---|---|
| `Reader` | every in-scope subscription (AKS subs + hub + connectivity) | `discover-scope.ps1`, `collect-data.ps1`, `generate-reports.ps1` | Enumerate AKS, VNets, subnets, NSGs, route tables, LBs, NAT GW, peerings, gateways, PEs, Private DNS, Network Watcher, flow logs, Azure Firewall. |
| `Azure Kubernetes Service Cluster User Role` | each AKS cluster | optional `kubectl` follow-up | Pull kubeconfig for read-only `kubectl get/describe`. **Not** cluster-admin. |
| `Monitoring Reader` | each AKS sub + workspace + LB/NAT GW/FW resource | `collect-metrics.ps1`, `collect-kql.ps1` | Read platform metrics on every device in the path. |
| `Log Analytics Reader` | each Log Analytics workspace (Container Insights, flow logs, firewall logs) | `collect-kql.ps1` | Run the KQL query library. Required for both in-scope LAW and any cross-sub LAW resolved on the fly (`arg-law-resolved.json`). |

### Specific data-plane actions (not covered by `Reader`)

`collect-effective-routes.ps1` calls effective-route / effective-NSG endpoints on AKS **node NICs**. These are POST "actions", not `*/read`, and `Reader` is **not** sufficient. Grant either:

| Option | Scope | Actions granted |
|---|---|---|
| Built-in `Network Contributor` | each AKS node resource group (`MC_*`) | Includes the two actions below — easiest grant. |
| Custom role (preferred, true least-privilege) | each AKS node resource group (`MC_*`) | `Microsoft.Network/networkInterfaces/effectiveRouteTable/action`, `Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action` |

Without these, step 4 emits authorization failures and the per-pool routing/NSG sections in the report will be empty. The rest of the assessment still runs.

### Microsoft Graph (precheck only)

`precheck.ps1` issues a few Graph reads (signed-in user, tenant info) for context. A guest / external identity blocked by tenant Conditional Access (e.g., `AADSTS530004` "compliant device required") will fail this step. Because precheck is **advisory**, `run.ps1` downgrades the failure to a warning and continues. Use `-StrictPrecheck` to abort instead. Fix at the environment level by signing in from a compliant device or using a member identity.

### Conditional (only if the source exists)

| Role | Scope | When |
|---|---|---|
| `Storage Blob Data Reader` | flow-log storage account | NSG/VNet flow logs without Traffic Analytics |
| `Reader` | Azure Firewall RG | Firewall present in path |
| `Reader` | Private DNS zones RG | Private DNS resolution in scope |
| `Microsoft Sentinel Reader` | Sentinel workspace | TI-match queries in `Queries.kql` |

### Cross-subscription Log Analytics

If a workspace referenced by a diagnostic setting lives **outside** the assessment scope (e.g., a central observability subscription), `collect-kql.ps1` will resolve it on the fly via `az monitor log-analytics workspace show`. The signed-in identity needs `Reader` + `Log Analytics Reader` in **that** subscription too, or the workspace will be flagged unresolvable and skipped.

### Deliberately not requested

`Contributor`, `Network Contributor` at sub scope, `*Cluster Admin*`, `Log Analytics Contributor`, `Owner`, `Storage Blob Data Contributor`, `User Access Administrator`.

## Run order

```powershell
# 1. precheck.ps1              # confirm read-only RBAC across all in-scope subs
# 2. discover-scope.ps1        # find AKS-bearing subs + auto-include peers/hub/connectivity
# 3. collect-data.ps1          # ARG inventory of AKS, networking, telemetry surfaces
# 4. collect-effective-routes.ps1   # per-pool node NIC effective routes + NSGs
# 5. collect-metrics.ps1       # LB SNAT, NAT GW, FW capacity metrics
# 6. collect-kql.ps1           # run Queries.kql against each detected workspace
# 7. generate-reports.ps1      # per-sub HTML + index.html
```

Or run all via `run.ps1`.

### Direct-invocation caveats

- `collect-data.ps1` defaults `-ScopeFile` to `<OutputDir>\scope.json`. If you pass `-OutputDir` to a fresh folder you **must** also place a `scope.json` there (typically by running `discover-scope.ps1 -OutputDir <same folder>` first) or pass `-ScopeFile` explicitly. Without this, the script fails fast — no more silent fall-back to a shared scope file.
- `generate-reports.ps1` accepts `-StableFilename` to overwrite the per-sub HTML on rerun (instead of writing a new timestamped file each time). `run.ps1` passes this by default; opt out at the orchestrator level via `-TimestampedFilenames`.
- `run.ps1` skips a phase whose primary artifact in `-OutputDir` is younger than `-MaxDataAgeHours` (default 24). Use `-ForceRefresh` to override or `-MaxDataAgeHours 0` to always re-collect.

## Output layout

Both `run.ps1` and direct invocation of any individual script (when `-OutputDir`
/ `-DataDir` are not supplied) write into the same per-run dated tree under
`azaksassessment\reports\`. The customer label resolves from `-TenantName` →
first label of `-RequiredTenantDomain` → `Customer`.

```
azaksassessment\reports\
└── <yyyy-MM-dd>_<CustomerName>\
    ├── <yyyy-MM-dd>_Data\
    │     precheck-summary.json
    │     scope.json
    │     scoped-subscriptions.json
    │     arg-aks.json
    │     arg-vnets.json
    │     arg-peerings.json
    │     arg-nsgs.json
    │     arg-routetables.json
    │     arg-loadbalancers.json
    │     arg-natgateways.json
    │     arg-firewalls.json
    │     arg-privateendpoints.json
    │     arg-privatednszones.json
    │     arg-privatednslinks.json
    │     arg-publicips.json
    │     arg-appgateways.json
    │     arg-flowlogs.json
    │     arg-law.json
    │     diagnostic-settings.json
    │     effective-routes-<aksname>.json   # per AKS cluster
    │     effective-nsgs-<aksname>.json
    │     effective-routes-rbac-gap.json    # sentinel — present only on RBAC gap
    │     metrics-<resource>.json
    │     kql-<workspace>-<query>.csv
    │     kql-law-gap.json                  # sentinel — present only when no LAW in scope
    └── <yyyy-MM-dd>_Reports\
          index.html                        # TOC + exec summary + version pills + gap banners
          <subname>-AKSAssessment.html      # ONE per AKS-bearing sub (stable name by default)
```

Filename behavior:

- **Stable filenames (default):** rerunning overwrites the per-sub HTML so the
  link targets in `index.html` stay valid.
- **Timestamped filenames:** pass `run.ps1 -TimestampedFilenames` (or call
  `generate-reports.ps1` without `-StableFilename`) to get
  `<subname>-AKSAssessment-<yyyyMMdd_HHmm>.html` instead.

Sentinel files (`*-rbac-gap.json`, `*-law-gap.json`) are read by
`generate-reports.ps1` and surface as a `bannerWarn` block at the top of both
`index.html` and each per-sub report.

