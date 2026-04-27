---
name: azaksassessment
description: 'Run the read-only AzAKSAssessment toolchain end-to-end: precheck → discover scope → ARG inventory → effective routes → metrics → KQL → HTML reports. USE FOR: AKS assessment, AKS traffic discovery, AKS exfiltration hunt, AKS network audit, AKS read-only audit, multi-subscription AKS review, AKS topology report, AzAKSAssessment, run AKS assessment, generate AKS reports, AKS HTML report, AKS Resource Graph inventory, AKS effective routes, AKS LB/NATGW/Firewall metrics, AKS Log Analytics KQL hunt. DO NOT USE FOR: deploying or modifying any Azure resource (this toolchain is strictly read-only), creating diagnostic settings or alerts, general AKS troubleshooting, non-AKS subscriptions.'
---

# AzAKSAssessment — Read-Only AKS Discovery & Exfiltration Hunt

Drives the bundled `AzAKSAssessment` PowerShell toolchain (eight `*.ps1` scripts + `Queries.kql` + `run.ps1` orchestrator, all under [`./scripts/`](./scripts/)) in a clean, reproducible, **strictly read-only** way and produces one HTML report per AKS-bearing subscription plus an `index.html` summary.

The scripts ship with this skill — no separate clone needed.

## When to Use

- Multi-subscription AKS networking + traffic + exfiltration review.
- HTML deliverable (per-sub + index) without modifying any Azure resource.
- Audit AKS topology, LB SNAT, NAT GW, Azure Firewall, peerings, PEs, Private DNS, flow-log coverage.
- Hunt east-west, north-south, on-prem, or PaaS exfiltration patterns from existing telemetry.

## Hard Rules (BLOCKING)

This toolchain is **read-only**. Refuse to suggest, run, or accept patches that introduce:

- Any `New-Az*`, `Set-Az*`, `Remove-Az*`, `Update-Az*`, `Add-Az*` cmdlet
- `Invoke-AzRest` with any non-GET method
- `kubectl exec | debug | port-forward | apply | patch | delete | cp | edit | replace | scale | rollout | label | annotate | taint | drain | cordon | uncordon`
- `helm install | upgrade | uninstall | rollback`, `tcpdump`
- Creation of diagnostic settings, flow logs, alerts, or workbooks
- Any data-plane upload

### Allowed verbs only
- `az ... show | list | graph query | account ...`
- `Get-Az*`, `Search-AzGraph`, `Invoke-AzOperationalInsightsQuery`
- `kubectl get | describe | api-resources | api-versions | config view`
- File I/O against the local `data/` and `reports/` folders

Reading existing diagnostic settings, flow-log configs, alerts, and workbooks **is allowed**.

## Tenant & Scope Safety

- Every script accepts `-RequiredTenantDomain <domain>` and aborts via tenant guard if `az` context mismatches. If omitted, warn loudly.
- Never hardcode tenant ID, subscription ID, customer name, domain, or email.
- Subscription scope is **discovered**, never hardcoded. `discover-scope.ps1` finds AKS-bearing subs and auto-includes peered, hub, and connectivity subs. Downstream scripts read `data/scope.json` — do not re-discover or re-filter.
- `-SubscriptionPrefix` is applied only in `discover-scope.ps1` and baked into `scope.json`.

## Inputs

| Input | Required | Example | Notes |
|---|---|---|---|
| `RequiredTenantDomain` | recommended | `contoso.onmicrosoft.com` | Tenant guard. If omitted, warn loudly. |
| `OnpremPrefixes` | recommended | `10.0.0.0/8,192.168.0.0/16` | Comma-separated CIDRs. Regex-validated. |
| `LookbackDays` | optional | `7` | Window for metrics + KQL. |
| `TenantName` | optional | `Contoso` | Friendly label in reports. |
| `SubscriptionPrefix` | optional | `prod-` | Filters AKS-bearing sub discovery. |

## Procedure

All scripts live in [`./scripts/`](./scripts/). `cd` into that directory (or invoke with full paths) before running.

### 1. Precheck (advisory)
```powershell
.\precheck.ps1 -RequiredTenantDomain <domain> -SubscriptionPrefix <prefix>
```
Report RBAC gaps. Continue even on non-zero exit (advisory only).

### 2. Discover scope
```powershell
.\discover-scope.ps1 -RequiredTenantDomain <domain> -SubscriptionPrefix <prefix>
```
Confirm the AKS-bearing subs and auto-included peer/hub/connectivity subs in `data/scope.json` look right before proceeding. Stop and ask if the discovered scope is wrong — do **not** edit `scope.json` by hand silently.

### 3. Collect ARG inventory
```powershell
.\collect-data.ps1 -RequiredTenantDomain <domain>
```
Expect ~21 `arg-*.json` files. A missing file means either zero resources of that type or an ARG permission gap — call out which.

### 4. Collect effective routes & NSGs
```powershell
.\collect-effective-routes.ps1 -RequiredTenantDomain <domain>
```
Empty results are **normal** for AKS NICs (the API is restricted on managed nodepools).

### 5. Collect metrics
```powershell
.\collect-metrics.ps1 -LookbackHours (<LookbackDays> * 24) -RequiredTenantDomain <domain>
```
Pulls LB SNAT, NAT GW, and Azure Firewall capacity metrics.

### 6. Collect KQL
```powershell
.\collect-kql.ps1 -OnpremPrefixes "<prefixes>" -LookbackDays <n> -RequiredTenantDomain <domain>
```
No-op (not error) when no Log Analytics workspaces are in scope. `Queries.kql` block delimiter is exactly `// ===NAME===` — parser regex is `^//\s*===`.

### 7. Generate reports
```powershell
.\generate-reports.ps1 -TenantName "<friendly>" -RequiredTenantDomain <domain>
```

### 8. One-shot orchestrator (alternative to steps 1–7)
```powershell
.\run.ps1 `
  -RequiredTenantDomain "<domain>" `
  -TenantName "<friendly>" `
  -OnpremPrefixes "10.0.0.0/8,192.168.0.0/16" `
  -LookbackDays 7
```
Use `-Skip*` switches to resume from any phase.

## PowerShell Conventions (when editing toolchain scripts)

- `#requires -Version 5.1`, `[CmdletBinding()]`, `param()`, `$ErrorActionPreference = 'Stop'`.
- Comment-based help: `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`.
- `Write-Output` for data, `Write-Warning` for recoverable, `Write-Error` for terminal; never `Write-Host`.
- `[ValidateNotNullOrEmpty()]` and `[ValidatePattern()]` on subscription IDs, domains, CIDRs.
- CIDRs must match `^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$`. Reject anything else — never paste raw input into a query body.
- All paths via `Join-Path $PSScriptRoot ...`. Idempotent overwrites in `data/` and `reports/`.

## KQL Library (`Queries.kql`)

- Block delimiter is exactly `// ===NAME===` on its own line.
- One named block per analytical question with a `// ` header (purpose, inputs, source table).
- Time filters use `$LookbackDays`; no hardcoded `ago(7d)`.
- `OnpremPrefixes` interpolation goes through the regex-validated path in `collect-kql.ps1` — never trust raw input.

## Report Standards

- 100% self-contained: inline CSS, inline SVG, system fonts, no CDN, no external scripts/images.
- Every report opens with the disclaimer block ("unofficial / as-is, not a Microsoft product") linking to the upstream project URL declared in the project README. Do not embed any personal email, employer name, customer name, or tenant ID.
- Topology diagrams: left-to-right flow, no crossing arrows, no NSG / UDR / Private DNS / Flow Logs inside the diagram (those go in tables below).
- AKS version pills must reflect the lifecycle table in `generate-reports.ps1` (`Get-K8sVersionStatus`).
- Recommendations link to `learn.microsoft.com/azure/aks/...` canonical docs only — no blogs, no third-party.
- Print-friendly: `@media print` rules expand all `<details>` and hide nav/export buttons.

## Validation Gate

Run all three checks and report ✅/❌ for each:

```powershell
# 1. Parse check
Get-ChildItem *.ps1 | ForEach-Object {
  $errs = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errs)
  if ($errs) { Write-Warning "$($_.Name): $($errs.Count) errors" }
}

# 2. PII scan (must return zero matches outside placeholder examples)
Select-String -Path *.ps1,*.md,*.kql -Pattern 'onmicrosoft|@.*\.com|<customer-name>'

# 3. Forbidden-verb scan (read-only invariant)
Select-String -Path *.ps1 -Pattern '\b(New-Az|Set-Az|Remove-Az|Update-Az|Add-Az)\w+'
```

Then verify each generated HTML:
- Disclaimer + upstream project link present at top
- No personal email, employer name, customer name, or tenant ID anywhere in the report
- Self-contained (no external `<link href>`, `<script src>`, `<img src>`)
- Topology SVG renders L→R with no crossings
- AKS version pills match the `Get-K8sVersionStatus` lifecycle table

## Outputs

Written under the `scripts/` folder (or wherever `run.ps1` is invoked from):

```
scripts/
├── data/
│   ├── scope.json
│   ├── arg-*.json                   # ARG inventory per resource type
│   ├── diag-*.json
│   ├── effective-routes-<aks>.json
│   ├── metrics-<resource>.json
│   └── kql-<workspace>-<query>.csv
└── reports/
    ├── <subname>-AKSAssessment-<ts>.html  # one per AKS-bearing sub
    └── index.html                          # TOC + exec summary + version pills
```
