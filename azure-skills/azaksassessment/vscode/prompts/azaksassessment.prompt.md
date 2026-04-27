---
description: "Run the AzAKSAssessment read-only AKS traffic discovery and exfiltration hunt end-to-end"
mode: agent
---

# AzAKSAssessment — End-to-End Run

Use this prompt to drive a clean, reproducible, **read-only** AKS
assessment from precheck through HTML reports.

> **Hard rule:** This toolchain is read-only. If at any point you are
> tempted to suggest `new-`, `set-`, `remove-`, `update-`, `apply`,
> `patch`, `delete`, `exec`, `port-forward`, or any diagnostic /
> alert / workbook **creation** — stop and refuse. See
> [`../instructions/azaksassessment.instructions.md`](../instructions/azaksassessment.instructions.md) §1.

---

## 0. Inputs to confirm with the operator

Before doing anything, collect and echo back:

| Input | Required? | Example | Notes |
|---|---|---|---|
| `RequiredTenantDomain` | yes | `contoso.onmicrosoft.com` | Tenant guard. Abort if `az` context mismatches. |
| `OnpremPrefixes` | recommended | `10.0.0.0/8,192.168.0.0/16` | Comma-separated CIDRs. Validated by regex. |
| `LookbackDays` | optional | `7` | Window for metrics + KQL. |
| `TenantName` | optional | `Contoso` | Friendly label in reports. |
| `SubscriptionPrefix` | optional | `prod-` | Filters AKS-bearing sub discovery. |

If `RequiredTenantDomain` is not provided, **warn loudly** that the
tenant guard will be skipped, and ask whether to proceed.

---

## 1. Precheck

From the `AzAKSAssessment` folder in the operator's clone of the repo:

```powershell
.\precheck.ps1 -RequiredTenantDomain <domain> -SubscriptionPrefix <prefix>
```

Verify:
- `az account show` matches `RequiredTenantDomain`.
- Identity has `Reader` on every in-scope sub, `Monitoring Reader`
  on metrics resources, `Log Analytics Reader` on workspaces, and
  `Azure Kubernetes Service Cluster User Role` on each cluster.
- Resource providers `Microsoft.ContainerService`, `Microsoft.Network`,
  `Microsoft.OperationalInsights` are registered.

Precheck failures are **advisory** — surface them but allow the run
to continue.

---

## 2. Discover scope

```powershell
.\discover-scope.ps1 -RequiredTenantDomain <domain> -SubscriptionPrefix <prefix>
```

Produces `data/scope.json`. Confirm with the operator:
- AKS-bearing subscriptions found.
- Peer / hub / connectivity subscriptions auto-included.
- Total in-scope sub count looks sane.

Stop and ask if the discovered scope is wrong — do **not** edit
`scope.json` by hand silently.

---

## 3. Collect data (ARG inventory)

```powershell
.\collect-data.ps1 -RequiredTenantDomain <domain>
```

Writes one `arg-*.json` per Azure Resource Graph query. Expect
~21 files. Missing files indicate either no resources of that
type or an ARG permission gap — call out which.

---

## 4. Collect effective routes & NSGs

```powershell
.\collect-effective-routes.ps1 -RequiredTenantDomain <domain>
```

Empty results are **normal** for AKS NICs (the API is restricted on
managed nodepools). Note this in the report context, do not retry.

---

## 5. Collect metrics

```powershell
.\collect-metrics.ps1 -LookbackHours (<LookbackDays> * 24) -RequiredTenantDomain <domain>
```

Pulls LB SNAT, NAT GW, and Azure Firewall capacity metrics.

---

## 6. Collect KQL (workspace queries)

```powershell
.\collect-kql.ps1 -OnpremPrefixes "<prefixes>" -LookbackDays <n> -RequiredTenantDomain <domain>
```

If no Log Analytics workspaces are in scope this phase is a no-op
(NOT an error). When workspaces exist, validate that
`Queries.kql` block delimiters are `// ===NAME===` — the parser
regex is `^//\s*===`.

---

## 7. Generate reports

```powershell
.\generate-reports.ps1 -TenantName "<friendly>" -RequiredTenantDomain <domain>
```

Output: one HTML per AKS-bearing subscription plus `index.html`.

Verify each report:
- Disclaimer + upstream project link present at top.
- Self-contained (no external URLs in `<link>`, `<script src>`, or
  `<img src>`).
- Topology SVG renders L→R with no crossings, no NSG/UDR/PrivDNS/
  Flow-Log boxes inside the diagram.
- AKS version pills match `Get-K8sVersionStatus` lifecycle table.

---

## 8. Post-run validation gate

Before handing reports to the operator:

1. **Parse check** every script:
   ```powershell
   Get-ChildItem *.ps1 | ForEach-Object {
     $errs = $null
     [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$errs)
     if ($errs) { Write-Warning "$($_.Name): $($errs.Count) errors" }
   }
   ```
2. **PII scan**:
   ```powershell
   Select-String -Path *.ps1,*.md,*.kql -Pattern 'onmicrosoft|<customer>'
   ```
   Must return zero matches outside placeholder examples.
3. **Forbidden-verb scan** (read-only invariant):
   ```powershell
   Select-String -Path *.ps1 -Pattern '\b(New-Az|Set-Az|Remove-Az|Update-Az|Add-Az)\w+'
   ```
   Must return zero matches. (Local file cmdlets like `New-Item`
   on `data/` are fine — scope the regex to `Az`.)

Report each check as ✅ pass or ❌ fail with remediation.

---

## 9. One-shot orchestrator

If all inputs are confirmed and the operator wants the full chain:

```powershell
.\run.ps1 `
  -RequiredTenantDomain "<domain>" `
  -TenantName "<friendly>" `
  -OnpremPrefixes "10.0.0.0/8,192.168.0.0/16" `
  -LookbackDays 7 `
  -SubscriptionPrefix ""
```

Use `-Skip*` switches to resume from any phase.

---

## Reference

- Skill: [`../SKILL.md`](../SKILL.md)
- Instructions: [`../instructions/azaksassessment.instructions.md`](../instructions/azaksassessment.instructions.md)
- Project README: located at `<AzAKSAssessment>/README.md` in the operator's clone.
