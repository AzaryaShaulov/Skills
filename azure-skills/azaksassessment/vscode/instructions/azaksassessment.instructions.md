---
applyTo:
  - "**/AzAKSAssessment/**"
---

# AzAKSAssessment — Read-Only AKS Discovery & Exfiltration Hunt

This instruction file governs all code, scripts, queries, and reports under
`AzAKSAssessment/`. It is **stricter than** any general PowerShell+Azure
instruction file. When the two conflict, this file wins.

---

## 1. Absolute read-only guarantee (BLOCKING)

The toolset performs **zero** writes / modifications / updates / deletes
against any Azure resource, Kubernetes object, diagnostic setting, alert,
NSG, route table, firewall, NetworkPolicy, CoreDNS ConfigMap, workspace,
storage account, or anything else.

### Allowed verbs only
- `az ... show | list | graph query | account ...`
- `Get-Az*`, `Search-AzGraph`, `Invoke-AzOperationalInsightsQuery`
- `kubectl get | describe | api-resources | api-versions | config view`
- File I/O against the local `data/` and `reports/` folders

### Forbidden — reject any patch that introduces these
`new-`, `set-`, `remove-`, `update-`, `add-`, `start-`, `stop-`,
`restart-`, `deploy-`, `import-` (against Azure), `Invoke-AzRest`
with any non-GET method, `kubectl exec | debug | port-forward |
apply | patch | delete | cp | edit | replace | scale | rollout |
label | annotate | taint | drain | cordon | uncordon`,
`helm install | upgrade | uninstall | rollback`, `tcpdump`, any
data-plane upload, any diagnostic-setting / flow-log / alert /
workbook **creation**.

Reading existing diagnostic settings, flow-log configs, alerts,
and workbooks **is allowed**.

---

## 2. Tenant & scope safety

- Every script must accept `-RequiredTenantDomain <domain>` and abort
  early via the tenant guard if the current `az` context doesn't match.
  Skip only when the caller passes an empty string.
- Never hardcode a tenant ID, subscription ID, customer name, domain,
  or email anywhere in code, defaults, comments, or sample output.
- Subscription scope is **discovered**, never hardcoded:
  `discover-scope.ps1` finds AKS-bearing subs, then auto-includes
  peered, hub, and connectivity subs. Downstream scripts read
  `data/scope.json` — do not re-discover or re-filter.
- `-SubscriptionPrefix` is applied only in `discover-scope.ps1` and
  baked into `scope.json`.

---

## 3. PowerShell conventions

- `#requires -Version 5.1` at the top of every `*.ps1`.
- `[CmdletBinding()]` + `param()` block, `$ErrorActionPreference = "Stop"`.
- Comment-based help with `.SYNOPSIS`, `.DESCRIPTION`, `.PARAMETER`
  on every script.
- `Write-Output` for structured/log lines; `Write-Warning` for
  recoverable issues; `Write-Error` only for terminal failures;
  never `Write-Host`.
- `[ValidateNotNullOrEmpty()]` on required params; `[ValidatePattern()]`
  on subscription IDs, domains, CIDR strings.
- Validate any user-supplied string that is concatenated into a KQL,
  ARG, or shell argument. CIDRs must match
  `^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$`. Reject anything else — never
  paste raw input into a query body.
- Idempotent file writes: always overwrite into `data/` and `reports/`
  with deterministic filenames. Never append.
- All paths via `Join-Path $PSScriptRoot ...` — no relative `./`.

---

## 4. Data layout (do not change without updating README + reports)

```
<TenantOrCustomer>/<yyyy-MM-dd_HHmm>-AKSAssessment/
  data/
    scope.json
    arg-*.json                  # one per ARG query
    diag-*.json                 # one per resource type
    effective-routes-<aks>.json
    effective-nsgs-<aks>.json
    metrics-<resource>.json
    kql-<workspace>-<query>.csv
  reports/
    <subname>-AKSAssessment-<ts>.html
    index.html
```

- One HTML report per **AKS-bearing subscription**. Hub /
  connectivity subs are context-only.
- `index.html` is the entry point with TOC, exec summary, version
  pills per sub, and known-limitations panel.

---

## 5. KQL query library (`Queries.kql`)

- Block delimiter is exactly `// ===NAME===` on its own line. The
  parser regex in `collect-kql.ps1` is `^//\s*===` — keep them aligned.
- Keep one named block per analytical question. Document the block
  with a `// ` header comment line giving purpose, inputs, and source
  table.
- All time filters must use the `$LookbackDays` placeholder pattern;
  no hardcoded `ago(7d)`.
- Any `OnpremPrefixes` interpolation must go through the regex-
  validated path in `collect-kql.ps1` — never trust raw input.

---

## 6. Reports (HTML)

- 100% self-contained: inline CSS, inline SVG, system fonts, no CDN,
  no external `<script src>`, no remote images.
- Every report opens with the disclaimer block ("unofficial /
  as-is, not a Microsoft product") and links to the upstream
  project URL declared in the project README. Do not embed any
  personal email, employer name, customer name, or tenant ID in
  the disclaimer or anywhere else.
- Topology diagrams: left-to-right flow, no crossing arrows, no
  network-attached resources (NSG / UDR / Private DNS / Flow Logs)
  inside the diagram — those go in tables below. Follow standard
  diagram-design guidance for traffic-direction labels and gap analysis.
- AKS version pills must reflect the lifecycle table in
  `generate-reports.ps1` (`Get-K8sVersionStatus`). Update the table's
  `LAST UPDATED` line whenever the version mapping changes.
- Print-friendly: `@media print` rules expand all `<details>` and
  hide nav/export buttons.

---

## 7. PII & redaction

Before committing or sharing reports / scripts / docs:

```powershell
Select-String -Path *.ps1,*.md,*.kql -Pattern 'onmicrosoft|@.*\.com|<customer-name>'
```

Must return **zero** matches outside of placeholder examples
(`<your-tenant>`, `<TenantOrCustomer>`).

---

## 8. Recommendations & external links

- Recommendations in reports must link to `learn.microsoft.com/azure/aks/...`
  canonical docs only (no blogs, no third-party). Each recommendation
  card carries a direct deep link.
- Do not invent CVE IDs or version numbers. The version lifecycle
  source URL is captured next to the table.

---

## 9. Change-control checklist (before any merge)

1. All 8 scripts pass `[System.Management.Automation.Language.Parser]::ParseFile()`
   with zero errors.
2. PII scan returns zero matches.
3. KQL parser test loads ≥1 block from `Queries.kql`.
4. README run-order section matches `run.ps1` step list.
5. Disclaimer present on every generated HTML and the README.
6. No new forbidden verb (see §1) introduced anywhere.
