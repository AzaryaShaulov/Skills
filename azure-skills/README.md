# azure-skills

Open agent skills for Azure assessments. Currently ships:

| Skill | Description |
|---|---|
| [`azaksassessment`](./azaksassessment/) | Read-only AKS discovery + exfiltration hunt. Bundles a complete PowerShell toolchain (8 scripts + KQL library + orchestrator). |

> **Disclaimer:** Unofficial, community-maintained, **not** a Microsoft product. Provided **as-is**, without warranty.

## Install (skills.sh CLI)

```bash
# Project scope (recommended — committed with your repo)
npx skills add <owner>/azure-skills

# Global scope (across all projects)
npx skills add <owner>/azure-skills -g

# Install to specific agents only
npx skills add <owner>/azure-skills -a claude-code -a github-copilot
```

After install, invoke from your agent chat with phrases like:
- "run an AKS assessment"
- "do a read-only AKS audit"
- "generate AKS exfiltration hunt reports"

Or use the slash command (where supported): `/azaksassessment`.

## Repository layout

```
.
├── README.md
├── LICENSE
├── .gitignore
└── azaksassessment/             # one self-contained skill folder
    ├── SKILL.md                 # portable agent skill (canonical)
    ├── scripts/                 # bundled PowerShell toolchain (10 files)
    │   ├── run.ps1
    │   ├── precheck.ps1
    │   ├── discover-scope.ps1
    │   ├── collect-data.ps1
    │   ├── collect-effective-routes.ps1
    │   ├── collect-metrics.ps1
    │   ├── collect-kql.ps1
    │   ├── generate-reports.ps1
    │   ├── Queries.kql
    │   └── README.md
    └── vscode/                  # optional VS Code / GitHub Copilot extras
        ├── instructions/
        │   └── azaksassessment.instructions.md
        └── prompts/
            └── azaksassessment.prompt.md
```

The `vscode/` folder contains GitHub Copilot–specific primitives that the
[skills CLI](https://github.com/vercel-labs/skills) does not install. VS Code
users can copy them manually:

```powershell
$dst = "<your-workspace>\.github"
Copy-Item .\azaksassessment\vscode\instructions\azaksassessment.instructions.md "$dst\instructions\"
Copy-Item .\azaksassessment\vscode\prompts\azaksassessment.prompt.md             "$dst\prompts\"
```

## Upstream toolchain

The `azaksassessment` skill bundles its own PowerShell toolchain under [`azaksassessment/scripts/`](./azaksassessment/scripts/) — no separate clone is required. See the [bundled README](./azaksassessment/scripts/README.md) for run-order and RBAC requirements.

## Contributing

Pull requests welcome. Please run the validation gate documented in each `SKILL.md` before submitting.

## License

[MIT](./LICENSE)
