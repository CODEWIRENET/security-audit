# security-audit

Pre-install security gate for [Claude Code](https://docs.claude.com/claude-code).
Scans every external artifact — packages, MCP servers, plugins, binaries, third-party skills —
**before** Claude installs or executes it.

Catches:
- Typosquats (Levenshtein-close package names)
- Fresh malware drops (packages under 30 days old)
- Maintainer takeovers / account changes inside 90 days
- Unsigned binaries
- Known CVEs and Socket.dev / Snyk advisories
- Malicious VirusTotal hits on `.exe` / `.msi` / `.dmg` / `.AppImage` / `.deb`

No exceptions for "well-known" or "Microsoft-owned" packages — supply chain attacks
(left-pad, event-stream, ua-parser-js, xz-utils) hit exactly those.

## Install

### Option A — Claude Code plugin

```text
/plugin install security-audit@CODEWIRENET/security-audit
```

(or `claude plugin add CODEWIRENET/security-audit` from the CLI)

### Option B — Standalone (no plugin system)

Clone and run the install script:

```bash
git clone https://github.com/CODEWIRENET/security-audit.git
cd security-audit

# Windows
pwsh ./install.ps1

# macOS / Linux
./install.sh
```

This copies the skill into `~/.claude/skills/security-audit/`. Restart Claude Code afterwards.

## Pick your storage folder (`<name>` placeholder)

Throughout this README — and inside `skills/security-audit/SKILL.md` — you'll see paths
like `~/.<name>/security-audit/whitelist.json` and `~/.<name>/security-audits/...`.

`<name>` is a placeholder for the folder where the skill stores its **whitelist** and its
**JSON audit reports**. Pick a name that fits your brand or org and use it consistently.
Examples: `.codewire`, `.acme`, `.mycompany`, or just `.claude` if you have no preference.

**This step is required.** Both `README.md` and `skills/security-audit/SKILL.md` reference
the path with the literal string `<name>`. If you install without substituting, the skill
will create real folders called `~/.<name>/...` on disk — ugly but harmless. To avoid that,
do a one-time find-and-replace **after cloning, before running the installer**:

### Windows (PowerShell)

```powershell
$folder = "codewire"   # ← your choice, no leading dot
Get-ChildItem -Path "README.md","skills" -Recurse -File |
  ForEach-Object {
    (Get-Content $_.FullName -Raw) -replace '<name>', $folder |
      Set-Content $_.FullName -NoNewline
  }
```

### macOS / Linux

```bash
FOLDER=codewire   # ← your choice, no leading dot
grep -rl '<name>' README.md skills \
  | xargs sed -i.bak "s/<name>/$FOLDER/g"
find . -name "*.bak" -delete
```

After substitution, run `install.ps1` / `install.sh` so the patched skill lands in
`~/.claude/skills/security-audit/`. The skill will then write its whitelist and audit
reports under `~/.<your-folder>/security-audit/` and `~/.<your-folder>/security-audits/`.

## CLAUDE.md hookup

Add this gate to your global `~/.claude/CLAUDE.md` so Claude knows when to invoke the skill:

```markdown
## Security audit (gate before external dependencies)

Before any new external dependency is installed or added — packages
(`npm/pnpm/yarn`, `dotnet add package`, `flutter pub add`, `pip`, `cargo`,
`go get`, plus manual edits to `package.json` / `*.csproj` / `pubspec.yaml` /
`requirements.txt` / `Cargo.toml` / `go.mod`), MCP servers in `.mcp.json`,
Claude/VS Code/JetBrains plugins, binaries (`.exe`/`.msi`/`.dmg`/`.AppImage`/
`.deb`/Docker images/model weights) or third-party Claude skills — run the
`security-audit` skill end-to-end per new direct artifact. Pre-approved:
`@playwright/mcp@latest` plus entries in
`~/.<name>/security-audit/whitelist.json`.

Verdict: `PASS` continue · `WARN` present concrete concerns and require
explicit approval · `FAIL` stop and propose alternatives. Append
`[security-audit] <artifact>@<version> — <verdict> — <risk>/100` to the
session handoff.

No exceptions for "well-known" or "Microsoft-owned" packages — supply chain
attacks hit exactly those. Binaries require VirusTotal; without
`VIRUSTOTAL_API_KEY` generate a GUI link and have the user verify manually
before installation.
```

## Configuration

- **VirusTotal API key** (recommended for binary scanning): set
  `VIRUSTOTAL_API_KEY` in your environment. Free tier gives 4 req/min, 500/day.
  Without a key, the skill falls back to GUI-link manual verification.
- **Whitelist**: add already-vetted packages to
  `~/.<name>/security-audit/whitelist.json`:

  ```json
  {
    "npm":   ["react", "react-dom", "@playwright/mcp"],
    "nuget": ["Newtonsoft.Json"],
    "pub":   ["provider", "firebase_core"]
  }
  ```

  **Edit this file by hand only.** Claude must not add to it.

## Verdict format

The skill writes a structured JSON report to
`~/.<name>/security-audits/<YYYY-MM-DD>/<artifact-slug>.json` and prints a
short summary in chat:

```text
[VERDICT] left-pad@1.3.0 — PASS — risk 12/100

✓ Stable version (8 years old)
✓ No install scripts
✓ Verified maintainer (stevemao)
```

See `skills/security-audit/SKILL.md` for the full risk-scoring table, exit
codes, and per-registry check details.

## License

MIT — see [LICENSE](LICENSE).
