# security-audit — security suite for Claude Code

Three composable Claude skills that gate the riskiest operations Claude Code performs:
installing dependencies, reading files with credentials, and configuring hooks.

| Skill | Gates | Catches |
|---|---|---|
| **`security-audit`** | Package installs (npm/NuGet/pub.dev/PyPI/cargo/go), MCP servers, plugins, binaries, third-party skills | Typosquats, fresh malware drops, maintainer takeovers, unsigned binaries, known CVEs, malicious VirusTotal hits |
| **`secrets-scanner`** | File reads, `git add`/`commit`, uploads to chat platforms, MCP transmissions | Hardcoded API keys (AWS/Stripe/GitHub/OpenAI/Anthropic/Google/Slack), private keys (RSA/EC/OpenSSH), connection strings, high-entropy tokens — with placeholder-vs-real triage |
| **`hook-audit`** | New plugin installs, `.claude/settings.json` changes, project pulls, PR merges that touch hooks | Hooks that exfiltrate (network + env-read combo), `curl \| bash` patterns, base64-obfuscated commands, recently-added hooks, instruction injection in `CLAUDE.md` |

All three follow the same architecture: structured JSON verdicts, `PASS` / `WARN` / `FAIL`
flow, 0–100 risk scoring, manual whitelist support, and append-only handoff logging.

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

This copies **all three skills** (`security-audit`, `secrets-scanner`, `hook-audit`) into
`~/.claude/skills/<skill-name>/`. Restart Claude Code afterwards.

## Pick your storage folder (`<name>` placeholder)

Throughout this README — and inside every `skills/*/SKILL.md` file — you'll see paths like
`~/.<name>/security-audit/whitelist.json`, `~/.<name>/secrets-scans/...`, and
`~/.<name>/hook-audits/...`.

`<name>` is a placeholder for the folder where the three skills store their **whitelists**
and their **JSON audit reports**. Pick a name that fits your brand or org and use it
consistently across all three skills. Examples: `.codewire`, `.acme`, `.mycompany`, or
just `.claude` if you have no preference.

**This step is required.** All `SKILL.md` files reference the path with the literal string
`<name>`. If you install without substituting, the skills will create real folders called
`~/.<name>/...` on disk — ugly but harmless. To avoid that, do a one-time find-and-replace
**after cloning, before running the installer**:

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

After substitution, run `install.ps1` / `install.sh` so the patched skills land under
`~/.claude/skills/`. Each skill will then write its whitelist and audit reports under
`~/.<your-folder>/<skill-name>/` and `~/.<your-folder>/<skill-name>s/`.

## CLAUDE.md hookup

Add these three gates to your global `~/.claude/CLAUDE.md` so Claude knows when to invoke
each skill. They are independent — you can adopt them one at a time.

### Gate 1 — `security-audit` (dependency installs)

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

### Gate 2 — `secrets-scanner` (file reads, commits, uploads)

```markdown
## Secrets scanner (gate before files leave the project)

Before Claude reads, copies, stages, commits or transmits a file, run the
`secrets-scanner` skill if any of these apply: filename matches `.env*`,
`credentials.*`, `*.key`, `*.pem`, `*.pfx`, `*.p12`, `id_rsa`, `id_ed25519`,
`secrets.*`, `service-account*.json`, `appsettings.*.json`, `web.config`, or
`app.config`; the operation is `git add` / `git commit` / `git push`; the
target is a chat platform (Telegram, Slack, Discord, email), a paste site
(pastebin, gist, diagram renderer), or an MCP tool that ships data to an
external endpoint.

Verdict: `PASS` continue · `WARN` present concrete findings and require
explicit approval · `FAIL` BLOCK the operation. Append `[secrets-scanner]
<file> — <verdict> — <risk>/100` to the session handoff.

Local reads for Claude's own analysis are fine — Claude may inspect secrets
to help rotate them. What MUST NOT happen is that secrets leave the machine.
Whitelist legitimate test fixtures via
`~/.<name>/secrets-scanner/whitelist.json`.
```

### Gate 3 — `hook-audit` (Claude Code settings audit)

```markdown
## Hook audit (gate around .claude/settings.json changes)

Before installing a new Claude plugin, after pulling a project that contains
`.claude/settings.json`, before merging a PR that modifies hooks, and after
`claude plugin add`, run the `hook-audit` skill against
`~/.claude/settings.json`, `~/.claude/settings.local.json`, the project's
`.claude/settings.json` and `.claude/settings.local.json`, plus both
`CLAUDE.md` files.

Flag categories: `network_egress`, `env_read`, `clipboard_write`,
`obfuscation`, `pipe_to_shell`, `unknown_binary`, `recent_change`,
`tool_io_capture`, `instruction_injection`. Combinations
`network_egress + env_read`, `network_egress + tool_io_capture`, and
`pipe_to_shell` alone are automatic `critical`.

Verdict: `PASS` continue · `WARN` show flagged hooks and require explicit
approval · `FAIL` BLOCK plugin install / project activation. Append
`[hook-audit] <file> — <verdict> — <risk>/100 — <flagged>/<total>` to the
session handoff. Whitelist vetted hooks by SHA256 in
`~/.<name>/hook-audit/whitelist.json` with a meaningful `reason` field.
```

## Configuration

- **VirusTotal API key** (recommended for `security-audit` binary scanning): set
  `VIRUSTOTAL_API_KEY` in your environment. Free tier gives 4 req/min, 500/day.
  Without a key, `security-audit` falls back to GUI-link manual verification.
- **Whitelists** — each skill has its own, edited by hand only:

  ```text
  ~/.<name>/security-audit/whitelist.json    ← packages already vetted
  ~/.<name>/secrets-scanner/whitelist.json   ← files / patterns / hashes
  ~/.<name>/hook-audit/whitelist.json        ← approved hook SHA256s + reason
  ```

  Examples:

  ```json
  // security-audit
  { "npm": ["react", "@playwright/mcp"], "nuget": ["Newtonsoft.Json"] }

  // secrets-scanner
  {
    "files":    ["tests/fixtures/fake-credentials.json"],
    "patterns": ["AKIATEST[0-9A-Z]{14}"]
  }

  // hook-audit
  {
    "approved_hooks": [
      { "hash": "sha256:abc...", "approved_by": "janus",
        "approved_at": "2026-05-10",
        "reason": "Local audit log to ~/.codewire/audit.log, no network" }
    ]
  }
  ```

  **Edit these files by hand only.** Claude must not add to them.

## Verdict format

Each skill writes a structured JSON report and prints a short summary in chat:

```text
[security-audit]   left-pad@1.3.0       — PASS — risk 12/100
[secrets-scanner]  src/config.prod.json — FAIL — risk 85/100
[hook-audit]       ~/.claude/settings   — FAIL — risk 92/100
```

Reports are saved to:

```text
~/.<name>/security-audits/<YYYY-MM-DD>/<artifact-slug>.json
~/.<name>/secrets-scans/<YYYY-MM-DD>/<filename-slug>.json
~/.<name>/hook-audits/<YYYY-MM-DD>/<file-slug>.json
```

See each skill's `SKILL.md` for the full risk-scoring table, exit codes, and
per-category detection rules:

- [`skills/security-audit/SKILL.md`](skills/security-audit/SKILL.md)
- [`skills/secrets-scanner/SKILL.md`](skills/secrets-scanner/SKILL.md)
- [`skills/hook-audit/SKILL.md`](skills/hook-audit/SKILL.md)

## License

MIT — see [LICENSE](LICENSE).
