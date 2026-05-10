# security-audit — security suite for Claude Code

Six composable Claude skills that gate the riskiest operations Claude Code performs:
installing dependencies, reading files with credentials, configuring hooks, granting
permissions, transmitting data to external services, and re-auditing dependencies over
time.

| Skill | Gates | Catches |
|---|---|---|
| **`security-audit`** | Package installs (npm/NuGet/pub.dev/PyPI/cargo/go), MCP servers, plugins, binaries, third-party skills | Typosquats, fresh malware drops, maintainer takeovers, unsigned binaries, known CVEs, malicious VirusTotal hits |
| **`secrets-scanner`** | File reads, `git add`/`commit`, uploads to chat platforms, MCP transmissions | Hardcoded API keys (AWS/Stripe/GitHub/OpenAI/Anthropic/Google/Slack), private keys (RSA/EC/OpenSSH), connection strings, high-entropy tokens — with placeholder-vs-real triage |
| **`hook-audit`** | New plugin installs, `.claude/settings.json` changes, project pulls, PR merges that touch hooks | Hooks that exfiltrate (network + env-read combo), `curl \| bash` patterns, base64-obfuscated commands, recently-added hooks, instruction injection in `CLAUDE.md` |
| **`permissions-audit`** | `.claude/settings.json` permission changes, plugin installs, project pulls, periodic drift checks | Wildcard allows (`Bash(*)`, `WebFetch(*)`), destructive commands in allow-list (`rm`, `dd`, `sudo`), pipe-to-shell allows, system-path writes, drift from blessed snapshot |
| **`egress-audit`** | Posts to chat/email/SMS, uploads to paste/image/file hosts, MCP outbound calls, clipboard writes, screenshot uploads | Unknown destinations, unauthorized recipients, large payloads, secrets-in-payload, frequency spikes, redirect chains, URL shorteners |
| **`dependency-rescan`** | Periodic re-audit of existing lockfiles (npm/NuGet/pub/Poetry/Pipenv/Cargo/Go/Composer), post-pull sanity checks | New CVEs published since last scan, maintainer takeovers since last scan, package deprecations, lockfile-vs-installed drift |

All six follow the same architecture: structured JSON verdicts, `PASS` / `WARN` / `FAIL`
flow, 0–100 risk scoring, manual whitelist support, and append-only handoff logging. They
are independent — install only the ones you need, adopt them one at a time.

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

This copies **all six skills** (`security-audit`, `secrets-scanner`, `hook-audit`,
`permissions-audit`, `egress-audit`, `dependency-rescan`) into
`~/.claude/skills/<skill-name>/`. Restart Claude Code afterwards.

## Pick your storage folder (`<name>` placeholder)

Throughout this README — and inside every `skills/*/SKILL.md` file — you'll see paths like
`~/.<name>/security-audit/whitelist.json`, `~/.<name>/secrets-scans/...`,
`~/.<name>/hook-audits/...`, `~/.<name>/permissions-audit/snapshots/...`,
`~/.<name>/egress-audit/allowed-domains.txt`, and
`~/.<name>/dependency-rescans/<project>/last.json`.

`<name>` is a placeholder for the folder where all six skills store their **whitelists**
and their **JSON audit reports**. Pick a name that fits your brand or org and use it
consistently across all skills. Examples: `.codewire`, `.acme`, `.mycompany`, or just
`.claude` if you have no preference.

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

Add these six gates to your global `~/.claude/CLAUDE.md` so Claude knows when to invoke
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

### Gate 4 — `permissions-audit` (allow-list audit)

```markdown
## Permissions audit (gate around .claude/settings.json permission changes)

Before installing a new plugin that may modify permissions, after pulling a
project containing `.claude/settings.json`, before approving a PR that
changes the `permissions` block, and periodically (weekly) for drift, run
the `permissions-audit` skill against all four settings files (global +
project, both committed and `.local`).

Detect: `wildcard_allow` (`Bash(*)`, `Edit(*)`, `WebFetch(*)`),
`destructive_command` (`Bash(rm:*)`, `Bash(sudo:*)`, `Bash(dd:*)`,
`Stop-Computer`, `reg delete`), `pipe_to_shell_allow`
(`Bash(curl:* | bash)`), `system_path_write` (`Edit(/etc/*)`,
`Write(C:\Windows\*)`), `bash_unsafe_flag` (`-c`, `eval`),
`network_unrestricted` (`WebFetch(*)`), `mcp_unrestricted`,
`recent_addition` (allow added inside 7 days),
`drift_added` / `drift_deny_removed` (diff vs blessed snapshot at
`~/.<name>/permissions-audit/snapshots/`).

Verdict: `PASS` continue · `WARN` show flagged rules and recommend tight-
scope alternatives · `FAIL` recommend the rule be removed. Append
`[permissions-audit] <file> — <verdict> — <risk>/100 — <flagged>/<total>`
to the session handoff. After fixes, save a new blessed snapshot.
```

### Gate 5 — `egress-audit` (outbound transmission gate)

```markdown
## Egress audit (gate before data leaves the machine)

Before any outbound transmission — posts to Telegram/Slack/Discord/email/
SMS, uploads to pastebin/gist/imgur/cloudinary/transfer.sh/file.io,
diagram renderers (mermaid.live, kroki.io), playground saves
(jsfiddle/codepen/codesandbox), `curl`/`Invoke-WebRequest` POST/PUT,
MCP-tool calls that ship payload externally, clipboard writes of non-
trivial content, or screenshot uploads — run the `egress-audit` skill.

Detect: `unknown_destination` (domain not in
`~/.<name>/egress-audit/allowed-domains.txt`), `unauthorized_recipient`
(chat-ID/email not in
`~/.<name>/egress-audit/allowed-recipients.json`), `large_payload`
(>10 KB), `secret_in_payload` (run `secrets-scanner` patterns over body),
`frequency_spike` (>10 posts/5 min to same destination),
`clipboard_egress`, `screenshot_with_pii`. Resolve URL shorteners and
follow redirect chains. IP-based destinations (non-private) are
auto-flagged.

Verdict: `PASS` continue · `WARN` present concerns and require explicit
approval · `FAIL` BLOCK the transmission. Append
`[egress-audit] <destination> — <verdict> — <risk>/100 — <size> bytes` to
the session handoff and to `~/.<name>/egress-audits/<date>/posts.log`.
```

### Gate 6 — `dependency-rescan` (periodic re-audit)

```markdown
## Dependency rescan (periodic delta audit of existing lockfiles)

Run the `dependency-rescan` skill weekly (via `/loop 7d` or a scheduled
task), after a major time gap (weeks/months) since the last security
audit, on `git pull` / `git post-merge`, and when the user asks to "check
for new CVEs", "rescan dependencies", "audit lockfile". Reuses
`security-audit` checks but inverts the model: scan EXISTING packages
against TODAY's threat data instead of new packages at install.

Reads any present lockfile: `package-lock.json`, `pnpm-lock.yaml`,
`yarn.lock`, `packages.lock.json`, `project.lock.json`, `pubspec.lock`,
`poetry.lock`, `Pipfile.lock`, `requirements.txt` (pinned),
`Cargo.lock`, `go.sum`, `composer.lock`. Compares against last baseline
in `~/.<name>/dependency-rescans/<project-slug>/last.json` and reports
ONLY deltas: new CVEs since last scan, maintainer changes since last
scan, deprecations, abandonments, lockfile-vs-installed drift.

Verdict: `PASS` (no risky deltas) · `WARN` (review and consider
upgrades) · `FAIL` (immediate action — critical CVE or compromised
package). Append
`[dependency-rescan] <project> — <verdict> — <risk>/100 — <deltas>/<total>`
to the session handoff. At 90+ days since last scan, auto-promote
WARN→FAIL because the dependency state is by definition unmonitored.
```

## Configuration

- **VirusTotal API key** (recommended for `security-audit` binary scanning): set
  `VIRUSTOTAL_API_KEY` in your environment. Free tier gives 4 req/min, 500/day.
  Without a key, `security-audit` falls back to GUI-link manual verification.
- **Whitelists** — each skill has its own, edited by hand only:

  ```text
  ~/.<name>/security-audit/whitelist.json         ← packages already vetted
  ~/.<name>/secrets-scanner/whitelist.json        ← files / patterns / hashes
  ~/.<name>/hook-audit/whitelist.json             ← approved hook SHA256s + reason
  ~/.<name>/permissions-audit/whitelist.json      ← approved broad rules + reason
  ~/.<name>/egress-audit/allowed-domains.txt      ← glob list of OK domains
  ~/.<name>/egress-audit/allowed-recipients.json  ← chat-IDs / email addresses
  ~/.<name>/dependency-rescan/whitelist.json      ← ignored deltas with expiry
  ```

  Snapshots & logs (created automatically by the skills, not edited by hand):

  ```text
  ~/.<name>/permissions-audit/snapshots/<file-slug>/<YYYY-MM-DD>.json
  ~/.<name>/egress-audits/<YYYY-MM-DD>/posts.log
  ~/.<name>/dependency-rescans/<project-slug>/last.json
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

  // hook-audit / permissions-audit
  {
    "approved_hooks": [
      { "hash": "sha256:abc...", "approved_by": "janus",
        "approved_at": "2026-05-10",
        "reason": "Local audit log, no network" }
    ]
  }

  // dependency-rescan (note expires_at — no eternal accept-the-risk)
  {
    "ignore_deltas": [
      { "package": "npm:lodash@4.17.20",
        "delta_types": ["deprecated"],
        "reason": "Locked for legacy compat",
        "approved_at": "2026-05-10",
        "expires_at": "2026-08-10" }
    ]
  }
  ```

  ```text
  # ~/.<name>/egress-audit/allowed-domains.txt
  *.codewire.net
  api.anthropic.com
  api.telegram.org/bot6414779032/*
  hooks.slack.com/services/T01CODEWIRE/*
  ```

  **Edit these files by hand only.** Claude must not add to them.

## Verdict format

Each skill writes a structured JSON report and prints a short summary in chat:

```text
[security-audit]     left-pad@1.3.0          — PASS — risk 12/100
[secrets-scanner]    src/config.prod.json    — FAIL — risk 85/100
[hook-audit]         ~/.claude/settings.json — FAIL — risk 92/100
[permissions-audit]  ~/.claude/settings.json — FAIL — risk 88/100
[egress-audit]       gist.github.com         — FAIL — risk 75/100
[dependency-rescan]  /e/REPOSITORY-GITHUB/x  — WARN — risk 45/100 (4 deltas)
```

Reports are saved to:

```text
~/.<name>/security-audits/<YYYY-MM-DD>/<artifact-slug>.json
~/.<name>/secrets-scans/<YYYY-MM-DD>/<filename-slug>.json
~/.<name>/hook-audits/<YYYY-MM-DD>/<file-slug>.json
~/.<name>/permissions-audits/<YYYY-MM-DD>/<file-slug>.json
~/.<name>/egress-audits/<YYYY-MM-DD>/<destination-slug>.json
~/.<name>/dependency-rescans/<project-slug>/<YYYY-MM-DD>.json
```

See each skill's `SKILL.md` for the full risk-scoring table, exit codes, and
per-category detection rules:

- [`skills/security-audit/SKILL.md`](skills/security-audit/SKILL.md)
- [`skills/secrets-scanner/SKILL.md`](skills/secrets-scanner/SKILL.md)
- [`skills/hook-audit/SKILL.md`](skills/hook-audit/SKILL.md)
- [`skills/permissions-audit/SKILL.md`](skills/permissions-audit/SKILL.md)
- [`skills/egress-audit/SKILL.md`](skills/egress-audit/SKILL.md)
- [`skills/dependency-rescan/SKILL.md`](skills/dependency-rescan/SKILL.md)

## License

MIT — see [LICENSE](LICENSE).
