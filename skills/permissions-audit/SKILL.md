---
name: permissions-audit
description: Auditerer Claude Code permissions-konfigurationer i `~/.claude/settings.json`, `~/.claude/settings.local.json` og projekt-niveau `.claude/settings.json` / `.claude/settings.local.json` for for-brede allow-rules og smalle deny-rules der efterlader brugeren ubeskyttet. Skal aktiveres når brugeren skriver "audit mine permissions", "tjek allow-list", "kør permissions audit", "er mine claude-permissions for brede", efter installation af et plugin der ændrer permissions, efter pull af et projekt med `.claude/settings.json`, før godkendelse af en PR der ændrer permissions, og periodisk (anbefales weekly) for at fange drift. Detekterer: wildcard-allows (`Bash(*)`, `Edit(*)`, `WebFetch(*)`), destruktive kommandoer i allow-list (`rm`, `dd`, `mkfs`, `sudo`, `reg delete`, `format`, `shred`, `fdisk`, `Stop-Computer`, `Restart-Computer`), pipe-to-shell-allows (`curl … | bash`, `irm … | iex`), system-path writes (`/etc/*`, `C:\Windows\*`, `/usr/bin/*`), bash unsafe flags (`-c`, `-e`, `eval`, `exec`), unrestricted WebFetch (alle domæner), tomme eller nær-tomme deny-lister, allow-rules tilføjet inden for de sidste 7 dage, og drift fra brugerens sidst-godkendte snapshot. Komplementerer `hook-audit`: hook-audit ser på custom hook-kode der eksekverer ved hvert tool-kald, mens permissions-audit ser på hvad Claude må gøre helt uden at spørge.
---

# Permissions Audit

Scanner Claude Code permissions-lister for for-brede allow-rules og snapshot-drift.

## Hvorfor

Claude Code's permissions-system har tre buckets per tool:

```json
{
  "permissions": {
    "allow": ["Bash(npm test)", "Bash(npm run build)"],
    "ask":   ["Bash(npm install)"],
    "deny":  ["Bash(rm:*)", "Bash(curl:* | bash)"]
  }
}
```

Et entry i `allow` betyder Claude kan kalde det **uden at spørge**. Et entry der lyder
uskyldigt (`Bash(*)`) eller specifikt (`Bash(rm:*)`) kan i praksis dække langt mere end
brugeren forventede. Permissions-audit fanger det.

## Workflow (5 faser)

### Fase 1 — Lokalisér settings-filer

Samme stier som `hook-audit`:

| Fil | Scope |
|---|---|
| `~/.claude/settings.json` | Global, version-tracked |
| `~/.claude/settings.local.json` | Global, untracked (machine-specific) |
| `<cwd>/.claude/settings.json` | Projekt, committed |
| `<cwd>/.claude/settings.local.json` | Projekt, untracked |

Effektive permissions er **union** af alle 4 filer (hvis nogen tillader, kan Claude gøre
det). Audit'en skal vise dette samlede billede, ikke kun per-fil.

### Fase 2 — Parse permissions-sektion

For hver fil: parse `permissions.allow`, `permissions.ask`, `permissions.deny`. Understøt
også legacy-formatet hvor permissions kun var en array.

### Fase 3 — Klassificér hver allow-rule

Læs `references/permission-patterns.md` for fulde regler. Kategorier:

| Kategori | Eksempel | Default severity |
|---|---|---|
| `wildcard_allow` | `Bash(*)`, `Edit(*)`, `*` | high |
| `destructive_command` | `Bash(rm:*)`, `Bash(dd:*)`, `Bash(sudo:*)` | critical |
| `pipe_to_shell_allow` | `Bash(curl:* | bash)`, `Bash(irm:* | iex)` | critical |
| `system_path_write` | `Edit(/etc/*)`, `Write(C:\Windows\*)` | high |
| `bash_unsafe_flag` | `Bash(bash -c:*)`, `Bash(* eval *)` | high |
| `network_unrestricted` | `WebFetch(*)`, `WebFetch(http*)` | medium |
| `mcp_unrestricted` | `mcp__*` uden specifik server-prefix | medium |
| `recent_addition` | Allow-rule tilføjet inden for 7 dage | low (multiplikator) |

### Fase 4 — Snapshot-drift

Permissions-audit gemmer en **blessed snapshot** når brugeren har godkendt det aktuelle
state:

```text
~/.<name>/permissions-audit/snapshots/<settings-file-slug>/<YYYY-MM-DD>.json
```

Ved hver audit:
1. Find seneste blessed snapshot for hver settings-fil.
2. Diff `allow`/`deny` mod nuværende.
3. Nye entries i `allow` siden snapshot → flag som `drift_added`.
4. Fjernede entries fra `deny` siden snapshot → flag som `drift_deny_removed` (mistænkeligt).
5. Hvis ingen snapshot findes: foreslå at gemme én efter audit'en (manuel handling).

`drift_added` kombineret med en risk-kategori → opjustér ét trin.

### Fase 5 — Saml verdict

Verdict pr. fil (aggregeret) plus et samlet "effective permissions"-verdict på tværs af
alle 4 filer. Hvis blot én rule ender på `critical`: filens og det samlede verdict er
`FAIL`.

## Verdict-format

JSON skrives til
`~/.<name>/permissions-audits/<YYYY-MM-DD>/<file-slug>.json`:

```json
{
  "file": "~/.claude/settings.json",
  "checked_at": "2026-05-10T12:00:00Z",
  "verdict": "FAIL",
  "risk_score": 88,
  "rules_total": 12,
  "rules_flagged": 2,
  "findings": [
    {
      "rule": "Bash(rm:*)",
      "bucket": "allow",
      "categories": ["destructive_command"],
      "severity": "critical",
      "added_within_days": 2,
      "drift": "added since blessed snapshot 2026-05-01"
    },
    {
      "rule": "WebFetch(*)",
      "bucket": "allow",
      "categories": ["network_unrestricted"],
      "severity": "medium"
    }
  ],
  "concerns": [
    "Bash(rm:*) allows arbitrary file deletion without prompt",
    "WebFetch(*) allows fetching any URL without prompt"
  ],
  "recommendations": [
    "Replace Bash(rm:*) with specific deny rule, or remove entirely",
    "Replace WebFetch(*) with WebFetch(https://docs.claude.com/*) or similar tight scope",
    "Save current state as blessed snapshot after fixes"
  ],
  "snapshot": {
    "compared_to": "2026-05-01",
    "added_in_allow": ["Bash(rm:*)"],
    "removed_from_deny": []
  }
}
```

## Risk score (0–100)

| Kategori | low | medium | high | critical |
|---|---|---|---|---|
| wildcard_allow | — | 25 | 50 | — |
| destructive_command | — | — | — | 80 |
| pipe_to_shell_allow | — | — | — | 90 |
| system_path_write | — | 30 | 50 | — |
| bash_unsafe_flag | — | — | 40 | — |
| network_unrestricted | 10 | 25 | — | — |
| mcp_unrestricted | 10 | 20 | — | — |
| recent_addition | 5 | — | — | — (multiplikator) |
| drift_added | — | 15 | — | — (multiplikator) |
| drift_deny_removed | — | — | 40 | — |

**Verdict mapping:**
- `0–25` → `PASS`
- `26–60` → `WARN`
- `61–100` → `FAIL`
- Et hvilket som helst `critical` finding → automatisk `FAIL`.

## Exit codes

```
0 = PASS
1 = WARN (manual review)
2 = FAIL (a critical-severity rule is in effect — should be removed)
3 = Tool/parse error (treat as WARN)
```

## Snapshot-håndtering

### Gem ny blessed snapshot

Efter brugeren har gennemgået audit-rapporten og godkendt det aktuelle state:

```bash
# Pseudo-flow — implementeres af skill'en:
cp ~/.claude/settings.json \
   ~/.<name>/permissions-audit/snapshots/global-settings/$(date +%F).json
```

Snapshot er en kopi af permissions-sektionen plus en lille metadata-header med tidsstempel
og brugerens approval-besked.

### Læs sidste snapshot

Læs nyeste fil i `~/.<name>/permissions-audit/snapshots/<file-slug>/`. Ingen filer = ingen
drift-check muligt; flag det i rapporten.

### Snapshot-rotation

Behold de sidste 12 snapshots pr. fil (én pr. måned ved typisk brug). Slet ældre med
mindre brugeren explicit beder dig om at beholde dem.

## Whitelist

`~/.<name>/permissions-audit/whitelist.json` — vetted permission-rules der ikke flagges:

```json
{
  "approved_rules": [
    {
      "rule": "WebFetch(*)",
      "approved_by": "janus",
      "approved_at": "2026-05-10",
      "reason": "Personal dev machine, accept the risk for now"
    }
  ]
}
```

**Brug whitelist sparsomt.** Hvis du whitelist'er `Bash(*)`, så har du fjernet beskyttelsen
helt — i de fleste tilfælde er det bedre at smalne reglen end at whiteliste den.

## Rapportering til brugeren

```
[permissions-audit] ~/.claude/settings.json — FAIL — risk 88/100

✗ Bash(rm:*) — destructive_command (CRITICAL, added 2 days ago)
⚠ WebFetch(*) — network_unrestricted (medium)

Drift since 2026-05-01:
  + Bash(rm:*) added to allow

Anbefaling:
  1. Fjern Bash(rm:*) fra allow (eller flyt til deny)
  2. Erstat WebFetch(*) med specifik domæne-pattern
  3. Gem ny blessed snapshot efter rettelser

Fuld rapport: ~/.<name>/permissions-audits/2026-05-10/global-settings.json
```

## Logging i sessionens handoff

```
[permissions-audit] <fil> — <verdict> — <risk>/100 — <flagged>/<total> rules flagged
```

## Forudsætninger

- JSON-parser.
- Filsystem-adgang til settings + snapshot-mappe.
- `git log` for "added_within_days"-detektion (valgfrit — falder tilbage til mtime).

## Reference-filer

- `references/permission-patterns.md` — destruktive kommando-patterns, wildcard-detektor,
  system-path-listen, sample tight-scope alternatives, snapshot-format.
