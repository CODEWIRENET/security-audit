---
name: dependency-rescan
description: Re-auditerer dependencies der allerede er installeret i et projekt — fanger CVE'er der er offentliggjort SIDEN sidste install, maintainer-takeovers der er sket EFTER installation, package-deprecations, abandoned upstreams, og version-drift mellem lockfile og faktisk installeret. Skal aktiveres når brugeren skriver "rescan dependencies", "tjek for nye CVE'er", "audit lockfile", "har nogen pakker fået problemer siden sidst", "kør dependency rescan", og periodisk (anbefales weekly via `/loop` skill eller scheduled task) plus efter et major time gap (uger/måneder) siden sidste sikkerheds-audit. Læser lockfiles: `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `packages.lock.json`, `project.lock.json` (NuGet), `pubspec.lock` (Flutter/Dart), `poetry.lock`, `Pipfile.lock`, `requirements.txt` (pinned versioner), `Cargo.lock`, `go.sum`, `composer.lock`. Genbruger `security-audit`'s CVE-, Socket.dev-, Snyk- og maintainer-checks men kører dem mod EKSISTERENDE pakker, ikke nye installs. Sammenligner mod sidste rescan i `~/.<name>/dependency-rescans/<project-slug>/last.json` og rapporterer KUN deltas — pakker der er blevet risikable siden sidst, ikke en komplet liste. Output er typisk kort selv for store projekter, fordi de fleste runs intet finder.
---

# Dependency Rescan

Periodisk re-audit af allerede-installerede dependencies. Fanger trusler der ikke
eksisterede ved install-tidspunktet.

## Hvorfor

`security-audit` checker en pakke EN GANG — ved install. Men:

- En CVE kan være offentliggjort 6 måneder efter install.
- En pakke kan have skiftet maintainer til en kompromitteret konto efter install.
- En pakke kan være blevet deprecated eller abandoned.
- Lockfile kan være divergeret fra faktisk `node_modules`/etc.

Dependency-rescan fanger denne tidsforsinkede risiko. Den genbruger `security-audit`'s
detection-logik men vender den om: i stedet for "før install, scan nye pakker" er det
"efter install, scan eksisterende pakker mod nye trusler".

## Workflow (5 faser)

### Fase 1 — Discovery

Lokalisér lockfiles i cwd. Spring `node_modules/`, `.git/`, `dist/`, `build/`, `target/`,
`bin/`, `obj/` over:

| Lockfile | Format | Pakke-manager |
|---|---|---|
| `package-lock.json` | JSON | npm |
| `pnpm-lock.yaml` | YAML | pnpm |
| `yarn.lock` | Custom | yarn (v1) / berry |
| `packages.lock.json` | JSON | NuGet (PackageReference) |
| `project.lock.json` | JSON | NuGet (legacy) |
| `pubspec.lock` | YAML | pub.dev (Flutter/Dart) |
| `poetry.lock` | TOML | Poetry (Python) |
| `Pipfile.lock` | JSON | Pipenv |
| `requirements.txt` (med `==`) | Text | pip (manual pinning) |
| `Cargo.lock` | TOML | cargo (Rust) |
| `go.sum` | Text | go modules |
| `composer.lock` | JSON | Composer (PHP) |

Læs `references/lockfile-formats.md` for parser-detaljer pr. format.

### Fase 2 — Last-rescan-load

Læs `~/.<name>/dependency-rescans/<project-slug>/last.json` (hvis findes):

```json
{
  "_meta": {
    "scanned_at": "2026-04-15T08:00:00Z",
    "lockfile_hashes": {
      "package-lock.json": "sha256:abc123...",
      "packages.lock.json": "sha256:def456..."
    }
  },
  "packages": {
    "npm:react@18.2.0": {
      "last_check": "2026-04-15",
      "last_verdict": "PASS",
      "known_cves": [],
      "maintainers": ["facebook"]
    }
  }
}
```

Hvis filen mangler: dette er første rescan. Behandl alle pakker som "nyligt scannede" og
gem fuld baseline ved slutningen.

`<project-slug>` = SHA256 af absolut sti til projekt-roden (første 16 tegn).

### Fase 3 — Per-pakke check

For hver pakke i lockfile:

1. **Hash-sammenligning**: hvis pakke er uændret siden sidste rescan (samme version,
   samme integrity-hash i lockfile), spring fuldt re-check og kør kun:
   - **CVE-delta-check**: er der nye CVE'er publiceret siden sidste rescan-dato?
   - **Maintainer-delta-check**: er current maintainer-set ≠ sidste rescan?

2. **Hvis pakken er ændret eller ny**: kør fuld `security-audit`-check (registry-tjek,
   typosquat, install scripts, source repo, advisories).

3. **Deprecation-check**: kør altid (let). Hvis pakken er markeret deprecated, abandoned,
   eller arkiveret på upstream → flag.

### Fase 4 — Drift-detektion

Sammenlign lockfile mod faktisk installeret tilstand:

- **npm**: `package-lock.json` versioner vs. `node_modules/<pkg>/package.json`.
- **NuGet**: `packages.lock.json` vs. installeret assembly-versioner i `bin/`.
- **pub.dev**: `pubspec.lock` vs. `.dart_tool/package_config.json`.
- **pip**: `requirements.txt` vs. `pip freeze`.

Drift = pakke i lockfile, men ikke installeret (eller forkert version installeret).
Alene er det ikke en sikkerhedsrisiko, men det indikerer at lockfile ikke er respekteret
— flag som `medium` informational.

### Fase 5 — Saml delta-rapport og opdater baseline

Producér rapport KUN over pakker der har ændret risk-status siden sidste rescan:

- Nye `WARN` eller `FAIL` der ikke var der før.
- Eksisterende `WARN`/`FAIL` der er forværret (fra warn → fail).
- Nye CVE'er på pakker der tidligere var `PASS`.

Pakker uden ændringer logges ikke (rapport ville være 1000+ linjer for store projekter).

Skriv ny baseline til `~/.<name>/dependency-rescans/<project-slug>/last.json`.

## Verdict-format

```json
{
  "project": "/e/REPOSITORY-GITHUB/security-audit",
  "project_slug": "a1b2c3d4e5f6g7h8",
  "scanned_at": "2026-05-10T12:00:00Z",
  "previous_scan": "2026-04-15T08:00:00Z",
  "days_since_last": 25,
  "verdict": "WARN",
  "risk_score": 45,
  "lockfiles": [
    "package-lock.json",
    "packages.lock.json"
  ],
  "summary": {
    "packages_total": 482,
    "packages_unchanged": 478,
    "packages_changed": 4,
    "deltas": {
      "new_cve": 1,
      "maintainer_change": 1,
      "deprecated": 1,
      "drift": 1
    }
  },
  "findings": [
    {
      "package": "npm:lodash@4.17.20",
      "delta": "new_cve",
      "severity": "high",
      "detail": "CVE-2026-12345 published 2026-04-22 (after last scan), prototype pollution",
      "recommendation": "Upgrade to lodash@4.17.21 or later"
    },
    {
      "package": "npm:left-pad@1.3.0",
      "delta": "maintainer_change",
      "severity": "medium",
      "detail": "Maintainer changed from stevemao to <new-account-3-days-old>",
      "recommendation": "Pin to 1.3.0 explicitly, monitor for malicious version bump"
    },
    {
      "package": "npm:request@2.88.2",
      "delta": "deprecated",
      "severity": "medium",
      "detail": "Marked deprecated upstream 2026-03-01, no security maintenance",
      "recommendation": "Replace with axios, undici, or node:fetch"
    },
    {
      "package": "npm:debug@4.3.4",
      "delta": "drift",
      "severity": "low",
      "detail": "Lockfile says 4.3.4, installed is 4.3.5",
      "recommendation": "Run npm ci to sync, or update lockfile"
    }
  ]
}
```

## Risk score (0–100)

Score er aggregeret over deltas (ikke pr. pakke; det skalerer dårligt).

| Delta-type | low | medium | high | critical |
|---|---|---|---|---|
| new_cve | 5 | 15 | 30 | 50 |
| maintainer_change | — | 20 | 40 | — |
| deprecated | 5 | 15 | — | — |
| abandoned (no commits 12+ months) | — | 10 | — | — |
| drift | 5 | — | — | — |
| Active malicious advisory (Socket.dev/Snyk) | — | — | 50 | 80 |

**Verdict mapping:**
- `0–25` → `PASS`
- `26–60` → `WARN`
- `61–100` → `FAIL`
- Et hvilket som helst `critical` finding → automatisk `FAIL`.

**Bemærk**: ved store time gaps (90+ dage siden sidste rescan), opjustér WARN→FAIL,
fordi dependency-state er definitionsmæssigt risikabel ved manglende monitorering.

## Exit codes

```
0 = PASS (no risky deltas)
1 = WARN (review and consider upgrades)
2 = FAIL (immediate action required — critical CVE or compromised package)
3 = Tool/parse error (treat as WARN)
```

## Cadence

Skill'en planlægger ikke sig selv. Wire den via:

### `/loop` skill (hvis installeret)

```text
/loop 7d /skill dependency-rescan
```

Eller dynamisk:

```text
/loop /skill dependency-rescan
```

(Lader Claude beslutte cadence baseret på hvor lang tid siden sidste run.)

### Scheduled task (Windows)

```powershell
$action = New-ScheduledTaskAction -Execute "claude" -Argument "skill dependency-rescan"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 8am
Register-ScheduledTask -TaskName "ClaudeDependencyRescan" -Action $action -Trigger $trigger
```

### cron (macOS / Linux)

```cron
0 8 * * 1 cd /path/to/project && claude skill dependency-rescan
```

### Git hooks (på pull/post-merge)

```bash
# .git/hooks/post-merge
#!/usr/bin/env bash
claude skill dependency-rescan --quick
```

`--quick` flag: kun CVE-delta + maintainer-delta-check, ingen fuld registry-rerun.
Bruges til hurtig sanity-check ved pull.

## Whitelist

`~/.<name>/dependency-rescan/whitelist.json` — pakker hvor specifikke deltas ignoreres:

```json
{
  "ignore_deltas": [
    {
      "package": "npm:lodash@4.17.20",
      "delta_types": ["deprecated"],
      "reason": "Locked to this version due to legacy compat, accept the risk",
      "approved_by": "janus",
      "approved_at": "2026-05-10",
      "expires_at": "2026-08-10"
    }
  ]
}
```

`expires_at` tvinger gen-godkendelse — accept-the-risk skal ikke være evig. Når en
ignore-rule udløber, behandl pakken som ny finding igen.

## Rapportering til brugeren

Kort default (det meste af tiden er der intet at rapportere):

```
[dependency-rescan] /e/REPOSITORY-GITHUB/security-audit — PASS — risk 0/100

482 packages scanned, 0 deltas since 2026-04-15 (25 days ago).
```

Med findings:

```
[dependency-rescan] /e/REPOSITORY-GITHUB/security-audit — WARN — risk 45/100

482 packages scanned, 4 deltas since 2026-04-15 (25 days ago):

✗ npm:lodash@4.17.20 — new CVE-2026-12345 (high)
  Upgrade to lodash@4.17.21+

⚠ npm:left-pad@1.3.0 — maintainer changed (medium)
  New account 3 days old, pin and monitor

⚠ npm:request@2.88.2 — deprecated upstream (medium)
  Replace with axios/undici/node:fetch

ℹ npm:debug@4.3.4 — drift (low)
  Run `npm ci` to sync

Fuld rapport: ~/.<name>/dependency-rescans/<slug>/2026-05-10.json
```

## Logging i sessionens handoff

```
[dependency-rescan] <project> — <verdict> — <risk>/100 — <deltas>/<total> packages changed
```

## Forudsætninger

- `security-audit` skill installeret (genbruges som library).
- Filsystem-adgang til lockfiles og baseline-mappe.
- Internetadgang til CVE-databaser, Socket.dev, registry-API'er.
- For drift-detektion: pakke-manager CLI tilgængelig (`npm ls`, `dotnet list package`,
  `flutter pub deps`, `pip freeze`).

## Reference-filer

- `references/lockfile-formats.md` — parser-detaljer pr. lockfile-format, eksempel-output,
  edge cases (workspaces, monorepos, optional dependencies).
