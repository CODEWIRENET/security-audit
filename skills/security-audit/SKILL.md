---
name: security-audit
description: Tjekker pakker, plugins, MCP-servere, CLI-tools, VS Code/JetBrains extensions, Docker images, model-vægte og binære filer for sikkerhedsrisici INDEN installation, tilføjelse eller eksekvering. Skal ALTID aktiveres når du eller brugeren er på vej til at køre `npm install`, `npm/pnpm/yarn add`, `dotnet add package`, `flutter pub add`, `pip install`, `cargo add`, `go get`, før en ny MCP-server konfigureres i `.mcp.json` eller `claude_desktop_config.json`, før et Claude plugin (`claude plugin add`), VS Code extension eller JetBrains plugin installeres, før en binær fil (`.exe`, `.msi`, `.dmg`, `.AppImage`, `.deb`, prebuilt fra GitHub Releases, Docker image, model-vægte) hentes eller eksekveres, eller før en tredjeparts Claude skill installeres. Brug også når brugeren skriver "tjek pakken X", "er Y sikker at installere", "kan jeg stole på Z", "scan denne fil", "kør security audit", eller på anden måde antyder verifikation af eksterne dependencies. Supply chain-angreb (left-pad, event-stream, ua-parser-js, xz-utils, npm typosquats) rammer netop populære pakker — ingen undtagelser for "kendte" eller "Microsoft-ejede" navne. Kør tjekket selv ved minor/patch-bumps over major-grænser eller ved ejerskifte inden for 90 dage.
---

# Security Audit

Strukturerer et grundigt sikkerhedstjek af alt eksternt der lander i Janus' projekter eller miljø, inden det installeres eller eksekveres.

## Kerneprincip

Et tjek skal være **konklusivt** før installation finder sted. Intet "det ser nok fint ud". Hvis tjekket ikke kan gennemføres (network nede, registry svarer ikke, ingen VT-key), er resultatet `WARN` — aldrig stiltiende `PASS`.

## Workflow (5 faser)

### Fase 1 — Identificér og klassificér

Lav en liste over hvert nyt eksternt artefakt. Klassificér hvert som én af:

| Type | Eksempel |
|---|---|
| `npm` | `react`, `@scope/pkg` |
| `nuget` | `Newtonsoft.Json`, `Codewire.Auth` |
| `pub` | `provider`, `firebase_core` |
| `pip` | `requests`, `numpy` |
| `cargo` | `serde`, `tokio` |
| `go` | `github.com/spf13/cobra` |
| `mcp` | `@playwright/mcp`, `@modelcontextprotocol/server-filesystem` |
| `claude-plugin` | `anthropic/frontend-design`, `garrytan/gstack` |
| `vscode-ext` | `ms-python.python` |
| `jetbrains-plugin` | `com.example.plugin` |
| `binary` | `installer.exe`, `tool.AppImage`, `model.gguf` |
| `docker` | `nginx:1.25`, `ghcr.io/.../image:tag` |
| `claude-skill` | tredjeparts SKILL.md fra GitHub |

Hvis pakken allerede står i lockfile/csproj/pubspec og kun er en patch- eller minor-bump inden for samme major: spring til Fase 4 (kun CVE-tjek). Major-bump = fuld scan.

### Fase 2 — Registry-tjek

Læs `references/registries.md` for de fulde tjeklister pr. type. Minimum-tjek der gælder for alle:

- **Udgivelsesdato**: under 30 dage = WARN-flag (mulig fresh malware drop).
- **Ejerskift**: tjek for ejerskifte/maintainer-skifte inden for 90 dage = WARN-flag.
- **Verificeret publisher**: pakkens publisher matcher den forventede organisation (npm "verified", NuGet "Prefix Reserved", pub.dev "verified publisher", GitHub-org).
- **Source repo**: GitHub/GitLab-repo eksisterer, er aktivt, antal stjerner og forks er konsistent med pakkens download-tal, README ser legitim ud.
- **Typosquat**: pakkenavnet ligner ikke (Levenshtein ≤ 2) en mere populær pakke. Eksempler: `crossenv` vs `cross-env`, `colourful` vs `colorful`.
- **Install scripts**: for npm specifikt — tjek `scripts.preinstall`, `scripts.install`, `scripts.postinstall`. Ikke-trivielle install scripts = WARN minimum.
- **License**: licens er angivet og ikke "UNLICENSED" eller tom.

### Fase 3 — Web-søgning efter advisories

For hvert artefakt, søg:

1. `<navn> CVE` — tjek NVD og GitHub Security Advisories.
2. `<navn> malware` — tjek for kendte malware-rapporter.
3. `<navn> compromised` — tjek for kendte kompromitteringer.
4. `<navn> supply chain` — tjek for kendte supply chain-angreb.
5. `site:socket.dev <navn>` — Socket.dev's automatiske analyse.
6. `site:snyk.io/advisor <navn>` — Snyk Advisor.
7. For NuGet specifikt: `site:github.com/advisories <navn>`.

Hvis nogen af disse returnerer aktuelle (under 12 mdr) hits relateret til den specifikke version eller version-range: `severity: high` minimum.

### Fase 4 — VirusTotal (kun for binære filer)

Kun kør for `binary` og `docker` (image digest). Læs `references/virustotal.md` for fulde API-kald. Kort:

1. Beregn SHA256: `sha256sum <fil>` eller for Docker: brug image digest fra `docker inspect`.
2. Tjek om `VIRUSTOTAL_API_KEY` er sat:
   - Hvis sat: `curl -s -H "x-apikey: $VIRUSTOTAL_API_KEY" "https://www.virustotal.com/api/v3/files/<sha256>"`
   - Hvis ikke sat: byg URL `https://www.virustotal.com/gui/file/<sha256>` og bed brugeren om manuel verifikation. Marker tjekket som `WARN` indtil bekræftet.
3. Aggregér `last_analysis_stats`:
   - `malicious >= 1` → `severity: critical`
   - `suspicious >= 3` → `severity: high`
   - `last_analysis_date` over 30 dage gammel → `severity: medium` (re-scan anbefalet)
   - 0 malicious + 0 suspicious + frisk dato → OK
4. For URLs (download-links): base64url-encode og kald `/api/v3/urls/{id}`.
5. Free tier-loft: 4 requests/min, 500/dag. Throttle ved batch-tjek.

### Fase 5 — Saml verdict og rapportér

Producér struktureret JSON (se "Verdict-format" nedenfor), gem til disk, og rapportér til brugeren.

## Verdict-format

Output er ALTID JSON først. Skriv til stdout og gem også som fil i `~/.codewire/security-audits/<YYYY-MM-DD>/<artefakt-slug>.json`.

```json
{
  "artifact": "left-pad",
  "type": "npm",
  "version": "1.3.0",
  "checked_at": "2026-05-10T12:00:00Z",
  "verdict": "PASS",
  "risk_score": 12,
  "checks": [
    {
      "name": "publish_age",
      "status": "ok",
      "detail": "Published 2017-04-26 (8 år siden)"
    },
    {
      "name": "maintainer_changes",
      "status": "ok",
      "detail": "Ingen maintainer-skift de sidste 90 dage"
    },
    {
      "name": "install_scripts",
      "status": "ok",
      "detail": "Ingen pre/post-install scripts"
    },
    {
      "name": "verified_publisher",
      "status": "ok",
      "detail": "Maintainer: stevemao (verified)"
    },
    {
      "name": "typosquat_check",
      "status": "ok",
      "detail": "Ingen nære matches i top 1000"
    },
    {
      "name": "cve_search",
      "status": "ok",
      "detail": "Ingen aktive CVE'er fundet"
    },
    {
      "name": "socket_dev",
      "status": "ok",
      "detail": "Score 92/100, ingen risk-flags"
    },
    {
      "name": "virustotal",
      "status": "n/a",
      "detail": "Kildepakke, ikke binær"
    }
  ],
  "concerns": [],
  "recommendations": [
    "Pin version med `1.3.0` i stedet for `^1.3.0`"
  ],
  "sources": [
    "https://npmjs.com/package/left-pad",
    "https://socket.dev/npm/package/left-pad",
    "https://github.com/stevemao/left-pad"
  ]
}
```

### Risk score (0–100)

Hvert check der fejler tilføjer point:

| Check | low | medium | high | critical |
|---|---|---|---|---|
| publish_age | 5 | 10 | 20 | — |
| maintainer_changes | — | 15 | 30 | — |
| install_scripts | 10 | 25 | 40 | — |
| verified_publisher | 5 | 15 | — | — |
| typosquat_check | — | — | 40 | 60 |
| cve_search | — | 20 | 40 | 70 |
| virustotal | — | 30 | 60 | 100 |

**Verdict mapping:**
- `0–25` → `PASS`
- `26–60` → `WARN`
- `61–100` → `FAIL`
- Et hvilket som helst `critical` check → automatisk `FAIL` uanset score.

## Exit codes (når kaldt fra subagent eller script)

```
0 = PASS
1 = WARN
2 = FAIL
3 = Tool/network error (kan ikke konkludere — behandl som WARN)
```

## Rapportering til brugeren

Efter JSON er gemt, vis i chat:

```
[VERDICT] left-pad@1.3.0 — PASS — risk 12/100

✓ Stabil version (8 år gammel)
✓ Ingen install scripts
✓ Verified maintainer (stevemao)

Anbefaling: pin version med `1.3.0` i stedet for `^1.3.0`
Fuld rapport: ~/.codewire/security-audits/2026-05-10/left-pad.json
```

For `WARN`:

```
[VERDICT] suspicious-pkg@0.0.3 — WARN — risk 48/100

⚠ Udgivet for 4 dage siden (mulig fresh drop)
⚠ Ny maintainer (oprettet konto for 11 dage siden)
✓ Ingen kendte CVE'er

Vil du fortsætte med installation alligevel? Begrund hvorfor.
```

For `FAIL`:

```
[VERDICT] left_pad@1.3.0 — FAIL — risk 70/100

✗ TYPOSQUAT: navnet matcher 'left-pad' (Levenshtein 1) — formentlig ondsindet
✗ Konto oprettet for 2 dage siden
✗ 0 stjerner, ingen aktivitet på source repo

INSTALLATION BLOKERET. Mente du `left-pad` (med bindestreg)?
```

## Logging i sessionens handoff

Append til sessionens handoff-document:

```
[security-audit] <artefakt>@<version> — <verdict> — <risk>/100 — <rapport-sti>
```

## Hvidliste

Pakker på `~/.codewire/security-audit/whitelist.json` springer fuldt tjek over og kører kun en hurtig CVE-søgning. Filen redigeres KUN manuelt af brugeren — Claude må ikke tilføje til den. Format:

```json
{
  "npm": ["react", "react-dom", "@playwright/mcp"],
  "nuget": ["Newtonsoft.Json", "Codewire.Auth"],
  "pub": ["provider", "firebase_core"]
}
```

## Forudsætninger

- `curl` og `jq` til API-kald og JSON-parsing.
- `sha256sum` til hash-beregning (på Windows: `certutil -hashfile <fil> SHA256`).
- Internetadgang til registry-API'er, GitHub Advisory Database, og Socket.dev.
- Valgfrit men anbefalet: `VIRUSTOTAL_API_KEY` i miljø.

## Reference-filer

- `references/registries.md` — detaljerede tjek pr. registry-type (npm, NuGet, pub.dev, MCP, etc.)
- `references/virustotal.md` — VirusTotal API v3 endpoints, curl-eksempler, rate limits, response-parsing.

Læs dem on-demand når du støder på den specifikke artefakt-type.
