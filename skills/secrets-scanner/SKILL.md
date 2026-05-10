---
name: secrets-scanner
description: Tjekker filer for hardcodede credentials (API keys, tokens, private keys, connection strings) FØR Claude læser, kopierer, committer eller sender dem til eksterne services. Skal ALTID aktiveres når Claude er på vej til at læse en fil med navn der matcher `.env*`, `credentials.*`, `*.key`, `*.pem`, `*.pfx`, `*.p12`, `id_rsa`, `id_ed25519`, `secrets.*`, `service-account*.json`, `appsettings.*.json`, `web.config` eller `app.config`, før `git add` / `git commit` af nye eller ændrede filer, før upload til chat-platforms (Telegram, Slack, Discord, email), før paste til pastebins/gists/diagram-renderers, og før transmission gennem MCP-tools til eksterne endpoints. Brug også når brugeren skriver "scan for secrets", "tjek for credentials", "er der API-nøgler i denne fil", "kør secrets audit". Dækker AWS, Stripe, GitHub, OpenAI, Anthropic, Google, Slack, Telegram, JWT + private keys (RSA/EC/OpenSSH/PGP) + connection strings (postgres://, mysql://, mongodb://, Server=) + high-entropy 32+ char strenge. Distinguérer mellem ægte secrets og placeholders ("REPLACE_ME", "<your-key-here>", "xxx", `test_`/`fake_` prefixes).
---

# Secrets Scanner

Pre-flight gate der detekterer hardcodede credentials FØR de forlader projektet
(via Claude læser/kopier/commit/upload/MCP-call).

## Kerneprincip

Et **false negative** (missed real secret) er katastrofalt. Et **false positive** er en mild
gene. Når i tvivl: `WARN`. Whitelist findes specifikt til at neutralisere kendte falske
positiver — ikke til at gætte sig væk fra reelle fund.

## Workflow (6 faser)

### Fase 1 — Identificér target-filer

Lav en liste over hver fil Claude er på vej til at læse, kopiere, stage, committe eller
sende ud. For batch-operationer (`git add .`, `Read` af mappe, MCP file-list): scan hver
fil individuelt.

Spring over (ingen scan): `node_modules/`, `.git/`, `dist/`, `build/`, `target/`, `bin/`,
`obj/`, `*.lock` (ingen credentials forventet i lockfiles).

### Fase 2 — Filnavn-gate

Hvis filnavnet matcher en kendt sensitiv pattern, jump direkte til Fase 3 selv hvis
extensionen siger binær. Patterns:

```
.env            .env.*           !.env.example      !.env.sample
credentials.json credentials.yml  credentials.yaml
*.key           *.pem            *.pfx              *.p12
id_rsa          id_dsa           id_ecdsa           id_ed25519
secrets.json    secrets.yaml     secrets.yml
service-account*.json
appsettings.Production.json      appsettings.Development.json
web.config      app.config       *.publishsettings
.npmrc          .pypirc          .docker/config.json
.aws/credentials .ssh/config      .kube/config
```

Filnavn alene = WARN minimum. Indhold-scan afgør endelig severity.

### Fase 3 — Regex-scan

Læs `references/patterns.md` for fuld regex-katalog. Minimum-providers:

| Provider | Pattern |
|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | `(?i)aws.{0,20}['"][0-9a-zA-Z/+]{40}['"]` |
| Stripe live | `sk_live_[0-9a-zA-Z]{24,}` |
| GitHub PAT | `gh[pousr]_[A-Za-z0-9]{36,}` |
| OpenAI | `sk-(proj-)?[A-Za-z0-9]{40,}` |
| Anthropic | `sk-ant-[A-Za-z0-9_-]{40,}` |
| Google API | `AIza[0-9A-Za-z_-]{35}` |
| Slack | `xox[baprs]-[A-Za-z0-9-]{10,}` |
| Telegram bot | `[0-9]{8,10}:[A-Za-z0-9_-]{35}` |
| JWT | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` |
| RSA/EC/OpenSSH key | `-----BEGIN (RSA \|EC \|DSA \|OPENSSH \|PGP )?PRIVATE KEY-----` |

Connection strings:

| Pattern |
|---|
| `postgres(ql)?://[^:]+:[^@]+@` |
| `mysql://[^:]+:[^@]+@` |
| `mongodb(\+srv)?://[^:]+:[^@]+@` |
| `(?i)Server=.+;.*Password=[^;]+;` |
| `(?i)Data Source=.+;.*Password=[^;]+;` |

### Fase 4 — Entropy-analyse

For 32+ char strenge der ikke matcher en regex: beregn Shannon-entropi. Tærskel:

- Entropi ≥ 4.5 + længde ≥ 32 + ikke i en kommentar/string-literal-position der ligner en
  hash → kandidat for `medium`-severity.
- Falske positiver: SHA256-hashes (entropi ~5.0 men har specifik længde 64), UUIDs
  (entropi ~3.5), base64-encoded billeder (kan være meget lange, behandl som warning kun
  hvis filnavn er sensitivt).

### Fase 5 — Triage (placeholder vs ægte)

Læs `references/triage.md` for fulde regler. Quick-rules — neutralisér til `low` eller
`info` hvis match'en optræder i en af disse kontekster:

- Strengen indeholder: `REPLACE_ME`, `CHANGE_ME`, `YOUR_KEY_HERE`, `<your-`, `xxx`,
  `xxxxxxxx`, `0000`, `1111`.
- Prefix med `test_`, `fake_`, `dummy_`, `example_`, `mock_`.
- Filnavn indeholder `example`, `sample`, `template`, `fixture`, `mock`, `test`.
- Konteksten er en kodekommentar der explicit siger "example".
- Strengen er en kendt offentlig test-key (Stripe `sk_test_...` test-mode er ikke
  hemmelig — markér som `info`).

### Fase 6 — Saml verdict og rapportér

Producér struktureret JSON. Append til handoff. Hvis `FAIL` på en commit-/push-/upload-
operation: BLOKER operationen.

## Verdict-format

JSON skrives til stdout og gemmes i
`~/.<name>/secrets-scans/<YYYY-MM-DD>/<filename-slug>.json`:

```json
{
  "file": "src/config.production.json",
  "checked_at": "2026-05-10T12:00:00Z",
  "verdict": "FAIL",
  "risk_score": 85,
  "findings": [
    {
      "type": "aws_access_key",
      "severity": "critical",
      "line": 12,
      "match_preview": "AKIA****************",
      "context": "\"awsAccessKey\": \"AKIA****************\""
    },
    {
      "type": "connection_string",
      "severity": "high",
      "line": 24,
      "match_preview": "Server=prod-db…Password=****;",
      "context": "ConnectionStrings.Default"
    }
  ],
  "concerns": [
    "AWS access key with non-test prefix",
    "Production connection string with embedded password"
  ],
  "recommendations": [
    "Move AWS key to environment variable",
    "Use Azure Key Vault / AWS Secrets Manager for connection string",
    "Add this file to .gitignore"
  ],
  "operation_blocked": "git commit"
}
```

## Risk score (0–100)

| Finding | low | medium | high | critical |
|---|---|---|---|---|
| Provider-regex match (live key) | — | — | 50 | 80 |
| Provider-regex match (test key) | 5 | — | — | — |
| Private key block | — | — | — | 95 |
| Connection string with password (non-localhost) | — | 30 | 50 | — |
| Connection string with password (localhost) | 10 | — | — | — |
| Entropy candidate alone | 10 | 20 | — | — |
| Sensitive filename + non-trivial content | — | 25 | — | — |

**Verdict mapping:**
- `0–25` → `PASS`
- `26–60` → `WARN`
- `61–100` → `FAIL`
- Et hvilket som helst `critical` finding → automatisk `FAIL` uanset score.

## Exit codes

```
0 = PASS (no findings)
1 = WARN (low/medium findings, manual review)
2 = FAIL (high/critical findings — operation MUST be blocked)
3 = Tool/parse error (treat as WARN)
```

## Operationer der MUST blokeres ved FAIL

- `git add` / `git commit` / `git push` af den scannede fil
- Upload til chat-platform, paste-tool, web-tool eller MCP-endpoint
- Kopiering til shared/synced location (OneDrive, Dropbox, Google Drive)
- Inklusion i tool-output der sendes til en ekstern API

Lokal læsning til Claudes egen analyse er OK — Claude må gerne se secrets for at
hjælpe brugeren rotere dem. Det der ikke må ske er at de **forlader** maskinen.

## Whitelist

`~/.<name>/secrets-scanner/whitelist.json` — vetted filer/mønstre der springer scan over.

```json
{
  "files": [
    "tests/fixtures/fake-credentials.json",
    "docs/example-config.yml"
  ],
  "hashes": [
    "sha256:abc123..."
  ],
  "patterns": [
    "AKIATEST[0-9A-Z]{14}",
    "sk_test_[0-9a-zA-Z]{24,}"
  ]
}
```

Filen redigeres KUN manuelt af brugeren. Claude må ikke tilføje til den.

## Rapportering til brugeren

```
[secrets-scanner] src/config.production.json — FAIL — risk 85/100

✗ AWS access key (line 12)
✗ Production connection string with password (line 24)

OPERATION BLOKERET: git commit
Anbefaling: flyt secrets til miljøvariable + tilføj fil til .gitignore.
Fuld rapport: ~/.<name>/secrets-scans/2026-05-10/config-production.json
```

## Logging i sessionens handoff

```
[secrets-scanner] <fil> — <verdict> — <risk>/100 — <findings-count> findings
```

## Forudsætninger

- Regex-engine (PCRE eller .NET regex).
- Shannon-entropi-beregner (10 linjer kode).
- Filsystem-adgang til target-filer.
- Læseadgang til whitelist.

## Reference-filer

- `references/patterns.md` — fuld regex-katalog pr. provider, inkl. revoked-key-formater.
- `references/triage.md` — placeholder vs ægte secret-heuristikker, kontekst-regler,
  whitelist-anbefalinger.

Læs dem on-demand når du støder på en specifik provider eller en uklar finding.
