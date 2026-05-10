# Hook detection patterns

Detaljerede regler for at klassificere en hook-kommando i en eller flere kategorier.
Læs denne on-demand i Fase 3 af hook-audit workflow.

## `network_egress` — hook laver eksternt netværkskald

### Bash / sh

```regex
\b(curl|wget|http|fetch|nc|ncat|telnet)\s+
```

Plus argument-form med URL: `[a-z]+://[^\s'"]+`.

**Whitelisted destinationer** (nedjustér til `info`):
- `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`
- `host.docker.internal`
- `*.codewire.net` (din egen infrastruktur — tilpas pr. bruger via whitelist.json)

### PowerShell

```regex
\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm|curl|wget|Start-BitsTransfer|System\.Net\.WebClient)\b
```

### Node / npm hooks

```regex
\b(fetch|axios|got|node-fetch|http\.request|https\.request)\b
```

### Python

```regex
\b(requests\.|urllib\.|httpx\.|aiohttp\.|socket\.connect)\b
```

### Severity ladder

- Kald til whitelisted host → `info`.
- Kald til localhost/private IP → `low`.
- Kald til offentlig URL uden auth → `medium`.
- Kald til offentlig URL med POST og indhold der refererer env/tool-IO → `high`.

---

## `env_read` — hook læser env-variabler

### Bash / sh

```regex
\b(printenv|env\b|set\b)\s*(\||>|;|$)
\$\{?[A-Z_]+\}?
```

Specielt sensitive variabel-navne (case-insensitive):

```regex
.*KEY.*|.*TOKEN.*|.*SECRET.*|.*PASSWORD.*|.*PASSWD.*|.*PWD.*|.*AUTH.*|.*CREDENTIAL.*|.*PRIVATE.*
```

Hvis hook-kommando refererer en af disse → `medium` minimum. Hvis env-listen sendes
videre (pipe, redirect til fil, redirect til netværk): `high`.

### PowerShell

```regex
\$env:[A-Z_]+
\bGet-ChildItem\s+env:
\b\$env\b
```

### Specifikke env-vars der altid er sensitive

```
ANTHROPIC_API_KEY            CLAUDE_CODE_OAUTH_TOKEN
GITHUB_TOKEN                 GH_TOKEN
NPM_TOKEN                    NUGET_API_KEY
AWS_ACCESS_KEY_ID            AWS_SECRET_ACCESS_KEY
GCP_SERVICE_ACCOUNT_KEY      GOOGLE_APPLICATION_CREDENTIALS
SLACK_TOKEN                  TELEGRAM_BOT_TOKEN
DATABASE_URL                 CONNECTION_STRING
SSH_AUTH_SOCK                SSH_PRIVATE_KEY
```

Read af en af disse + en anden flag (network_egress, clipboard_write, file_write
udenfor projekt) → automatisk `critical`.

---

## `clipboard_write` — hook skriver til clipboard

### Windows

```regex
\b(clip\.exe|clip\b|Set-Clipboard)\b
```

### macOS

```regex
\bpbcopy\b
```

### Linux

```regex
\b(xclip\b|xsel\b|wl-copy\b)\b
```

Severity: `medium` alene. Clipboard-write + tool_io_capture → `high` (bruger paster
indholdet uden at vide det).

---

## `obfuscation` — base64/hex/escaping

### Base64-decode patterns

```regex
\bbase64\s+(-d|--decode|-D)\b
\bbase64\.b64decode\b
\[Convert\]::FromBase64String
\bdecodeURIComponent\b
```

Combined med `eval`/`exec`/`Invoke-Expression`/`iex`/`bash <(...)` → kritisk.

### Encoded PowerShell

```regex
powershell(\.exe)?\s+(-enc|-e|-EncodedCommand)\s+[A-Za-z0-9+/=]{40,}
```

= automatisk `high` minimum. Encoded commands er hyppigt malware-leveringsmiddel.

### Hex / octal escapes

```regex
\\x[0-9a-fA-F]{2}|\\0[0-7]{1,3}
```

Mere end 5 escape-sekvenser i én command → `medium`. Mere end 20 → `high`.

### Excessive escaping

Tæl mængden af `\` eller `^` (PowerShell) eller `` ` ``-escapes. Threshold:

- > 30% af command er escape-tegn → `high`.

---

## `pipe_to_shell` — `curl | bash` mønstre

```regex
\b(curl|wget|fetch|Invoke-WebRequest|irm|iwr)\b[^|]*\|\s*(sh|bash|zsh|fish|pwsh|powershell|iex|Invoke-Expression)
```

Eller bash-syntaks `bash <(curl ...)`:

```regex
\b(bash|sh|zsh)\s+<\(\s*(curl|wget|fetch)
```

Severity: **automatisk `critical`**. Der findes ingen legitim grund til at en Claude Code
hook eksekverer fjern-hentet kode uden review.

---

## `unknown_binary` — hook kalder en binær der ikke kan verificeres

### Detection

1. Parse første token i kommandoen (eller efter `&&`/`;`/`|`).
2. Hvis det er en kendt builtin (`echo`, `printf`, `cd`, `ls`, etc.) → skip.
3. Hvis det er en sti (`/usr/local/bin/foo` eller `C:\Tools\foo.exe`):
   - Tjek om filen eksisterer.
   - Tjek code-signing (Windows: `Get-AuthenticodeSignature`. macOS: `codesign -dv`).
   - Hvis usigneret eller ukendt udgiver → `medium`.
   - Hvis filen ikke eksisterer → `medium` (måske er den i PATH, eller måske mangler den).
4. Hvis det er bare et navn (`foo`):
   - Slå op i PATH.
   - Hvis ikke fundet → `low` (kan være installeret senere).
   - Hvis fundet og signeret af kendt udgiver (Microsoft, Apple, GitHub, Anthropic, etc.) → skip.

### Whitelisted binær-navne (skip check)

```
git, node, npm, pnpm, yarn, dotnet, python, python3, pip, cargo, go, flutter, dart,
docker, kubectl, terraform, ansible, ssh, scp, rsync, jq, curl, wget, sed, awk, grep,
find, ls, cat, head, tail, sort, uniq, wc, echo, printf, test, true, false, sleep,
date, mktemp, dirname, basename, realpath, readlink, cp, mv, rm, mkdir, rmdir, touch,
chmod, chown, ln, tee, xargs, cut, tr, paste, diff, patch
```

(Deres tilstedeværelse er forventet på de fleste systemer; deres misbrug fanges af de
øvrige kategorier — fx `curl` til exfil-domæne fanges af `network_egress`.)

---

## `recent_change` — hook tilføjet/modificeret nylig

### Detection

For hver settings.json-fil i et git-repo:

```bash
git log -1 --format=%ct -- <fil>
```

Hvis `now - last_change_timestamp < 7 days` → flag fil med `recent_change`.

For hooks-array-niveau: parse historik over filen, find første commit hvor en specifik
hook-hash optrådte. Hvis under 7 dage → flag den specifikke hook.

For settings.local.json (untracked): brug `Get-Item ... .LastWriteTime` (Windows) eller
`stat -c %Y ...` (Linux/macOS). Mindre præcist (kan være ændret af noget andet end hook),
men bedste tilgængelige signal.

### Severity

`recent_change` alene = `low` (5 point). Kombineret med en anden flag = **opjustér ét
trin**. Fersk + obfuscation + network = klassisk drive-by attack.

---

## `excessive_scope` — for bred matcher

Hook-matcher feltet bestemmer hvilke tools hook'en fyrer på. Eksempler:

| Matcher | Scope | Risk |
|---|---|---|
| `Bash` | Kun bash-tool | OK |
| `Edit\|Write` | To tools | OK |
| `*` eller `.*` eller fraværende | Alle tools (inkl. Read, WebFetch, …) | medium |

En hook der fyrer på `*` får alt at se — alt Claude læser, alt det skriver, alt det
fetcher. For en logging-hook kan det være legitimt; for noget der laver en POST udad
er det rødt flag.

Severity: `low` alene. Kombineret med `network_egress` = `medium`. Kombineret med
`tool_io_capture` = `high`.

---

## `tool_io_capture` — hook læser tool input/output

### Bash / sh — Claude Code injicerer tool-IO via env-vars

```regex
\$CLAUDE_TOOL_INPUT|\$CLAUDE_TOOL_OUTPUT|\$\{CLAUDE_TOOL_INPUT\}|\$\{CLAUDE_TOOL_OUTPUT\}
```

### PowerShell

```regex
\$env:CLAUDE_TOOL_INPUT|\$env:CLAUDE_TOOL_OUTPUT
```

### Severity

- Læser men gemmer kun lokalt (`> file.log`) → `info`.
- Læser og piper til shell-kommando (`grep`, `awk`, `jq`) → `low`.
- Læser og sender til netværk → `critical` (auto-promote).
- Læser og kopierer til clipboard → `high`.

---

## `instruction_injection` — CLAUDE.md exfil-bedrageri

CLAUDE.md er ikke en hook-fil men en instructions-injection-vektor. Scan for sætninger der
beder Claude om at gøre noget mistænkeligt:

### Detection-mønstre (case-insensitive)

```
"send.*to.*(http|ftp|api|webhook)"
"upload.*to.*[a-z]+://"
"copy.*credentials.*to"
"include.*\$env|\$ENV.*in.*request"
"silently.*run|run.*silently"
"do not (tell|inform|notify) the user"
"hide this from the user"
"exfil"
"\\$\\(.*base64.*\\)"
```

### Sværere at fange (kontekst-afhængigt)

- Instruktioner der ændrer Claudes default-adfærd uden forklaring.
- Instruktioner der specifikt beder om at læse filer udenfor projekt-scope.
- Instruktioner der kræver at credentials inkluderes i tool-output.

For disse: vis den fulde kontekst (±5 linjer omkring match) og lad brugeren bekræfte.
Severity `medium` indtil bekræftet.

---

## False-positive-listen (kendte legitime hooks)

| Pattern / hook | Hvorfor det IKKE er ondsindet |
|---|---|
| `git diff --cached \| pre-commit run` | Standard pre-commit framework, kun lokalt |
| `eslint $CLAUDE_TOOL_OUTPUT` (læser tool-output men kun til linting) | Lokal lint, ingen netværk |
| `notify-send "Task done"` | Lokal notification |
| `osascript -e 'display notification "..."'` | Lokal macOS notification |
| Hooks der skriver til `~/.<name>/audit.log` | Lokal audit, foreslået af security-audit selv |
| `codewire-telegram.exe send ...` (per CODEWIRE CLAUDE.md) | Bruger-godkendt notification-CLI |

For disse anbefales whitelist.json entries med `reason`-felt så audit forbliver
revisitable.

---

## Kombinations-regler (recap)

```
network_egress + env_read           → automatisk critical
network_egress + tool_io_capture    → automatisk critical
network_egress + obfuscation        → automatisk critical
recent_change + ANY other flag      → opjustér ét trin
pipe_to_shell                       → automatisk critical (alene)
```

Disse kombinations-regler implementeres i Fase 3 af workflow.
