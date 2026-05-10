# Egress detection patterns

Detaljerede regler for klassifikation af outgoing-destinations + content-inspektion.

## Destination-klassifikation

### `chat`

Slack:
```
hooks.slack.com/services/*       # webhook
slack.com/api/chat.postMessage   # bot API
```

Telegram:
```
api.telegram.org/bot[0-9]+:[A-Za-z0-9_-]+/sendMessage
api.telegram.org/bot[0-9]+:[A-Za-z0-9_-]+/sendDocument
```

Discord:
```
discord.com/api/webhooks/*
discord.com/api/v[0-9]+/channels/*/messages
```

Microsoft Teams:
```
*.webhook.office.com/webhookb2/*
graph.microsoft.com/v1.0/teams/*/channels/*/messages
```

### `email`

API-baseret:
```
api.sendgrid.com/v3/mail/send
api.mailgun.net/v3/*/messages
api.postmarkapp.com/email
api.brevo.com/v3/smtp/email
api.resend.com/emails
```

SMTP via MCP/CLI (sværere at fange — flag når kommandolinje-kald rammer port 25/465/587).

### `sms`

```
api.twilio.com/2010-04-01/Accounts/*/Messages.json
sns.*.amazonaws.com               # AWS SNS
rest.messagebird.com/messages
```

### `paste` / `image-host` / `file-host`

```
pastebin.com/api/api_post.php
gist.github.com/                  # men også gist.githubusercontent.com for raw
dpaste.com/api/v2/
hastebin.com/documents
*.imgur.com/3/upload
api.imgur.com/3/upload
api.cloudinary.com/v1_1/*/upload
transfer.sh/                      # PUT to /<filename>
file.io/                          # POST to root
api.dropboxapi.com/2/files/upload
www.googleapis.com/upload/drive/v3/files
```

### `diagram` / `playground`

```
mermaid.live/                     # via /edit#... links er content-encoded
kroki.io/                         # POST diagram source
plantuml.com/plantuml/png/        # GET med encoded source i path
api.jsfiddle.net/
codepen.io/pen/save
codesandbox.io/api/v1/sandboxes/define
replit.com/data/repls/save
```

### `webhook` (generisk)

Hvis URL matcher `webhook` i path eller subdomain → flag som webhook-type.
Severity: behandl som `chat` eller `generic-http` afhængig af kontekst.

### `clipboard`

Tools/kommandoer:
```
clip.exe (Windows)
Set-Clipboard (PowerShell)
pbcopy (macOS)
xclip / xsel / wl-copy (Linux)
```

### `screenshot`

Tools:
```
screencapture (macOS)
gnome-screenshot, scrot, grim (Linux)
Save-Screenshot, Snipping Tool (Windows)
playwright screenshot
selenium screenshot
```

Screenshot-only er typisk OK; kombineret med upload (image-host eller chat-attachment)
flag som `screenshot_with_pii` (medium).

### `mcp`

MCP-tool-kald: tjek om tool-navnet matcher kendt outbound-pattern eller hvis tool's egen
metadata siger "external API call".

Mønstre der indikerer outbound:
```
mcp__<server>__send_*
mcp__<server>__post_*
mcp__<server>__upload_*
mcp__<server>__publish_*
mcp__<server>__notify_*
mcp__<server>__email_*
mcp__<server>__telegram_*
mcp__<server>__slack_*
```

### `generic-http`

Fallback for ikke-klassificerede domæner. Brug `unknown_destination`-flag.

## Glob-matching mod allowed-domains.txt

Implementér standard glob:
- `*` matcher 0+ tegn (ikke `/`)
- `**` matcher 0+ tegn (inkl. `/`)
- `?` matcher 1 tegn

Eksempler:

```
*.codewire.net    matcher  api.codewire.net  ✓
                           www.codewire.net  ✓
                           a.b.codewire.net  ✗ (kun ét niveau, brug **.codewire.net)

**.codewire.net   matcher  a.b.codewire.net  ✓

api.telegram.org/bot6414779032/*
                  matcher  api.telegram.org/bot6414779032/sendMessage  ✓
                  matcher  api.telegram.org/bot9999999999/sendMessage  ✗
```

## Payload-format detection

### JSON

Content-Type: `application/json`. Payload starter med `{` eller `[`.

Kør secrets-scan på string-værdier rekursivt. Beregn samlet bytes.

### multipart/form-data

Content-Type: `multipart/form-data; boundary=...`. Indeholder formfelter + filer.

For hver fil-part: kør secrets-scan på indholdet. Tjek filename-pattern (sensitivt
filnavn = high flag selv hvis indhold er trivielt).

### URL-encoded

Content-Type: `application/x-www-form-urlencoded`. Payload er `key=value&key2=value2`.

Decode hver value, kør secrets-scan.

### Binary

Content-Type: `application/octet-stream` eller `image/*` etc. Hvis filnavn matcher
sensitivt mønster: high flag selv uden content-scan.

For billeder: ingen content-scan (vi kan ikke OCR'e tekst i billeder her). Men hvis
operationen er en screenshot-upload-kæde: flag som `screenshot_with_pii` (medium).

## Frequency-tuning

Default thresholds:
- 1-3 / 5min: OK
- 4-10 / 5min: low
- 11-30 / 5min: medium
- 30+ / 5min: high

Disse er konservative. Brugere der har faktiske bulk-flows (CI-rapporter, audit-loops)
bør tune via:

`~/.<name>/egress-audit/frequency-overrides.json`:

```json
{
  "api.telegram.org/bot6414779032/*": {
    "5min_warn": 20,
    "5min_high": 60,
    "reason": "Janus' personal alert bot, expected high volume during deploy windows"
  }
}
```

## Frequently confused: secrets-scanner vs egress-audit

Same finding-types, different timing:

| Finding | secrets-scanner | egress-audit |
|---|---|---|
| AWS-key i `config.json` | Ja (filnavn-match + content) | Kun hvis filen sendes ud |
| AWS-key i payload-body til Slack | Nej (ikke en fil-operation) | Ja (`secret_in_payload`) |
| `~/.aws/credentials` der pakkes som zip | Ja (filnavn-match) | Ja (når zip-filen sendes) |

Best practice: kør altid begge i sekvens. `secrets-scanner` på filer der pakkes/sendes,
`egress-audit` på selve send-operationen.

## False-positive-listen

Følgende er kendte legitime outbound-mønstre der bør være pre-godkendt:

| Mønster | Hvorfor |
|---|---|
| `*.npmjs.com`, `registry.npmjs.org` | npm install henter fra registry |
| `*.nuget.org`, `api.nuget.org` | NuGet install |
| `pub.dev`, `pub.dartlang.org` | pub.dev install |
| `pypi.org`, `pypi.python.org` | pip install |
| `crates.io`, `static.crates.io` | cargo install |
| `proxy.golang.org`, `sum.golang.org` | go modules |
| `*.docker.io`, `*.docker.com`, `ghcr.io` | docker pull |
| `objects.githubusercontent.com`, `codeload.github.com` | git clone over HTTPS |
| `api.github.com`, `raw.githubusercontent.com` | GitHub API + raw files |

Disse hører til en pre-leveret default-allow-liste i `allowed-domains.txt`-templaten.

## Edge cases

### Redirect-chains

Hvis destination returnerer 30x: følg op til 5 redirects og audit den endelige
destination også. Hvis nogen i kæden er `unknown_destination`: flag.

### URL-shorteners

```
bit.ly, tinyurl.com, t.co, goo.gl, ow.ly, is.gd, buff.ly
```

Disse skjuler den ægte destination. Resolve dem først (HEAD-request, læs Location-header)
og audit den resolverede URL. Hvis resolution fejler: flag som `unknown_destination` med
ekstra `severity_bump: shortener_unresolvable`.

### IP-baserede destinations

```
^https?://([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]+)?(/|$)
```

IP-adresser i stedet for domænenavne er mistænkelige. Hvis IP er privat (10.x, 172.16-31,
192.168.x, 127.x): OK. Hvis offentlig: `unknown_destination` automatisk.

### IPv6

```
^https?://\[[0-9a-fA-F:]+\](:[0-9]+)?(/|$)
```

Samme regel som IPv4. Privat IPv6 (fc00::/7) OK; offentlig flag.
