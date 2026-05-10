# Secret-detection patterns

Komplet regex-katalog pr. provider. Brug PCRE-syntaks (kompatibel med ripgrep, .NET, Python `re`).

## Provider tokens

### AWS

| Type | Pattern | Severity |
|---|---|---|
| Access Key ID | `AKIA[0-9A-Z]{16}` | critical |
| Access Key ID (newer) | `(ASIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASCA)[0-9A-Z]{16}` | critical |
| Secret Access Key | `(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+=]{40}['\"]` | critical |
| Session Token | `(?i)aws(.{0,20})?session(.{0,20})?['\"][A-Za-z0-9/+=]{100,}['\"]` | high |

### Stripe

| Type | Pattern | Severity |
|---|---|---|
| Live secret | `sk_live_[0-9a-zA-Z]{24,}` | critical |
| Live restricted | `rk_live_[0-9a-zA-Z]{24,}` | critical |
| Live publishable | `pk_live_[0-9a-zA-Z]{24,}` | medium |
| Test secret | `sk_test_[0-9a-zA-Z]{24,}` | low (test-mode keys are not secret) |
| Webhook secret | `whsec_[0-9a-zA-Z]{32,}` | high |

### GitHub

| Type | Pattern | Severity |
|---|---|---|
| Personal Access Token (classic) | `ghp_[A-Za-z0-9]{36}` | critical |
| OAuth Access Token | `gho_[A-Za-z0-9]{36}` | critical |
| User-to-Server Token | `ghu_[A-Za-z0-9]{36}` | critical |
| Server-to-Server Token | `ghs_[A-Za-z0-9]{36}` | critical |
| Refresh Token | `ghr_[A-Za-z0-9]{36}` | critical |
| Fine-grained PAT | `github_pat_[A-Za-z0-9_]{82}` | critical |

### OpenAI / Anthropic

| Type | Pattern | Severity |
|---|---|---|
| OpenAI API Key | `sk-(proj-)?[A-Za-z0-9_-]{40,}` | critical |
| Anthropic API Key | `sk-ant-(api\|admin)[0-9]{2}-[A-Za-z0-9_-]{40,}` | critical |

### Google

| Type | Pattern | Severity |
|---|---|---|
| API Key | `AIza[0-9A-Za-z_-]{35}` | high |
| OAuth Client Secret | `(?i)client_secret['\"]?\s*:\s*['\"][A-Za-z0-9_-]{24,}['\"]` | high |
| Service Account JSON | `"type":\s*"service_account"` (file-level marker) | critical (whole file) |

### Slack / Discord / Telegram

| Type | Pattern | Severity |
|---|---|---|
| Slack Bot Token | `xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,}` | critical |
| Slack User Token | `xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{32,}` | critical |
| Slack App-Level Token | `xapp-[0-9]+-[A-Z0-9]+-[0-9]+-[A-Za-z0-9]+` | critical |
| Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{24,}` | high |
| Discord Bot Token | `[MNO][A-Za-z0-9_-]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}` | critical |
| Telegram Bot Token | `[0-9]{8,10}:[A-Za-z0-9_-]{35}` | high |

### JWT / Generic

| Type | Pattern | Severity |
|---|---|---|
| JWT (3 segments) | `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` | medium (kan være session token) |
| Bearer-style header | `(?i)authorization:\s*bearer\s+[A-Za-z0-9._-]{20,}` | high |

### Azure / Microsoft

| Type | Pattern | Severity |
|---|---|---|
| Storage Account Key | `(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{60,}` | critical |
| SAS Token | `(?i)sig=[A-Za-z0-9%+/=]{40,}&se=` | high |
| Client Secret | `(?i)client_secret['\"]?\s*=\s*['\"][A-Za-z0-9~_.-]{30,}['\"]` | critical |

### NuGet / npm registry tokens

| Type | Pattern | Severity |
|---|---|---|
| NuGet API Key | `oy2[a-z0-9]{43}` | critical |
| npm Access Token | `npm_[A-Za-z0-9]{36}` | critical |

## Private keys

```
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN PGP PRIVATE KEY BLOCK-----
-----BEGIN PRIVATE KEY-----
-----BEGIN ENCRYPTED PRIVATE KEY-----
```

Alle = `critical`. Private keys hører ikke hjemme i et repo, ikke engang krypterede.

## Connection strings

| Type | Pattern | Severity |
|---|---|---|
| PostgreSQL | `postgres(ql)?://[^:\s]+:[^@\s]+@[^/\s]+` | high (lower if host = localhost) |
| MySQL | `mysql://[^:\s]+:[^@\s]+@[^/\s]+` | high |
| MongoDB | `mongodb(\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+` | high |
| MSSQL (.NET) | `(?i)(Server\|Data Source)=[^;]+;.*?(Password\|Pwd)=[^;]+;` | high |
| Redis | `redis://[^:\s]*:[^@\s]+@[^/\s]+` | high |
| RabbitMQ | `amqp://[^:\s]+:[^@\s]+@[^/\s]+` | high |

For host = `localhost` / `127.0.0.1` / `::1` / `host.docker.internal`: nedjustér til
`medium` (development setup, mindre kritisk men stadig dårlig praksis at committe).

## High-entropy detection

For strenge der ikke matcher noget regex:

1. Find alle string-literals med længde ≥ 32.
2. Beregn Shannon-entropi: `H = -Σ p(c) * log2(p(c))` over tegn-frekvenser.
3. Tærskel: `H ≥ 4.5` AND længde ≥ 32 → kandidat.
4. Filtrér kendte ikke-secrets:
   - SHA256: hex, længde præcis 64, kun `[0-9a-f]`.
   - UUIDs: `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`.
   - Base64-billeder: starter med `iVBORw0KGgo` (PNG), `/9j/` (JPEG), `JVBERi0` (PDF).
   - Git SHAs: hex, længde 7–40.
5. Resterende kandidater = `medium`-severity, log med kontekst-snippet.

## Filename-only detection

Hvis ingen pattern matchede men filnavnet er sensitivt (jf. SKILL.md Fase 2 listen):
log som `medium` finding med type `sensitive_filename_no_content_match`. Kan være:
- Tom skabelon (acceptable hvis stadig committed)
- Krypteret/encoded indhold (separat scan needed)
- Faktiske secrets i et format vi ikke har pattern for (kræver manuelt review)

## False-positive-listen (kendte ikke-secrets der ligner)

| Mønster | Hvorfor det IKKE er en secret |
|---|---|
| `AKIAIOSFODNN7EXAMPLE` | AWS docs example key |
| `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | AWS docs example secret |
| `sk_test_*` (ikke-live) | Stripe test-mode, offentlig dokumentation |
| `0000000000000000` (nuller) | Placeholder |
| `xxxxxxxxxxxxxxxx` (x'er) | Placeholder |
| `<your-key>`, `<API_KEY>` | Template syntaks |

Disse hardcodes i triage-fasen, ikke som whitelist (whitelist skal være sjældent brugt).
