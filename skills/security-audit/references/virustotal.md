# VirusTotal API v3

Komplet reference til VirusTotal-integration. Brug kun for `binary` og `docker`-typer (samt URL-tjek af download-links).

## API-key

```bash
# Kræves for automatiseret tjek
export VIRUSTOTAL_API_KEY="<din-key>"
```

Få key på `https://www.virustotal.com/gui/my-apikey` efter login. Free tier: **4 requests/min**, **500/dag**, **15.5k/måned**.

Hvis `VIRUSTOTAL_API_KEY` ikke er sat: byg GUI-URL og bed brugeren om manuel verifikation. Marker tjekket som `WARN` indtil bekræftet:

```
https://www.virustotal.com/gui/file/<sha256>
https://www.virustotal.com/gui/url/<base64url-id>
https://www.virustotal.com/gui/domain/<domain>
```

## Endpoints

Base URL: `https://www.virustotal.com/api/v3/`

Alle requests kræver header: `x-apikey: $VIRUSTOTAL_API_KEY`

### Fil-rapport via hash (primær use case)

```bash
SHA256=$(sha256sum <fil> | awk '{print $1}')

curl -s \
  -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/files/$SHA256"
```

På Windows:

```powershell
$sha = (Get-FileHash <fil> -Algorithm SHA256).Hash.ToLower()
curl -H "x-apikey: $env:VIRUSTOTAL_API_KEY" `
  "https://www.virustotal.com/api/v3/files/$sha"
```

Response 404 betyder filen er ukendt for VT — overvej at uploade den (se nedenfor).

### Upload af fil (hvis hash er ukendt)

```bash
# Op til 32 MB direkte
curl -s \
  -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  -F "file=@<fil>" \
  "https://www.virustotal.com/api/v3/files"
```

Response indeholder en `analysis_id`. Poll resultatet:

```bash
curl -s \
  -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/analyses/<analysis_id>"
```

For filer over 32 MB: kald `/files/upload_url` først for at få en signed upload URL.

### URL-rapport

URL-id er base64url-encoded URL uden padding:

```bash
URL="https://example.com/installer.exe"
URL_ID=$(echo -n "$URL" | base64 -w 0 | tr '+/' '-_' | tr -d '=')

curl -s \
  -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/urls/$URL_ID"
```

Hvis ukendt: scan først:

```bash
curl -s \
  -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  --data-urlencode "url=$URL" \
  "https://www.virustotal.com/api/v3/urls"
```

### Domain-rapport

```bash
curl -s \
  -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/domains/<domain>"
```

### IP-rapport

```bash
curl -s \
  -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/ip_addresses/<ip>"
```

## Response-parsing

De vigtige felter ligger under `data.attributes`:

```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "harmless": 60,
        "malicious": 0,
        "suspicious": 0,
        "undetected": 12,
        "timeout": 0,
        "type-unsupported": 0,
        "failure": 0
      },
      "last_analysis_date": 1715000000,
      "first_submission_date": 1700000000,
      "times_submitted": 142,
      "reputation": 0,
      "total_votes": { "harmless": 0, "malicious": 0 },
      "meaningful_name": "<navn>",
      "signature_info": {
        "verified": "Signed",
        "signers": "Microsoft Corporation; ..."
      }
    }
  }
}
```

### Aggregering til verdict

Med `jq`:

```bash
RESULT=$(curl -s -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/files/$SHA256")

MALICIOUS=$(echo "$RESULT" | jq -r '.data.attributes.last_analysis_stats.malicious // 0')
SUSPICIOUS=$(echo "$RESULT" | jq -r '.data.attributes.last_analysis_stats.suspicious // 0')
LAST_DATE=$(echo "$RESULT" | jq -r '.data.attributes.last_analysis_date // 0')
NOW=$(date +%s)
AGE_DAYS=$(( (NOW - LAST_DATE) / 86400 ))

if [ "$MALICIOUS" -ge 1 ]; then
  echo "CRITICAL: $MALICIOUS engines flagged this file as malicious"
  exit 2
elif [ "$SUSPICIOUS" -ge 3 ]; then
  echo "HIGH: $SUSPICIOUS engines flagged this file as suspicious"
  exit 1
elif [ "$AGE_DAYS" -gt 30 ]; then
  echo "MEDIUM: Last analysis $AGE_DAYS days old, recommend rescan"
  exit 1
else
  echo "OK: 0 malicious, $SUSPICIOUS suspicious, scanned $AGE_DAYS days ago"
  exit 0
fi
```

### Threshold-tabel

| Tilstand | Severity |
|---|---|
| `malicious >= 1` | `critical` |
| `suspicious >= 3` | `high` |
| `suspicious 1–2` | `medium` |
| `last_analysis_date > 30 dage gammel` | `medium` (re-scan anbefalet) |
| 0 malicious, 0 suspicious, frisk dato | `ok` |

**Bemærk**: ægte 0-day malware vil ofte have `malicious: 0` simpelthen fordi engines endnu ikke har lært den. Brug VT som ét signal blandt flere — ikke det eneste.

## Rate limiting

Free tier: **4 requests/min**.

Ved batch-tjek (flere artefakter): sleep 16s mellem requests for at holde sig under loftet:

```bash
for sha in "${HASHES[@]}"; do
  curl -s -H "x-apikey: $VIRUSTOTAL_API_KEY" \
    "https://www.virustotal.com/api/v3/files/$sha"
  sleep 16
done
```

Ved 429 (rate limited): exponential backoff — 30s, 60s, 120s, abort efter 3 forsøg.

## Edge cases

### Filen er for ny til at være indekseret

Hvis filen lige er udgivet (f.eks. en GitHub Release fra i dag), kan VT returnere 404. Upload den i stedet, eller bed brugeren om at vente og uploade manuelt:

```
https://www.virustotal.com/gui/home/upload
```

### Filen er for stor (>32 MB)

Brug `/files/upload_url`-endpointet først:

```bash
UPLOAD_URL=$(curl -s -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  "https://www.virustotal.com/api/v3/files/upload_url" | jq -r '.data')

curl -s -X POST \
  -H "x-apikey: $VIRUSTOTAL_API_KEY" \
  -F "file=@<stor-fil>" \
  "$UPLOAD_URL"
```

### Privacy-følsomme filer

Vær opmærksom på: **alt der uploades til VT bliver delt med VT-partnere** og potentielt offentligt søgbart. Upload aldrig:
- Filer med credentials, secrets, API keys, tokens.
- Klient-data, persondata, GDPR-relevant indhold.
- Internt udviklet kode der ikke skal lækkes.

For sådanne filer: hash-lookup OK (hashen lækker ikke indhold), men aldrig upload.

### Docker images

VT scanner ikke Docker images direkte. Brug i stedet:

```bash
trivy image <image>
docker scout cves <image>
```

Og verificér image digest mod registry's officielle digest.

## GUI-URLs til manuel verifikation

Når API-key ikke er tilgængelig, generér disse links til brugeren:

```
File:    https://www.virustotal.com/gui/file/<sha256>
URL:     https://www.virustotal.com/gui/url/<base64url-id>
Domain:  https://www.virustotal.com/gui/domain/<domain>
IP:      https://www.virustotal.com/gui/ip-address/<ip>
Search:  https://www.virustotal.com/gui/search/<query>
```

## Officielle docs

- API v3 reference: https://docs.virustotal.com/reference/overview
- Python wrapper (`vt-py`): https://virustotal.github.io/vt-py/
