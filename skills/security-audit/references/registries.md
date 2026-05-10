# Registry-tjek pr. type

Detaljerede tjek for hver artefakt-type. Læs kun den sektion der matcher den aktuelle type.

---

## npm

### Metadata-hentning

```bash
# Fuld pakkeinfo
npm view <pkg> --json

# Kun de relevante felter
npm view <pkg> time maintainers versions repository scripts.preinstall scripts.install scripts.postinstall --json
```

### Konkrete tjek

1. **Udgivelsesdato**: `time.<version>` — under 30 dage = WARN.
2. **Install scripts**: `scripts.preinstall`, `scripts.install`, `scripts.postinstall` skal være tomme eller trivielle (f.eks. `node-gyp rebuild`). Alt der downloader, eksekverer eller netværker = HIGH severity.
3. **Maintainer-skift**: sammenlign `maintainers` mellem nuværende og forrige version. Nyt navn der ikke har bidraget til repoet før = WARN.
4. **Source repo**: `repository.url` skal pege på et eksisterende repo. Ingen repo = WARN. Repo med 0 commits til pakken = HIGH.
5. **Weekly downloads**: hent fra `https://api.npmjs.org/downloads/point/last-week/<pkg>`. Under 100 downloads/uge for en pakke der hævdes at være "kendt" = WARN.
6. **Socket.dev**: `https://socket.dev/npm/package/<pkg>` — tjek for issues som `Install Scripts`, `Telemetry`, `Network Access`, `Filesystem Access`, `Shell Access`, `Native Code`.
7. **Snyk Advisor**: `https://snyk.io/advisor/npm-package/<pkg>` — score under 60 = WARN.
8. **Typosquat**: sammenlign mod top 1000 npm-pakker. Levenshtein ≤ 2 til en mere populær pakke = HIGH severity.

### Røde flag specifikt for npm

- Pakke med kun én version (`0.0.1`) udgivet i sidste uge.
- Maintainer-konto under 30 dage gammel.
- `package.json` indeholder `"main": "index.js"` men `index.js` indeholder obfuskeret kode eller `eval(...)`.
- Postinstall-script der kalder ud til en ekstern URL.
- Pakkenavn med Unicode-tegn der ligner ASCII (homoglyph attack).

---

## NuGet

### Metadata-hentning

```bash
# Pakkeinfo via NuGet API
curl -s "https://api.nuget.org/v3/registration5-gz-semver2/<pkg>/index.json" | jq

# Brug også
curl -s "https://api-v2v3search-0.nuget.org/query?q=packageid:<pkg>&prerelease=true"
```

### Konkrete tjek

1. **"Prefix Reserved"-badge**: tjek om `https://www.nuget.org/packages/<pkg>` viser badge. For Microsoft-, System-, og kendte org-prefixes er dette obligatorisk. Ingen badge på `Microsoft.X` = HIGH (kan være typosquat).
2. **Author/Owner**: skal matche forventet organisation. `Microsoft.AspNetCore.X` skal eje af `Microsoft`.
3. **Signing**: tjek om pakken er signeret. `nuget verify -All <pkg>.nupkg` eller fra metadata: `verified: true`.
4. **Total downloads**: under 1000 for en pakke der hævdes at være kendt = WARN.
5. **Udgivelsesdato**: senest udgivet under 30 dage siden = WARN-flag for nye pakker.
6. **GitHub-repo**: tjek `projectUrl` og `repository.url` — repo skal eksistere og have aktivitet.
7. **Vulnerabilities**: tjek `https://github.com/advisories?query=<pkg>` for kendte issues.
8. **Dependencies**: hent transitive deps og kør samme typosquat-tjek på dem (særligt for nye direkte deps).

### Røde flag specifikt for NuGet

- Pakke der hævder at være `Microsoft.X` men ejes af privat konto.
- Ingen signing på pakke der gemmer sig som officiel.
- "Newtonsoft" → `Newtonsoftt`, `NewtonSoft`, `Newton.Soft` = typosquats.
- Pakke uden source link.

---

## pub.dev (Flutter / Dart)

### Metadata-hentning

```bash
# Pakke-API
curl -s "https://pub.dev/api/packages/<pkg>" | jq

# Score-API
curl -s "https://pub.dev/api/packages/<pkg>/score" | jq
```

### Konkrete tjek

1. **Verified publisher**: `verified_publisher` flag i metadata. Ikke-verified = WARN for produktionsbrug.
2. **Pub points**: under 100 = WARN, under 80 = HIGH for kerne-deps.
3. **Likes**: under 10 likes for en pakke der hævdes at være kendt = WARN.
4. **Popularity**: pub.dev's tier-system (top 1%, 10%, etc.) — ny pakke uden popularity score = WARN.
5. **Platforms**: tjek at deklarerede platforms matcher hvad pakken faktisk bruger. En pakke der hævder kun "Web" men importerer `dart:io` = WARN.
6. **Repository**: skal eksistere, repository.url skal være offentlig.
7. **License**: skal være OSI-godkendt for kommerciel brug.
8. **Discontinued / unlisted**: discontinued = WARN, unlisted = HIGH (skjult fra søgning, ofte tegn på issue).

### Røde flag specifikt for pub.dev

- Pakke der bruger `dart:ffi` eller `dart:io` uden klar grund (mulig native code-injection).
- Pakker der overrider build_runner steps uden dokumentation.

---

## pip (PyPI)

### Metadata-hentning

```bash
# JSON-API
curl -s "https://pypi.org/pypi/<pkg>/json" | jq

# Specifik version
curl -s "https://pypi.org/pypi/<pkg>/<version>/json" | jq
```

### Konkrete tjek

1. **Author / maintainer email**: tjek mod kendt org. Generic gmail = WARN for kerne-pakker.
2. **`setup.py` / `pyproject.toml` build hooks**: PyPI's setup.py kan eksekvere arbitrær Python ved install. Tjek for `cmdclass`, `setup_requires`, post-install hooks.
3. **Wheels vs. sdist**: kun sdist-tilgængelig = WARN (kører setup.py ved install). Wheels-only er sikrere.
4. **Typosquat**: PyPI har historik for typosquats (`requests` → `request`, `urllib` → `urllib3` legitim, `urllib2` typosquat).
5. **Project URLs**: skal pege på legitim repo.

### Røde flag specifikt for pip

- Pakke uden wheels og med ikke-trivielt `setup.py`.
- Pakke der downloader binær under install.

---

## MCP-servere

MCP-servere er IKKE bare pakker — de eksponerer tools til LLM'er og kan kalde eksterne services. Læs ALTID source først.

### Konkrete tjek

1. **Source review**: åbn repo'et og læs faktisk koden. Hvilke tools eksponerer den (`server.setRequestHandler('tools/list', ...)` eller equivalent)?
2. **Eksterne kald**: laver serveren netværkskald? Til hvilke endpoints?
3. **Credentials**: beder serveren om API keys, tokens, eller andre credentials? Hvor sender den dem?
4. **Filsystem-adgang**: hvilke paths har den adgang til? Begrænser den sig?
5. **Shell exec**: bruger den `child_process.exec` eller equivalent? Med hvilke argumenter?
6. **Publisher**: officiel Anthropic/Microsoft/GitHub/kendt org? Eller privat konto?
7. **Stars og aktivitet**: men husk — stars alene betyder intet. Læs koden.

### Pre-godkendte MCP-servere (springer fuldt tjek over)

- `@playwright/mcp@latest` — pre-godkendt af Janus.
- `@modelcontextprotocol/server-filesystem` — officiel Anthropic.
- `@modelcontextprotocol/server-github` — officiel Anthropic.

### Røde flag specifikt for MCP

- Server der har et `eval` eller `execute_code` tool uden klar sandboxing.
- Server der beder om OAuth tokens og sender dem til ukendt endpoint.
- Server der tilbyder "alle features" — for bred et scope = mindre granular kontrol.

---

## Claude plugins / skills

### Konkrete tjek

1. **Source repo**: skal være offentligt og læseligt før installation.
2. **SKILL.md gennemlæsning**: læs hele SKILL.md før install. Kig efter:
   - Eksekverer den scripts? Hvilke?
   - Beder den Claude om at sende data til eksterne endpoints?
   - Modificerer den globale konfigurationer?
3. **Bundled scripts**: hvis skill'en har `scripts/` — gennemlæs hver fil. `bash`/`sh`/`python` scripts der kalder ud til ukendte URLs = HIGH.
4. **Author**: kendt person eller anonymt repo? Anonymt repo med få commits = WARN.

### Pre-godkendte plugins/skills

- Anthropic-officielle skills (under `anthropics/` på GitHub).
- Skills i `/mnt/skills/public/` (leveret af Anthropic).
- Janus' egne skills under `~/.claude/skills/`.

---

## VS Code / JetBrains extensions

### Konkrete tjek

1. **Verified publisher** badge i marketplace.
2. **Installs / ratings**: under 1000 installs for en extension der hævdes at være kendt = WARN.
3. **Permissions**: hvilke API'er bruger den? Network? Workspace files? Terminal access?
4. **Source repo link**: skal være tilgængeligt fra marketplace-siden.
5. **Recent updates**: ingen updates de sidste 12 måneder = WARN (måske abandoned).
6. **CVE-historik**: tjek for kendte issues.

### Røde flag

- Extension der hævder at give "AI features" men ikke har klart angivet hvilken model/endpoint den bruger.
- Extension der beder om unrelated permissions (en linter der vil have terminal-adgang).

---

## Binære filer / installers

### Konkrete tjek

1. **Download URL**: HTTPS, og domænet matcher den officielle kilde.
2. **SHA256-sum**: beregn lokalt og sammenlign med officielt offentliggjort sum hvis tilgængelig.
3. **Code signing**: tjek signature.
   - Windows: `signtool verify /pa /v <fil>` eller PowerShell `Get-AuthenticodeSignature <fil>`.
   - macOS: `codesign -dv --verbose=4 <fil>` og `spctl --assess --verbose <fil>`.
   - Linux: tjek GPG-signatur hvis udgiver leverer.
4. **VirusTotal**: ALTID for binære filer. Se `virustotal.md`.
5. **Signature-issuer**: signed by hvem? Match mod forventet organisation.

### Røde flag

- Download fra `bit.ly`, `tinyurl`, eller andre URL-shorteners.
- Ingen signature, eller signature fra ukendt udgiver.
- SHA256 mismatch.
- VirusTotal: 1+ malicious detections.

---

## Docker images

### Konkrete tjek

1. **Image digest**: brug pinned digest (`image@sha256:...`), ikke kun tag.
2. **Base image**: hvad bygger den på? `scratch`, `distroless`, `alpine`, `debian-slim` er bedre end `latest` ubuntu.
3. **Layers**: `docker history <image>` — kig efter mistænkelige RUN-kommandoer.
4. **Trivy scan**: `trivy image <image>` — fail på CRITICAL eller HIGH CVE'er.
5. **Image size**: usædvanligt stort image kan indeholde extra payloads.
6. **Publisher**: officielle images har "Docker Official Image" eller "Verified Publisher" badge på Docker Hub.
7. **Pulls**: under 10k pulls for en image der hævdes at være kendt = WARN.

### Røde flag

- Image der bruger `latest` tag uden digest pinning.
- Image med entrypoint der kalder ud til ekstern server ved start.
- Image fra ikke-verified publisher med "official"-klingende navn.
