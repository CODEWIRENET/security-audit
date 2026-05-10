# Lockfile parser-reference

Hvordan man læser hver lockfile-type og udtrækker `(name, version, integrity-hash, source)`-
tupler. Brug i Fase 1 af dependency-rescan.

## npm — `package-lock.json`

JSON. v3 format (lockfileVersion 3) er nuværende default for npm 7+.

```json
{
  "name": "myproject",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "myproject", "version": "1.0.0" },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-...",
      "license": "MIT"
    }
  }
}
```

**Parser**: iterér `packages` keys. Skip top-level (`""`). Strip `node_modules/` prefix
fra key for at få pakke-navn. Inkludér scoped: `node_modules/@scope/pkg`.

**Edge cases**:
- Workspaces: `node_modules/<workspace-name>` peger på en lokal mappe. Skip pakker hvor
  `link: true` (lokale links, ikke registry-pakker).
- Optional deps: tjek `optional: true` flag, behandl samme måde som regular deps.

## pnpm — `pnpm-lock.yaml`

YAML. Format ændrer sig mellem pnpm-versioner; v6 er nuværende.

```yaml
lockfileVersion: '6.0'

dependencies:
  lodash:
    specifier: ^4.17.21
    version: 4.17.21

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-...}
    dev: false
```

**Parser**: iterér `packages` keys, parse `/<name>@<version>` syntaks. For scoped:
`/@scope/name@version`.

**Edge cases**:
- Peer-dependencies har version-suffix: `/react@18.2.0(react-dom@18.2.0)`. Strip alt efter
  første `(`.

## yarn v1 — `yarn.lock`

Custom format, ikke YAML/JSON. Hver entry:

```text
lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#..."
  integrity sha512-...
```

**Parser**: regex-baseret. Match `^([^@]+)@.*?:\n  version "([^"]+)"` for navn+version.

## yarn berry (v2+) — `yarn.lock`

YAML-lignende men ikke standard YAML. Har `__metadata` block i toppen:

```text
__metadata:
  version: 6
  cacheKey: 8c0
```

Strukturen ligner v1 men resolved er anderledes. Brug yarn's egne tools (`yarn info`)
eller en dedikeret parser.

## NuGet (PackageReference) — `packages.lock.json`

JSON. Genereres med `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` i
`.csproj`.

```json
{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "..."
      }
    }
  }
}
```

**Parser**: iterér target frameworks (`net8.0`, `net6.0`, etc.), så pakker. Behold kun
`type: Direct` for primær audit; `type: Transitive` afhænger af dem.

## NuGet (legacy) — `project.lock.json`

JSON. Bruges af gamle `project.json` projekter. Format ligner moderne men har
`libraries` sektion med integrity hashes.

## pub.dev (Flutter/Dart) — `pubspec.lock`

YAML.

```yaml
packages:
  provider:
    dependency: "direct main"
    description:
      name: provider
      sha256: "..."
      url: "https://pub.dev"
    source: hosted
    version: "6.1.1"
```

**Parser**: iterér `packages`. Filter `source: hosted` for pub.dev-pakker. Skip
`source: path` (lokale) og `source: git` (fra git-repos — kør separat git-audit).

## Poetry — `poetry.lock`

TOML.

```toml
[[package]]
name = "requests"
version = "2.31.0"
description = "..."

[package.dependencies]
charset-normalizer = ">=2,<4"
```

**Parser**: TOML har array-of-tables `[[package]]`. Hver er en pakke. Læs `name`,
`version`. Hashes findes i `[metadata.files]`-sektion (separat).

## Pipenv — `Pipfile.lock`

JSON.

```json
{
  "_meta": { "hash": { "sha256": "..." } },
  "default": {
    "requests": {
      "hashes": ["sha256:..."],
      "version": "==2.31.0"
    }
  },
  "develop": { ... }
}
```

**Parser**: iterér `default` og `develop` keys. Strip `==` fra version-string.

## pip — `requirements.txt`

Plain text. Kun nyttigt for audit hvis pinned med `==`:

```text
requests==2.31.0
django==4.2.7
numpy>=1.20.0  # ikke pinned, springes over
```

**Parser**: linje-for-linje, regex `^([A-Za-z0-9_.-]+)==([\w.-]+)$`. Skip kommentarer,
extras (`pkg[option]`), URL-baserede installs.

**Edge case**: hashes i requirements.txt:

```text
requests==2.31.0 \
    --hash=sha256:... \
    --hash=sha256:...
```

Slug hashes for verificering hvis tilgængelig (Fase 3 integrity-check).

## cargo (Rust) — `Cargo.lock`

TOML.

```toml
[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "..."
```

**Parser**: array-of-tables `[[package]]`. Filter på `source` der starter med
`registry+`. Skip `path = ".."`-stier.

## Go — `go.sum`

Plain text. Format:

```text
github.com/spf13/cobra v1.8.0 h1:...
github.com/spf13/cobra v1.8.0/go.mod h1:...
```

**Parser**: hver linje er `<module> <version>[/go.mod] <hash-prefix>:<hash>`. Brug
linjerne UDEN `/go.mod` for at få faktiske pakke-versioner.

`go.mod` har den deklarerede afhængighed; `go.sum` har den faktiske udvalgte version.
Audit'en skal bruge `go.sum` (det er sandheden).

## Composer (PHP) — `composer.lock`

JSON.

```json
{
  "_readme": [ ... ],
  "content-hash": "...",
  "packages": [
    {
      "name": "monolog/monolog",
      "version": "3.5.0",
      "dist": {
        "type": "zip",
        "url": "...",
        "shasum": "..."
      },
      "require": { ... }
    }
  ],
  "packages-dev": [ ... ]
}
```

**Parser**: iterér `packages` og `packages-dev`. Hver entry er en pakke. Læs `name` og
`version`.

## Edge cases på tværs af formater

### Monorepos / workspaces

Mange projekter har én lockfile i roden men flere `package.json`/`pubspec.yaml` i sub-
mapper. Lockfile'en indeholder den unionen af alle deps. Fint for audit (vi vil have
union).

Undtagelse: Yarn workspaces v2+ med separate caches pr. workspace. Tjek for
`.yarn/cache/` på flere niveauer.

### Lock-fri projekter

Projekter uden lockfile (sjældent men set): kør audit mod den deklarerede manifest med
range-versioner (`^1.0.0`, `~2.3.0`) som fallback. Mindre præcist men bedre end ingenting.
Flag projektet som `no_lockfile` (medium info).

### Forskellige filer for samme pakke

Mange formater har "lock" og "manifest" filer:

| Manifest | Lockfile |
|---|---|
| `package.json` | `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` |
| `*.csproj` | `packages.lock.json` |
| `pubspec.yaml` | `pubspec.lock` |
| `pyproject.toml` | `poetry.lock` |
| `Pipfile` | `Pipfile.lock` |
| `Cargo.toml` | `Cargo.lock` |
| `go.mod` | `go.sum` |
| `composer.json` | `composer.lock` |

Brug ALTID lockfile'en hvis den findes (præcis version-info). Manifest er fallback.

### Integrity-hash sammenligning

Når en pakke er uændret siden sidste rescan, sammenlign integrity-hashes:

| Format | Hash-felt |
|---|---|
| npm | `integrity` (sha512 ofte) |
| pnpm | `resolution.integrity` |
| yarn | `integrity` (kommer efter `version` linje) |
| NuGet | `contentHash` |
| pub.dev | `description.sha256` |
| Poetry | `[metadata.files]` array |
| Pipenv | `hashes` array |
| Cargo | `checksum` |
| Go | hash i `go.sum` |
| Composer | `dist.shasum` |

Hvis hash er identisk: pakke er definitivt uændret. Spring til CVE-delta-only-check.
Hvis hash mangler eller har ændret sig: kør fuld scan.
