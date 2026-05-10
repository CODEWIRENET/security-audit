# Permission detection patterns

Detaljerede regler for at klassificere en allow/deny-rule i en eller flere kategorier.
Læs denne on-demand i Fase 3 af permissions-audit workflow.

## `wildcard_allow` — bredt match

```regex
^\*$|^[A-Za-z]+\(\*\)$|^[A-Za-z]+\(\.\*\)$
```

Eksempler:
- `*` — matcher alt
- `Bash(*)` — alle bash-kommandoer
- `Edit(*)` — alle filer
- `WebFetch(*)` — alle URLs
- `mcp__*` — alle MCP tools

**Severity ladder:**
- `*` (root wildcard) — `high` (50)
- `Bash(*)` / `Edit(*)` / `Write(*)` — `high` (50)
- `WebFetch(*)` — `medium` (25)
- `mcp__<server>__*` (alle tools fra én server, server pinned) — `low` (10)
- `mcp__*` (alle tools fra alle servere) — `medium` (25)

## `destructive_command` — kommandoer der kan ødelægge data

### Filsystem-destruktive

```
rm                    # delete files/dirs
rmdir                 # delete dirs
unlink                # delete file
shred                 # securely delete
dd                    # bit-level write — kan overskrive disks
mkfs                  # format filesystem
fdisk                 # partition disk
parted                # partition disk
wipefs                # wipe filesystem signatures
blkdiscard            # discard block device
```

Windows:
```
format                # format drive
del                   # delete (cmd)
erase                 # delete (cmd)
Remove-Item           # delete (PowerShell, when used with -Force -Recurse)
Clear-Disk
Initialize-Disk
```

### Privilege-eskalation

```
sudo                  # elevate (Linux/macOS)
runas                 # elevate (Windows)
doas                  # elevate (BSD)
gksu / pkexec         # GUI elevation (Linux)
```

### Konfigurations-mutation

```
reg delete            # registry deletion (Windows)
reg add               # registry add (Windows)
sysctl -w             # kernel parameter mutation
chmod 777             # excessive permission grant (specifik form)
chown -R              # recursive ownership change
setfacl               # ACL change
attrib                # file attribute change (Windows)
```

### System-state

```
shutdown              # power off
reboot                # restart
halt                  # halt
poweroff              # power off
Stop-Computer         # PowerShell shutdown
Restart-Computer      # PowerShell restart
```

### Network/process

```
iptables              # firewall rule mutation
nft / nftables        # firewall rule mutation
netsh advfirewall     # Windows firewall mutation
kill -9               # force kill (acceptable for own processes, dangerous in allow)
killall               # mass kill
taskkill /F           # force kill (Windows)
```

### Pattern matching

Allow-rule der er en af disse strenge med `:*` suffix matcher kommandoen + alle args.
Specifikke args kan dog være sikre (`Bash(rm /tmp/test)` er fint), så audit skelner:

| Allow-rule | Severity |
|---|---|
| `Bash(rm:*)` | critical |
| `Bash(rm -rf:*)` | critical |
| `Bash(rm)` | medium (ingen args = harmless) |
| `Bash(rm /tmp/test)` | low (specific path) |
| `Bash(rm -rf /tmp/build:*)` | low (specifik prefix path) |
| `Bash(sudo:*)` | critical |
| `Bash(sudo -n -k)` | low (specific safe sub-command) |

## `pipe_to_shell_allow` — eksekver fjern-hentet kode

Allow-rules der dækker `curl|bash`-mønstre:

```regex
\b(curl|wget|fetch|Invoke-WebRequest|irm|iwr)\b.*\|\s*(sh|bash|zsh|fish|pwsh|powershell|iex|Invoke-Expression)
```

Eller bash-syntaks:

```regex
\b(bash|sh|zsh)\s+<\(\s*(curl|wget|fetch)
```

**Severity: automatisk `critical`.** Der findes ingen legitim grund til at allow-liste
fjern-eksekvering uden prompt.

## `system_path_write` — skriv-adgang til system-mapper

### Linux/macOS forbudte stier (alle giver `high`)

```
/etc/*
/usr/bin/*
/usr/sbin/*
/usr/lib/*
/var/log/*  (kan være OK for read, ikke write)
/boot/*
/sys/*
/proc/*
/dev/*  (på nær /dev/null, /dev/tty)
```

### Windows forbudte stier (alle giver `high`)

```
C:\Windows\*
C:\Windows\System32\*
C:\Program Files\*
C:\Program Files (x86)\*
C:\ProgramData\*  (afhænger af subfolder)
C:\Users\Default\*
HKLM:\*  (registry hives)
```

### Detektion

```regex
^Edit\((/etc/|/usr/|/boot/|/sys/|/proc/|/dev/|C:\\Windows\\|C:\\Program Files)
^Write\(...samme...\)
```

## `bash_unsafe_flag` — flags der eksekverer arbitrær kode

```regex
Bash\(.*\s-c\s.*\)                # bash -c "any command"
Bash\(.*\seval\b.*\)              # eval-baseret
Bash\(.*\sexec\b.*\)              # exec-baseret
Bash\(.*\$\(.*\).*\)              # command substitution i allow-rule
Bash\(.*`.*`.*\)                  # backtick command substitution
```

**Severity: `high`** (40). Brugeren forventer typisk at `Bash(npm:*)` betyder npm-kald,
ikke "npm anything inkl. shell-injection".

## `network_unrestricted` — fri internet-adgang

```regex
^WebFetch\(\*\)$
^WebFetch\(http[s]?:\*\)$
^WebFetch\(.*\*.*\)$  (med wildcard et eller andet sted)
```

**Severity:**
- `WebFetch(*)` eller `WebFetch(http*)` → `medium` (25)
- `WebFetch(https://*.<din-org>.com/*)` → `low` (10)
- `WebFetch(https://docs.claude.com/*)` → fint (10)

## `mcp_unrestricted` — fri adgang til MCP-tools

```regex
^mcp__\*$                         # alle MCP tools fra alle servere
^mcp__[a-z_-]+__\*$               # alle tools fra én server (mindre dårligt)
```

MCP-tools kan tilgå eksterne services. Auto-approve af alle = mister granulær kontrol.

## `recent_addition` — tidsstempel-detektion

For hver allow-rule:

1. Hvis settings-filen er i et git-repo: `git log -1 --format=%ct -L /<rule>/:<file>`
2. Hvis ikke: brug fil-mtime som proxy (mindre præcist).

Threshold: < 7 dage = flag.

**Severity:** `low` (5) alene. Multiplikator: kombineret med en risk-kategori → opjustér
ét trin.

## `drift_added` / `drift_deny_removed` — snapshot-diff

Sammenlign nuværende `allow` med blessed snapshot's `allow`:

- Nye entries i nuværende men ikke i snapshot → `drift_added`.
- Entries i snapshot's `deny` men ikke i nuværende → `drift_deny_removed`.

`drift_added` på en risk-kategori → multiplikator (opjustér).
`drift_deny_removed` alene → `high` (40). At fjerne en deny-regel er specielt mistænkeligt
fordi det udvider hvad Claude må uden prompt.

## Snapshot-format

```json
{
  "_meta": {
    "saved_at": "2026-05-10T12:00:00Z",
    "saved_by": "janus",
    "approval_message": "Reviewed all rules, all currently safe for this dev machine",
    "settings_file": "~/.claude/settings.json"
  },
  "permissions": {
    "allow": [
      "Bash(npm test)",
      "Bash(npm run build)",
      "Edit(src/**)"
    ],
    "ask": [
      "Bash(npm install)",
      "WebFetch(*)"
    ],
    "deny": [
      "Bash(rm:*)",
      "Bash(curl:* | bash)",
      "Edit(/etc/**)"
    ]
  }
}
```

## Tight-scope-alternativer (anbefalinger til brugeren)

Når en regel flagges, foreslå et tight-scope alternativ:

| For-bredt | Anbefalet alternativ |
|---|---|
| `Bash(*)` | List specifikke kommandoer: `Bash(npm test)`, `Bash(npm run build)`, `Bash(git status)` |
| `Bash(rm:*)` | Fjern fra allow. Brug `ask` eller specifikke paths: `Bash(rm /tmp/build:*)` |
| `WebFetch(*)` | Liste af domæner: `WebFetch(https://docs.claude.com/*)`, `WebFetch(https://github.com/*)` |
| `Edit(*)` | Begræns til projekt-mapper: `Edit(./src/**)`, `Edit(./tests/**)` |
| `mcp__*` | List specifikke servere: `mcp__playwright__*`, `mcp__codewire__*` |

## False-positive-listen (kendte sikre brede rules)

Disse er forventede og bør ikke flagges som høj risiko:

| Regel | Hvorfor det er OK |
|---|---|
| `Bash(echo:*)` | echo har ingen side-effekter |
| `Bash(ls:*)`, `Bash(pwd)`, `Bash(cd:*)` | read-only navigation |
| `Bash(cat:*)`, `Bash(head:*)`, `Bash(tail:*)` | read-only fil-inspektion |
| `Read(*)` | Read-tool er per design read-only |
| `Glob(*)`, `Grep(*)` | Search-tools, read-only |
| `WebFetch(https://docs.claude.com/*)` | Officielle docs, narrow scope |

Disse hardcodes som info-niveau (5 point) i stedet for at flagges som finding.
