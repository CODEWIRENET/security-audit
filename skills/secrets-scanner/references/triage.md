# Triage: placeholder vs ægte secret

Når et regex matcher, eller et entropy-spike findes, er næste spørgsmål: **er det faktisk
en secret, eller er det en demonstration/placeholder/test-værdi?**

Triage gør forskel på `FAIL` (operation blokeres) og `WARN` (manuel review). For aggressiv =
falske blokeringer. For slap = lækkede credentials.

## Placeholder-signaler (nedjustér severity)

### Token-baserede placeholders

Strengen indeholder en af disse litterale strenge (case-insensitive):

```
REPLACE_ME              CHANGE_ME             FIXME
YOUR_KEY                YOUR_SECRET           YOUR_TOKEN
YOUR_API_KEY            <your-                <api-key>
xxxxxxxx                XXXXXXXX              ********
0000000000              1234567890            placeholder
example                 sample                template
TODO                    REDACTED              REDACTED-FOR-DEMO
```

### Prefix-baserede placeholders

Strengen starter med (case-insensitive):

- `test_` — typisk test-mode credential
- `fake_`
- `dummy_`
- `mock_`
- `example_`
- `sample_`

### Kendte offentlige test-tokens

Disse er **publicerede** af leverandørerne og er ikke hemmelige:

| Token | Provider | Bemærkning |
|---|---|---|
| `AKIAIOSFODNN7EXAMPLE` | AWS | Docs example, hard-coded i AWS' egen dokumentation |
| `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | AWS | Docs example secret |
| `sk_test_*` (Stripe) | Stripe | Test-mode er offentligt tilgængelige test-keys |
| `pk_test_*` (Stripe) | Stripe | Test-mode publishable |
| `whsec_test_*` | Stripe | Test webhook |
| `eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U` | JWT.io | Default demo JWT |

Match mod en af disse → severity `info`, ikke en finding der tæller mod risk score.

## Filsti-baserede signaler

Hvis fil-stien indeholder en af disse fragmenter, nedjustér severity ét trin:

```
/test/          /tests/         /__tests__/
/fixtures/      /samples/       /examples/
/docs/          /documentation/ /examples/
.example.       .sample.        .template.
.test.          .mock.
```

**Bemærk**: bare fordi en fil er i `tests/` betyder det IKKE at indholdet er sikkert at
committe — udvikleren kunne have hardcodet en ægte test-bruger's credentials. Nedjustér,
men nedjustér ikke til 0.

## Kontekst-baserede signaler

Læs konteksten omkring match'en (±3 linjer):

### Komment der explicit siger "example" / "demo"

```python
# Example only — replace before deploying
api_key = "sk_live_xxxxxxxxxxxxxxx"
```

→ severity nedjusteret. Men hvis nøglen *ser ud som* et ægte tegnsæt: WARN, ikke skip.

### String literal der er en del af en URL/test-input

```javascript
const exampleResponse = {
  body: { token: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
};
```

→ hvis hele værdien matcher den litterale fra "kendte placeholders"-tabellen, skip.

### Variable-deklaration vs string concatenation

```javascript
// Sandsynligvis ægte:
const STRIPE_KEY = "sk_live_AbCdE...";

// Sandsynligvis test/fixture:
expect(response.body.token).toBe("sk_test_dummy");
```

Test-frameworks (`expect`, `assert`, `it(`, `describe(`, `test(`) tæt på match'en →
nedjustér ét trin.

## Hvornår ikke at nedjustere

Selv hvis flere placeholder-signaler matcher, **lad være med at nedjustere til 0** hvis:

- Match'en er en private key block (`-----BEGIN ... PRIVATE KEY-----`).
- Match'en er en connection string med en host der ikke er localhost.
- Filen er trackede i `.git/` (ikke ignored) OG har en `.production.` eller `.prod.` i
  filnavnet.
- `git log` viser at filen er pushed til en remote (ikke kun lokal).

Disse situationer er hvor placeholders typisk er ægte credentials der bare *ligner*
placeholders.

## Whitelist anbefaling

Hvis brugeren rapporterer at en specifik finding er en falsk positiv:

1. Verificér selv at det faktisk er en placeholder (læs konteksten).
2. Hvis bekræftet: foreslå brugeren at tilføje filen ELLER det specifikke pattern til
   `~/.<name>/secrets-scanner/whitelist.json`.
3. Tilføj **aldrig** automatisk. Hvidlistning skal være en bevidst handling.
4. Foretræk filsti-whitelisting over pattern-whitelisting (mere granular). Kun når
   samme pattern optræder i mange filer (f.eks. en delt mock-konstant) skal du foreslå
   pattern-whitelist.

## Edge cases

### Krypterede filer

Hvis filen ser ud til at være krypteret (`.gpg`, `.enc`, høj entropi i hele filen):
markér som `info` finding "encrypted file detected, manual review recommended".
Krypterede filer kan committes safely hvis nøglen ikke er i samme repo.

### Binary blobs

PNG/JPEG/PDF-headers detekteres → skip secret-scan på filen, men flag i rapport hvis
filnavnet er sensitivt (kan være en `.pem` med billede-extension som obfuskeringstrick).

### Code in markdown

```markdown
\`\`\`bash
export API_KEY=sk-real-key-here
\`\`\`
```

Code blocks i `.md` filer skal scannes. README'er er en hyppig kilde til lækkede keys.
