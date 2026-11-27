# tokencage

Zero-dependency Node.js tools for structured opaque tokens: prefixed API keys, session tokens and short magic-link codes.

tokencage generates high-entropy bearer tokens, detects accidental corruption offline with a checksum, hashes token material for at-rest storage, supports zero-downtime pepper rotation, binds verification to expiry and scopes, and redacts secrets safely for logs.

## Status

This repository is prepared for its first npm release. It is versioned as `1.0.0`, but this README does not claim that the package has already been published. After release, installation will be:

```sh
npm install tokencage
```

Until then, run it from a source checkout.

## Why this exists

Plain random tokens work, but production token handling usually grows the same fragile pieces by hand:

- a recognizable prefix for operators and secret-scanning hygiene
- a checksum so typos and truncation fail before a database lookup
- a public key id so token lookup does not require scanning every stored hash
- a keyed hash for high-entropy tokens instead of fast unsalted SHA-256
- scrypt for short human-typed codes instead of treating them like high-entropy keys
- key rotation without forcing every user or client to rotate at once
- expiry, revocation and exact scope checks that fail closed
- logging redaction that does not accidentally stringify into a secret

tokencage implements those pieces with no runtime dependencies.

## Threat model

In scope:

- accidental token corruption, truncation and transcription mistakes
- offline rejection before a database lookup or password hashing operation
- database disclosure of stored token hashes
- pepper rotation after a planned key change or suspected pepper exposure
- accidental logging or JSON serialization of token values
- malformed, duplicated, oversized or control-character-bearing credential headers
- authorization checks that must reject missing scopes, expiry and revocation

Out of scope:

- protecting a token after the token itself is disclosed
- replacing transport security. Always use TLS
- replacing a database. Expiry, revocation, key id uniqueness and audit state must be stored by the caller
- encryption. Tokens are opaque random secrets, not encrypted payloads
- JWT use cases. tokencage tokens carry no claims
- cryptographic error detection. CRC32 is only an accident detector, not authentication
- rate limiting. Use a reverse proxy or application limiter for online guessing attacks

## Token format

Canonical generated tokens use base62 characters only:

```text
<prefix>_<secret><checksum>
<prefix>_<keyId>_<secret><checksum>
```

Examples of shape, using shortened placeholders rather than valid tokens:

```text
acme_4xQa...
acme_K8qR2xYza1_4xQa...
```

Rules:

- `prefix` is lowercase ASCII matching `[a-z][a-z0-9_]{1,23}`
- a prefix cannot end in `_` or contain `__`
- `keyId` is exactly 10 base62 characters and canonical generated key ids include an uppercase letter
- `secret` is unbiased base62 generated with `crypto.randomBytes` and rejection sampling
- `checksum` is a six-character base62 encoding of CRC32
- default entropy is 256 bits; the enforced floor is 128 bits
- the checksum payload binds the prefix, key id mode and secret using separators that cannot appear in the token

Base62 is deliberate. Base64url includes `_`, which is also the visible field separator in this format. Choosing one unambiguous alphabet keeps parsing simple and avoids separator confusion.

The checksum is not a security boundary. Anyone can compute CRC32. Its job is to reject accidents before they reach a lookup or KDF. Authentication comes from entropy, TLS, at-rest hashing and server-side verification.

## Prefix collision guard

Prefixes identical or structurally similar to well-known vendor token prefixes are rejected by default. The built-in guard covers vendor families represented by `ghp`, `gho`, `sk_live`, `AKIA`, `xoxb`, `AIza`, `npm` and `pypi` after lowercase validation. This reduces the chance that a test token is treated as a real third-party credential by an external scanner.

If you have a deliberate compatibility reason, `allowVendorLikePrefix: true` permits the prefix and returns a warning in generation metadata. Prefer a distinct application prefix.

## Quick start

```js
import crypto from 'node:crypto';
import {
  createTokenCage,
  createTokenRecord,
  verifyTokenRecord
} from 'tokencage';

const pepper = crypto.randomBytes(32).toString('base64url');

const cage = createTokenCage({
  prefix: 'acme',
  keyId: true,
  pepper,
  version: 'v1'
});

const minted = cage.generate();
console.log(minted.token);
console.log(minted.redacted);

const record = cage.createRecord(minted.token, {
  scopes: ['read:reports'],
  ttlMs: 30 * 24 * 60 * 60 * 1000
});

storeRecordByKeyId(record.keyId, record);

const result = cage.verifyRecord(presentedToken, storedRecord, {
  requiredScopes: ['read:reports']
});

if (!result.valid) deny();
if (result.needsRehash) storeHash(record.keyId, result.nextHash);
```

Store pepper material in a secret manager in production. A pepper passed as a string is treated as exactly those UTF-8 bytes; hex-looking strings are not decoded automatically.

## Generation and inspection

```js
import { generateTokenDetails, inspectToken, isValidTokenFormat } from 'tokencage';

const details = generateTokenDetails({
  prefix: 'acme',
  bytes: 32,
  keyId: true
});

const inspection = inspectToken(details.token, {
  prefix: 'acme',
  keyId: true
});

if (!inspection.valid) {
  console.log(inspection.code);
  console.log(inspection.redacted);
}

const ok = isValidTokenFormat(details.token);
```

`inspectToken` never returns the raw token or secret. It returns metadata such as validity, failure code, prefix, key id, estimated entropy, safe redaction and warnings.

`bytes` means the minimum byte entropy budget. The default is 32 bytes, the floor is 16 bytes and the ceiling is 64 bytes. Rejection sampling avoids modulo bias rather than mapping random bytes with `% 62` directly.

## At-rest hashing

### High-entropy API keys and session tokens

Use peppered HMAC-SHA256. High-entropy tokens do not need a password-stretching KDF because they are not human-chosen. HMAC with a server-side pepper keeps offline guessing impractical even if the database leaks but the pepper does not.

```js
import { hashToken, verifyTokenHash } from 'tokencage';

const encoded = hashToken(token, {
  algorithm: 'hmac-sha256',
  pepper: process.env.TOKEN_PEPPER,
  version: 'v1'
});

const valid = verifyTokenHash(token, encoded, {
  pepper: process.env.TOKEN_PEPPER,
  version: 'v1'
});
```

The self-describing record is:

```text
tc1$hmac-sha256$v1$<base64url digest>
```

Peppers must be at least 32 bytes, at most 256 bytes, and pass lightweight regularity checks. Those checks reject common mistakes such as repeated strings, short strings and highly sequential values. They cannot prove that a pepper was generated randomly. Generate one with a CSPRNG and store it in a secret manager.

### Short human-typed codes and magic-link codes

Use scrypt for short values such as six-digit one-time codes:

```js
const encoded = hashToken('492810', { algorithm: 'scrypt' });
const valid = verifyTokenHash('492810', encoded);
```

The self-describing record is:

```text
tc1$scrypt$N=16384,r=8,p=1$<base64url salt>$<base64url derived key>
```

The floor is `N=16384`, `r=8`, `p=1`, with a random 16-byte salt and a 32-byte derived key. Parameters above the floor are accepted within a bounded memory ceiling. Async variants are available as `hashTokenAsync` and `verifyTokenHashAsync`.

A short code still needs expiry, single-use consumption and rate limiting. scrypt slows guessing; it does not make an unlimited online guesser safe.

## Zero-downtime rotation

```js
import { createTokenVerifier } from 'tokencage';

const verifier = createTokenVerifier({
  currentVersion: 'v2',
  peppers: {
    v2: process.env.TOKEN_PEPPER_V2,
    v1: process.env.TOKEN_PEPPER_V1
  }
});

const result = verifier.verifyAndRotate(token, storedHash);

if (!result.valid) deny();
if (result.needsRehash) {
  atomicallyStoreNextHash(result.keyId, result.nextHash);
}
```

The stored hash carries the pepper version that created it. Verification uses that version. When it matches a retired pepper, the result is valid and includes:

- `needsRehash: true`
- `nextHash` computed with the current pepper
- `keyId` and `prefix` when the token uses tokencage format

Only store `nextHash` after the presented token verifies. Do not overwrite a stored hash for an unverified request. Use a database uniqueness constraint or compare-and-swap operation where your database offers one.

## Scoped and expiring records

`createTokenRecord` creates a JSON-serializable record that contains a hash and metadata, never the raw token:

```js
const record = createTokenRecord(token, {
  pepper,
  version: 'v1',
  scopes: ['read:reports', 'write:reports'],
  ttlMs: 60 * 60 * 1000
});
```

`verifyTokenRecord` is pure and fail-closed. It does not mutate or update the record. It returns:

```js
{
  valid,
  reason,
  code,
  needsRehash,
  nextHash,
  keyId,
  prefix,
  record
}
```

Verification covers:

- record shape and schema version
- revocation
- creation time and expiry with bounded clock-skew configuration
- exact required scopes
- tokencage token format when `requireFormat` is true
- HMAC rotation or scrypt verification

Scope matching is exact. There are no wildcards. A stored scope of `*` does not mean all scopes. Scope strings are lowercase ASCII with letters, digits, colon, dot, underscore and hyphen.

After a valid verification, the caller decides whether to update `lastUsedAt`, store `nextHash`, consume a one-time code or write an audit event.

## Redaction and safe serialization

```js
import { TokenValue, redactToken } from 'tokencage';

console.log(redactToken(token));

const wrapped = new TokenValue(token);
console.log(String(wrapped));
console.log(JSON.stringify({ credential: wrapped }));
console.log(wrapped.reveal());
```

Valid generated tokens render in a form similar to:

```text
acme_K8qR2xYza1_...w9xY
```

Short, malformed or invalid values render as `[REDACTED]`. `TokenValue` implements safe `toString`, `toJSON`, `valueOf` and the Node.js custom inspect symbol. The raw value is available only through the explicit `reveal()` method.

Redaction is a leak-reduction control, not a substitute for log policy. The final four characters remain sensitive in aggregate and should not be treated as public data.

## HTTP credential extraction

```js
import { extractBearerToken, extractApiKeyHeader } from 'tokencage';

const bearer = extractBearerToken(req.headers);
const apiKey = extractApiKeyHeader(req.headers);
const custom = extractApiKeyHeader(req.headers, { name: 'x-acme-key' });
```

The Bearer parser follows the RFC 6750 token68 character set. It rejects control characters, non-ASCII input, embedded whitespace, oversized values and duplicated credential headers. A missing header or a different authorization scheme returns `null`; malformed bearer syntax throws `TokenCageError`.

Header input may be a string, a case-insensitive object, a `Map`, a Headers-like object or a single-value array. Multiple credential headers fail closed.

## High-level API

`createTokenCage` combines prefix policy, generation shape and pepper rotation:

```js
const cage = createTokenCage({
  prefix: 'acme',
  bytes: 32,
  keyId: true,
  currentVersion: 'v2',
  peppers: {
    v2: pepperV2,
    v1: pepperV1
  }
});

const minted = cage.generate();
const encoded = cage.hash(minted.token);
const rotation = cage.verifyAndRotate(minted.token, encoded);
const record = cage.createRecord(minted.token, { scopes: ['read'] });
const check = cage.verifyRecord(minted.token, record);
```

A cage can be generation-only when no pepper is configured. Calling HMAC hash or rotation methods on such a cage throws a configuration error. A generation-only cage can still create and verify scrypt records when `algorithm: 'scrypt'` is selected explicitly.

## API summary

- `generateToken(options)` returns a token string
- `generateTokenDetails(options)` returns token plus safe metadata
- `inspectToken(token, options)` parses and validates format without exposing the secret
- `isValidTokenFormat(token, options)` returns a boolean
- `validatePrefix(prefix, options)` validates prefix policy
- `validateKeyId(keyId)` validates canonical key id shape
- `validatePepper(pepper)` reports strength validation without exposing the pepper
- `hashToken(token, options)` creates an HMAC or scrypt record
- `hashTokenAsync(token, options)` async equivalent
- `verifyTokenHash(token, encodedHash, options)` verifies an encoded hash
- `verifyTokenHashAsync(token, encodedHash, options)` async equivalent
- `createTokenVerifier(config)` creates a rotating HMAC verifier
- `verifyAndRotate(token, encodedHash, config)` one-shot rotation verification
- `createTokenRecord(token, options)` creates a storable record
- `verifyTokenRecord(token, record, options)` pure fail-closed record verification
- `hasScopes(recordScopes, requiredScopes)` exact scope helper
- `redactToken(token)` and `maskToken(token)` safe display strings
- `TokenValue` and `createTokenValue(token)` safe serialization wrapper
- `extractBearerToken(input, options)` strict Bearer extraction
- `extractApiKeyHeader(input, options)` strict API key header extraction
- `createTokenCage(config)` integrated high-level API

## CLI

```sh
tokencage generate --prefix acme --bytes 32 --key-id
tokencage generate --prefix acme --key-id --json
tokencage inspect <token> --prefix acme --key-id
tokencage inspect <token> --json
tokencage inspect <token> --show-prefix-only
tokencage lint-config --config tokencage.config.json
tokencage lint-config --config tokencage.config.json --json
```

`inspect` prints metadata and a redacted preview. It does not echo the submitted raw token. `--show-prefix-only` further limits output to the prefix for valid tokens.

`lint-config` audits prefix, entropy, key id, pepper, version and expiry configuration without printing configured pepper material.

Exit codes:

- `0`: success, or lint config has no errors
- `1`: invalid token, lint errors, read failure or operation failure
- `2`: command-line usage error

## Package format and compatibility

- Node.js 18 or newer
- ESM entry: `src/index.mjs`
- CommonJS entry: `dist/index.cjs`
- Types: `types/index.d.ts`
- Runtime dependencies: none
- Development dependencies: none
- Package side effects: none

The CommonJS build is generated deterministically from the ESM source by `scripts/build-cjs.mjs`. CI checks that the committed build is up to date.

## Operational checklist

1. Generate peppers with a CSPRNG and store them in a secret manager.
2. Use separate peppers for separate environments.
3. Use TLS for every token presentation.
4. Store only tokencage hashes, never raw tokens.
5. Enforce key id uniqueness in the database.
6. Rate-limit verification attempts, especially short codes.
7. Expire and consume magic-link codes after first use.
8. Keep clock skew small and explicit.
9. Write `nextHash` only after a valid verification.
10. Treat redacted values as sensitive diagnostic data, not public identifiers.

## Development

```sh
npm test
node scripts/build-cjs.mjs --check
npm run smoke
npm pack --dry-run
```

As of the 1.0.0 release, `npm test` reports 738 passing tests.

See `CONTRIBUTING.md` for contribution rules and `SECURITY.md` for vulnerability reporting.
