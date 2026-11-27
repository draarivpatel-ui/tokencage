# Contributing to tokencage

Thank you for helping improve tokencage. This project is a security library, so correctness and restraint matter more than cleverness.

## Ground rules

- Keep runtime dependencies at zero.
- Support Node.js 18 and newer.
- Keep the ESM source in `src/index.mjs` as the single source of truth.
- Never commit a real token, pepper, password, cookie or private key.
- Do not weaken entropy floors, pepper checks, checksum validation, constant-time comparisons or expiry checks to make a test pass.
- Do not add wildcard scope semantics. Scope matching is exact by design.

## Development setup

The repository has no runtime or development dependencies. Use Node.js 18 or newer.

```sh
npm test
node scripts/build-cjs.mjs --check
npm run smoke
npm pack --dry-run
```

When `src/index.mjs` changes, regenerate the CommonJS build:

```sh
node scripts/build-cjs.mjs
```

## Test expectations

Add regression tests for every behavior change. Tests live in `tests/*.test.mjs` and use `node:test`. Security-sensitive changes should include adversarial cases, not only happy paths.

Useful test areas include:

- malformed and oversized input
- checksum mutation and truncation
- weak peppers and weak entropy configuration
- retired-key rotation and unknown versions
- expiry, revocation, clock skew and exact scope matching
- duplicate or malformed HTTP headers
- redaction through `String`, JSON and `util.inspect`
- ESM and CommonJS parity

## Pull requests

Keep a pull request focused. Explain the threat model impact of security changes. If a change affects wire format, hash format, record format or CLI output, call it out clearly as a compatibility concern.

Before opening a pull request, run the four verification commands above and include the results in the description.

## Security reports

Do not open a public issue for a vulnerability. Follow `SECURITY.md`.
