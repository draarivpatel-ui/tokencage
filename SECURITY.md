# Security policy

tokencage handles bearer secrets. Please report vulnerabilities privately and give the maintainer a reasonable opportunity to fix them before public disclosure.

## Reporting

Open a private GitHub security advisory for `draarivpatel-ui/tokencage` when advisory creation is enabled. If that path is unavailable, open a minimal public issue that says only that you need a private security contact. Do not include a proof of concept, token material, exploit steps or sensitive logs in a public issue.

Include in a private report:

- the affected version and commit
- the security impact
- a minimal reproduction
- whether the issue affects generation, parsing, hashing, rotation, records, redaction or the CLI
- any suggested coordinated disclosure timeline

## Scope

In scope:

- disclosure of token secret bytes through errors, logs, inspection output or redaction helpers
- biased token generation or failure to use `node:crypto` randomness
- checksum bypass in a way that accepts malformed tokens as valid
- non-constant-time secret comparison that depends on secret content
- pepper rotation accepting an unknown or wrong version
- prototype pollution, wildcard scope confusion or authorization bypass in record verification
- header extraction that accepts CRLF, duplicated credentials or embedded whitespace as one credential
- CLI output that leaks a submitted token or configured pepper

Out of scope:

- the fact that CRC32 is not cryptographic, which is documented design
- use of a fast HMAC for high-entropy tokens, which is documented design
- denial of service requiring input already above documented length bounds
- attacker control of the server's clock
- loss of a production pepper or database

## Cryptographic inventory

- Token generation: `crypto.randomBytes` with rejection sampling for unbiased base62 characters
- Format checksum: CRC32, used only for accidental corruption detection
- High-entropy token storage: HMAC-SHA256 with a server-side pepper
- Short human-typed secret storage: scrypt with random 16-byte salts and a hardened parameter floor
- Verification comparison: `crypto.timingSafeEqual` for equal-length byte strings

## Supported versions

Security fixes apply to the latest 1.x release until the project documents otherwise.
