# Good first issues

These starter tasks are intentionally narrow. Each should include tests and documentation updates when behavior changes.

## 1. Add CLI round-trip examples to the README

Show one generate command, one inspect command and one lint-config command. Redact example secrets. Acceptance: commands copy cleanly into a terminal and output shape matches the README.

## 2. Add a deterministic checksum fixture suite

Add a small JSON-independent fixture table in tests for known prefix, key id and secret combinations. Acceptance: fixtures verify on ESM and CommonJS builds and at least one fixture detects a single-character mutation.

## 3. Improve lint-config unknown-key guidance

Make the CLI warning explain whether an unknown key is ignored or should be removed. Acceptance: text and JSON output remain machine stable, with tests for both.

## 4. Add a magic-link integration example

Create a short docs example showing a six-digit code hashed with scrypt, verified once, then deleted or consumed. Acceptance: no reusable code is logged and expiry is part of the example.

## 5. Add API key middleware examples

Document framework-neutral examples for reading `Authorization` and `X-API-Key`. Acceptance: examples show missing credentials, malformed credentials and fail-closed behavior without framework dependencies.

## 6. Expand statistical generation tests

Add a stronger but still non-flaky distribution check for base62 output. Acceptance: the test explains its bounds, uses enough samples to avoid routine flakiness and completes quickly.

## 7. Add rotation migration documentation

Write a runbook for introducing `v2`, retiring `v1` and storing `nextHash` exactly once. Acceptance: the runbook includes rollback behavior and warns against writing unverified hashes.

## 8. Add CLI input fuzz cases

Add table-driven CLI tests for oversized tokens, control characters, missing values, duplicate flags and malformed JSON configs. Acceptance: exit codes stay documented and stderr never echoes submitted secret material.

## 9. Add TypeScript consumer smoke tests

Create a small compiler-based fixture only if the project decides to accept a development-only TypeScript dependency. Until then, improve declaration inspection tests. Acceptance: every public function and result field is represented in `types/index.d.ts`.

## 10. Add timing regression guards

Add tests proving malformed length mismatches reject before comparison and equal-length digests use `crypto.timingSafeEqual` through observable behavior. Acceptance: tests do not claim nanosecond timing proof and remain stable on loaded CI machines.
