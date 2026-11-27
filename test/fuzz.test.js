import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import {
  generateTokenDetails,
  inspectToken,
  validatePrefix,
} from '../src/index.mjs';

const propertyOptions = { seed: 20261127, numRuns: 75 };
const byteBudget = fc.integer({ min: 16, max: 32 });

test('generated tokens satisfy the documented format and inspection contract', () => {
  fc.assert(
    fc.property(byteBudget, fc.boolean(), (bytes, useKeyId) => {
      const details = generateTokenDetails({ prefix: 'fuzzapp', bytes, keyId: useKeyId });
      const inspection = inspectToken(details.token);
      assert.equal(inspection.valid, true, inspection.reason);
      assert.equal(inspection.prefix, 'fuzzapp');
      assert.equal(inspection.hasKeyId, useKeyId);
      assert.equal(inspection.secretLength, details.secretLength);
      assert.notEqual(inspection.redacted, details.token);
    }),
    propertyOptions,
  );
});

test('single-character checksum mutations are rejected', () => {
  fc.assert(
    fc.property(byteBudget, fc.integer({ min: 0, max: 5 }), (bytes, offset) => {
      const token = generateTokenDetails({ prefix: 'fuzzapp', bytes }).token;
      const position = token.length - 1 - offset;
      const replacement = token[position] === 'A' ? 'B' : 'A';
      const mutated = `${token.slice(0, position)}${replacement}${token.slice(position + 1)}`;
      const inspection = inspectToken(mutated);
      assert.equal(inspection.valid, false, `${token} mutated at ${position}`);
      assert.equal(inspection.code, 'checksum-mismatch');
    }),
    propertyOptions,
  );
});

test('hostile control and whitespace-bearing token strings never validate', () => {
  const tokenish = fc.stringMatching(/^[A-Za-z0-9]{10,60}$/);
  const hostileCharacter = fc.constantFrom(' ', '\t', '\n', '\r', '\0', '\u202e');
  fc.assert(
    fc.property(tokenish, hostileCharacter, (body, character) => {
      const candidate = `fuzzapp_${body}${character}`;
      const inspection = inspectToken(candidate);
      assert.equal(inspection.valid, false);
      assert.equal(inspection.code, 'invalid-character');
    }),
    propertyOptions,
  );
});

test('vendor-shaped prefixes stay rejected without an explicit override', () => {
  fc.assert(
    fc.property(fc.constantFrom('ghp', 'sk_live', 'akia', 'xoxb'), (prefix) => {
      const result = validatePrefix(prefix);
      assert.equal(result.valid, false);
      assert.equal(result.code, 'vendor-prefix');
      assert.equal(result.vendorLike, true);
    }),
    propertyOptions,
  );
});
