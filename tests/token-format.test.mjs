import test from 'node:test';
import assert from 'node:assert/strict';
import { esm, mint, flipChar } from './helpers.mjs';

const {
  generateToken,
  generateTokenDetails,
  inspectToken,
  isValidTokenFormat,
  validatePrefix,
  validateKeyId,
  TokenCageError,
  CODE
} = esm;

test('generateToken returns a string for a minimal valid configuration', () => {
  const token = generateToken({ prefix: 'ab' });
  assert.equal(typeof token, 'string');
  assert.equal(token.startsWith('ab_'), true);
});

test('generateTokenDetails returns deterministic metadata shape', () => {
  const details = mint();
  assert.equal(details.prefix, 'testapp');
  assert.equal(details.hasKeyId, true);
  assert.equal(typeof details.keyId, 'string');
  assert.equal(details.bytes, 32);
  assert.equal(details.secretLength, 43);
  assert.equal(details.entropyBits, 256);
  assert.equal(details.format, 'tokencage-v1');
  assert.equal(Array.isArray(details.warnings), true);
  assert.equal(Object.isFrozen(details), true);
});

test('generated key id is exactly ten canonical base62 characters', () => {
  const details = mint();
  assert.match(details.keyId, /^[0-9A-Za-z]{10}$/);
  assert.match(details.keyId, /[A-Z]/);
  assert.equal(validateKeyId(details.keyId).valid, true);
});

test('generated token without key id has one separator after the prefix', () => {
  const details = generateTokenDetails({ prefix: 'testapp' });
  assert.equal(details.hasKeyId, false);
  assert.equal(details.keyId, null);
  assert.equal(details.token.startsWith('testapp_'), true);
  assert.equal(details.token.split('_').length, 2);
});

test('generated token with key id has the key id between two separators', () => {
  const details = mint();
  const parts = details.token.split('_');
  assert.equal(parts.length, 3);
  assert.equal(parts[0], 'testapp');
  assert.equal(parts[1], details.keyId);
});

for (const bytes of [16, 17, 24, 32, 48, 64]) {
  test('byte budget ' + bytes + ' produces a valid token at the expected entropy floor', () => {
    const details = generateTokenDetails({ prefix: 'testapp', bytes });
    assert.equal(details.bytes, bytes);
    assert.equal(details.entropyBits >= bytes * 8, true);
    assert.equal(inspectToken(details.token).valid, true);
  });
}

for (const bytes of [0, 1, 8, 15]) {
  test('byte budget ' + bytes + ' is rejected as below the 128 bit floor', () => {
    assert.throws(() => generateToken({ prefix: 'testapp', bytes }), (error) => {
      assert.equal(error instanceof TokenCageError, true);
      assert.equal(error.code, CODE.WEAK_ENTROPY);
      return true;
    });
  });
}

for (const bytes of [-1, 16.5, Number.NaN, Infinity, '32', 65, 1000]) {
  test('invalid byte budget ' + String(bytes) + ' is rejected at configuration time', () => {
    assert.throws(() => generateToken({ prefix: 'testapp', bytes }), TokenCageError);
  });
}

for (const prefix of ['ab', 'a1', 'a_b', 'service_api', 'a' + 'x'.repeat(23), 'z9_8y']) {
  test('valid prefix accepted: ' + prefix, () => {
    const result = validatePrefix(prefix);
    assert.equal(result.valid, true);
    assert.equal(result.vendorLike, false);
    assert.equal(generateToken({ prefix }).startsWith(prefix + '_'), true);
  });
}

const invalidPrefixes = [
  '', 'a', '1ab', '_ab', 'Ab', 'aB', 'a-b', 'a b', 'a\tb', 'ab_', 'a__b',
  'a' + 'x'.repeat(24), 'éb', 'aé', 'a\nb', 'a\rb', 'a\0b', 'a.b', 'a/b', 'a$b'
];
for (const prefix of invalidPrefixes) {
  test('invalid prefix rejected: ' + JSON.stringify(prefix), () => {
    const result = validatePrefix(prefix);
    assert.equal(result.valid, false);
    assert.throws(() => generateToken({ prefix }), TokenCageError);
  });
}

for (const value of [undefined, null, 1, true, [], {}, Buffer.from('ab')]) {
  test('non-string prefix input is rejected: ' + String(value), () => {
    assert.equal(validatePrefix(value).valid, false);
    assert.throws(() => generateToken({ prefix: value }), TokenCageError);
  });
}

for (const prefix of ['ghp', 'gho', 'sk_live', 'akia', 'xoxb', 'aiza', 'npm', 'pypi', 'npm_test', 'ghp_test', 'sk_live_test']) {
  test('vendor-like prefix rejected by default: ' + prefix, () => {
    const result = validatePrefix(prefix);
    assert.equal(result.valid, false);
    assert.equal(result.vendorLike, true);
    assert.throws(() => generateToken({ prefix }), (error) => error.code === CODE.VENDOR_PREFIX);
  });
}

for (const prefix of ['ghp', 'npm_test', 'sk_live_test']) {
  test('vendor-like prefix requires explicit override and carries a warning: ' + prefix, () => {
    const result = validatePrefix(prefix, { allowVendorLikePrefix: true });
    assert.equal(result.valid, true);
    assert.equal(result.warnings.length > 0, true);
    const details = generateTokenDetails({ prefix, allowVendorLikePrefix: true });
    assert.equal(details.warnings.length > 0, true);
    assert.equal(inspectToken(details.token, { allowVendorLikePrefix: true }).valid, true);
    assert.equal(inspectToken(details.token).valid, false);
  });
}

for (const prefix of ['npmd', 'ghpa', 'xoxbot', 'aizaz', 'pypiware']) {
  test('prefix that does not recreate a vendor token shape is allowed: ' + prefix, () => {
    assert.equal(validatePrefix(prefix).valid, true);
  });
}

for (const keyId of ['A123456789', 'zA34567890', 'ZZZZZZZZZZ', '0aBcdEfgh1']) {
  test('canonical key id accepted: ' + keyId, () => {
    assert.equal(validateKeyId(keyId).valid, true);
  });
}

for (const keyId of ['', 'a', '123456789', 'abcdefghij', '0123456789', 'A12345678', 'A1234567890', 'A12345678!', 'A12345678_', null, undefined, 123]) {
  test('non-canonical key id rejected: ' + String(keyId), () => {
    assert.equal(validateKeyId(keyId).valid, false);
  });
}

test('inspectToken validates a generated key id token', () => {
  const details = mint();
  const inspection = inspectToken(details.token);
  assert.equal(inspection.valid, true);
  assert.equal(inspection.prefix, 'testapp');
  assert.equal(inspection.keyId, details.keyId);
  assert.equal(inspection.hasKeyId, true);
  assert.equal(inspection.secretLength, details.secretLength);
  assert.equal(inspection.entropyBits, details.entropyBits);
});

test('inspectToken validates a generated token without key id', () => {
  const details = generateTokenDetails({ prefix: 'testapp' });
  const inspection = inspectToken(details.token);
  assert.equal(inspection.valid, true);
  assert.equal(inspection.prefix, 'testapp');
  assert.equal(inspection.keyId, null);
  assert.equal(inspection.hasKeyId, false);
});

test('inspectToken enforces an expected prefix', () => {
  const token = mint().token;
  assert.equal(inspectToken(token, { prefix: 'testapp' }).valid, true);
  const wrong = inspectToken(token, { prefix: 'other' });
  assert.equal(wrong.valid, false);
  assert.equal(wrong.code, 'prefix-mismatch');
});

test('inspectToken enforces key id expectation true', () => {
  const withoutKey = generateToken({ prefix: 'testapp' });
  const result = inspectToken(withoutKey, { keyId: true });
  assert.equal(result.valid, false);
  assert.equal(result.code, 'key-id-missing');
});

test('inspectToken enforces key id expectation false', () => {
  const withKey = mint().token;
  const result = inspectToken(withKey, { keyId: false });
  assert.equal(result.valid, false);
  assert.equal(result.code, 'key-id-unexpected');
});

test('isValidTokenFormat returns boolean rather than throwing for malformed input', () => {
  assert.equal(isValidTokenFormat(mint().token), true);
  for (const value of [null, undefined, 1, false, {}, [], '']) {
    assert.equal(isValidTokenFormat(value), false);
  }
});

for (const value of [null, undefined, 0, false, {}, [], Buffer.from('x')]) {
  test('inspectToken safely rejects non-string input: ' + String(value), () => {
    const result = inspectToken(value);
    assert.equal(result.valid, false);
    assert.equal(result.code, 'invalid-type');
    assert.equal(result.redacted, '[REDACTED]');
  });
}

test('inspectToken never includes the raw token in its JSON output', () => {
  const details = mint();
  const output = JSON.stringify(inspectToken(details.token));
  assert.equal(output.includes(details.token), false);
  assert.equal(output.includes('"secret":'), false);
});

test('inspectToken reports token length without exposing secret content', () => {
  const details = mint();
  const inspection = inspectToken(details.token);
  assert.equal(inspection.length, details.token.length);
  assert.equal(Object.hasOwn(inspection, 'secret'), false);
  assert.equal(Object.hasOwn(inspection, 'token'), false);
});

test('a single secret character mutation is detected', () => {
  const details = mint();
  const bodyStart = details.token.lastIndexOf('_') + 1;
  const mutated = flipChar(details.token, bodyStart + 4);
  const inspection = inspectToken(mutated);
  assert.equal(inspection.valid, false);
  assert.equal(inspection.code, 'checksum-mismatch');
});

test('a single checksum character mutation is detected', () => {
  const details = mint();
  const mutated = flipChar(details.token, details.token.length - 1);
  const inspection = inspectToken(mutated);
  assert.equal(inspection.valid, false);
  assert.equal(inspection.code, 'checksum-mismatch');
});

test('a single prefix character mutation is detected', () => {
  const details = mint();
  const mutated = flipChar(details.token, 2);
  const inspection = inspectToken(mutated);
  assert.equal(inspection.valid, false);
});

test('a single key id character mutation is detected', () => {
  const details = mint();
  const keyIndex = details.token.indexOf(details.keyId) + 2;
  const mutated = flipChar(details.token, keyIndex);
  const inspection = inspectToken(mutated);
  assert.equal(inspection.valid, false);
});

test('adjacent secret character transposition is detected', () => {
  const details = mint();
  const bodyStart = details.token.lastIndexOf('_') + 1;
  let index = bodyStart;
  while (details.token[index] === details.token[index + 1]) index += 1;
  const mutated = details.token.slice(0, index) + details.token[index + 1] + details.token[index] + details.token.slice(index + 2);
  assert.equal(inspectToken(mutated).valid, false);
});

test('truncating the checksum is detected as invalid shape', () => {
  const details = mint();
  const truncated = details.token.slice(0, -1);
  assert.equal(inspectToken(truncated).valid, false);
});

test('truncating half the token is detected', () => {
  const details = mint();
  const truncated = details.token.slice(0, Math.floor(details.token.length / 2));
  assert.equal(inspectToken(truncated).valid, false);
});

test('appending one base62 character invalidates the token shape or checksum', () => {
  const details = mint();
  assert.equal(inspectToken(details.token + '0').valid, false);
});

test('removing the body separator invalidates the token', () => {
  const details = mint();
  const bodyStart = details.token.lastIndexOf('_');
  const mutated = details.token.slice(0, bodyStart) + details.token.slice(bodyStart + 1);
  assert.equal(inspectToken(mutated).valid, false);
});

for (const [label, mutate] of [
  ['space', (token) => token.slice(0, 5) + ' ' + token.slice(6)],
  ['tab', (token) => token.slice(0, 5) + '\t' + token.slice(6)],
  ['newline', (token) => token.slice(0, 5) + '\n' + token.slice(6)],
  ['carriage return', (token) => token.slice(0, 5) + '\r' + token.slice(6)],
  ['non ascii', (token) => token.slice(0, 5) + 'é' + token.slice(6)],
  ['delete control', (token) => token.slice(0, 5) + '\x7f' + token.slice(6)]
]) {
  test('token containing ' + label + ' is rejected before checksum verification', () => {
    const result = inspectToken(mutate(mint().token));
    assert.equal(result.valid, false);
    assert.equal(result.code, 'invalid-character');
  });
}

for (const bodyChar of ['-', '+', '/', '=', '!', '.', '~']) {
  test('non-base62 body character ' + bodyChar + ' is rejected', () => {
    const details = mint();
    const bodyStart = details.token.lastIndexOf('_') + 1;
    const mutated = details.token.slice(0, bodyStart + 3) + bodyChar + details.token.slice(bodyStart + 4);
    assert.equal(inspectToken(mutated).valid, false);
  });
}

test('maximum length bound rejects an otherwise valid token', () => {
  const details = mint();
  const result = inspectToken(details.token, { maxLength: details.token.length - 1 });
  assert.equal(result.valid, false);
  assert.equal(result.code, 'too-long');
});

test('maximum length bound accepts a token at exactly the bound', () => {
  const details = mint();
  const result = inspectToken(details.token, { maxLength: details.token.length });
  assert.equal(result.valid, true);
});

for (const maxLength of [0, 1, 30, 1025, 16.5, '256']) {
  test('invalid inspection maxLength rejected: ' + String(maxLength), () => {
    assert.throws(() => inspectToken(mint().token, { maxLength }), TokenCageError);
  });
}

for (const options of [
  { unknown: true },
  { prefix: 1 },
  { keyId: 'yes' },
  { maxLength: 256, extra: true },
  null,
  []
]) {
  test('invalid inspection options are rejected: ' + JSON.stringify(options), () => {
    assert.throws(() => inspectToken(mint().token, options), TokenCageError);
  });
}

for (const options of [
  { prefix: 'testapp', unknown: true },
  { prefix: 'testapp', bytes: 32, extra: true }
]) {
  test('invalid generation options are rejected: ' + JSON.stringify(options), () => {
    assert.throws(() => generateToken(options), TokenCageError);
  });
}

for (const options of [null, [], 'testapp']) {
  test('non-object generation options are rejected: ' + String(options), () => {
    assert.throws(() => generateToken(options), TokenCageError);
  });
}

test('generated details redaction does not expose the full secret', () => {
  const details = mint();
  assert.notEqual(details.redacted, details.token);
  assert.equal(details.redacted.includes('...'), true);
  assert.equal(details.token.includes(details.redacted), false);
});

test('keyed and unkeyed tokens are distinct canonical shapes', () => {
  const keyed = mint();
  const unkeyed = generateTokenDetails({ prefix: 'testapp', keyId: false });
  assert.notEqual(keyed.token, unkeyed.token);
  assert.equal(inspectToken(keyed.token, { keyId: true }).valid, true);
  assert.equal(inspectToken(unkeyed.token, { keyId: false }).valid, true);
});

test('token shape boundaries are enforced for tiny and giant bodies', () => {
  const valid = mint().token;
  const bodyStart = valid.lastIndexOf('_') + 1;
  const tiny = valid.slice(0, bodyStart) + '0'.repeat(10);
  const giant = valid.slice(0, bodyStart) + '0'.repeat(200);
  assert.equal(inspectToken(tiny).valid, false);
  assert.equal(inspectToken(giant).valid, false);
});

test('empty token is invalid rather than throwing', () => {
  const result = inspectToken('');
  assert.equal(result.valid, false);
  assert.equal(result.code, 'invalid-shape');
});

test('token without separator is invalid shape', () => {
  assert.equal(inspectToken('abcdefghijklmnopqrstuvwxyz').valid, false);
});

test('token ending at the separator is invalid shape', () => {
  assert.equal(inspectToken('testapp_').valid, false);
});

test('token starting at the separator is invalid shape', () => {
  assert.equal(inspectToken('_abcdefghijklmnopqrstuvwxyz123456').valid, false);
});

test('inspection warnings are copied rather than shared mutable state', () => {
  const details = generateTokenDetails({ prefix: 'npm', allowVendorLikePrefix: true });
  const first = inspectToken(details.token, { allowVendorLikePrefix: true });
  first.warnings.push('mutated');
  const second = inspectToken(details.token, { allowVendorLikePrefix: true });
  assert.equal(second.warnings.includes('mutated'), false);
});
