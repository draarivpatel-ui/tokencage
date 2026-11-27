import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { esm, root, strongPepper, secondStrongPepper, mint } from './helpers.mjs';

const {
  hashToken,
  hashTokenAsync,
  verifyTokenHash,
  verifyTokenHashAsync,
  validatePepper,
  TokenCageError,
  CODE
} = esm;

const pepper = strongPepper();
const otherPepper = secondStrongPepper();
const token = mint().token;

test('validatePepper accepts a random base64url pepper string', () => {
  const result = validatePepper(pepper);
  assert.equal(result.valid, true, result.reason);
  assert.equal(result.lengthBytes >= 32, true);
});

test('validatePepper accepts random bytes', () => {
  const result = validatePepper(crypto.randomBytes(32));
  assert.equal(result.valid, true, result.reason);
});

for (const [label, value] of [
  ['empty string', ''],
  ['short string', 'x'.repeat(31)],
  ['one repeated character', 'a'.repeat(32)],
  ['repeated hexadecimal block', '0123456789abcdef'.repeat(4)],
  ['alphabet sequence', 'abcdefghijklmnopqrstuvwxyzabcdef'],
  ['low variety password repetition', 'passwordpasswordpasswordpassword'],
  ['null', null],
  ['number', 42],
  ['object', {}],
  ['overlong pepper', crypto.randomBytes(300)]
]) {
  test('weak or invalid pepper rejected: ' + label, () => {
    const result = validatePepper(value);
    assert.equal(result.valid, false);
    assert.throws(() => hashToken(token, { pepper: value }), (error) => {
      assert.equal(error instanceof TokenCageError, true);
      assert.equal(error.code, CODE.WEAK_PEPPER);
      return true;
    });
  });
}

test('pepper validation does not echo pepper material', () => {
  const weak = 'a'.repeat(32);
  const output = JSON.stringify(validatePepper(weak));
  assert.equal(output.includes(weak), false);
});

test('hmac hash has the documented self-describing shape', () => {
  const encoded = hashToken(token, { pepper, version: 'v1' });
  assert.match(encoded, /^tc1\$hmac-sha256\$v1\$[A-Za-z0-9\-_]{43}$/);
});

test('hmac hash is deterministic for the same token pepper and version', () => {
  const first = hashToken(token, { pepper, version: 'v1' });
  const second = hashToken(token, { pepper, version: 'v1' });
  assert.equal(first, second);
});

test('hmac hash changes when the token changes', () => {
  const first = hashToken(token, { pepper, version: 'v1' });
  const second = hashToken(mint().token, { pepper, version: 'v1' });
  assert.notEqual(first, second);
});

test('hmac hash changes when the pepper changes', () => {
  const first = hashToken(token, { pepper, version: 'v1' });
  const second = hashToken(token, { pepper: otherPepper, version: 'v1' });
  assert.notEqual(first, second);
});

test('hmac hash changes when the version changes', () => {
  const first = hashToken(token, { pepper, version: 'v1' });
  const second = hashToken(token, { pepper, version: 'v2' });
  assert.notEqual(first, second);
});

test('hmac verification accepts the correct token', () => {
  const encoded = hashToken(token, { pepper, version: 'v1' });
  assert.equal(verifyTokenHash(token, encoded, { pepper, version: 'v1' }), true);
});

test('hmac verification rejects a different token', () => {
  const encoded = hashToken(token, { pepper, version: 'v1' });
  assert.equal(verifyTokenHash(mint().token, encoded, { pepper, version: 'v1' }), false);
});

test('hmac verification rejects the wrong pepper', () => {
  const encoded = hashToken(token, { pepper, version: 'v1' });
  assert.equal(verifyTokenHash(token, encoded, { pepper: otherPepper, version: 'v1' }), false);
});

test('hmac verification accepts a matching retired version through the peppers map', () => {
  const encoded = hashToken(token, { pepper, version: 'v1' });
  assert.equal(verifyTokenHash(token, encoded, {
    peppers: { v2: otherPepper, v1: pepper },
    currentVersion: 'v2'
  }), true);
});

for (const version of ['v1', 'v2', '2026-11', 'key.one', 'rotated_key']) {
  test('safe version label accepted: ' + version, () => {
    assert.match(hashToken(token, { pepper, version }), new RegExp('\\$' + version.replace(/[.-]/g, '\\$&') + '\\$'));
  });
}

for (const version of ['', ' v1', 'v1 ', 'v$1', 'v/1', 'v\n1', 'v'.repeat(33), 1, null]) {
  test('unsafe version label rejected: ' + String(version), () => {
    assert.throws(() => hashToken(token, { pepper, version }), TokenCageError);
  });
}

for (const encoded of [
  '',
  'tc1',
  'tc1$hmac-sha256',
  'tc1$hmac-sha256$v1',
  'tc1$hmac-sha256$v1$',
  'tc0$hmac-sha256$v1$' + 'A'.repeat(43),
  'tc1$hmac-sha1$v1$' + 'A'.repeat(43),
  'tc1$hmac-sha256$v1$' + 'A'.repeat(42),
  'tc1$hmac-sha256$v1$' + 'A'.repeat(44),
  'tc1$hmac-sha256$v1$' + 'A'.repeat(42) + '=',
  'tc1$hmac-sha256$v1$' + 'A'.repeat(42) + '+',
  'tc1$hmac-sha256$v$1$' + 'A'.repeat(43),
  'tc1$hmac-sha256$v1$' + 'A'.repeat(43) + '$extra'
]) {
  test('malformed hmac encoded hash returns false: ' + encoded.slice(0, 42), () => {
    assert.equal(verifyTokenHash(token, encoded, { pepper, version: 'v1' }), false);
  });
}

for (const value of [null, undefined, '', 1, false, {}, []]) {
  test('verifyTokenHash rejects invalid token input without throwing: ' + String(value), () => {
    assert.equal(verifyTokenHash(value, 'tc1$hmac-sha256$v1$' + 'A'.repeat(43), { pepper }), false);
  });
}

test('hashToken rejects an empty token', () => {
  assert.throws(() => hashToken('', { pepper }), TokenCageError);
});

test('hashToken rejects non-string token input', () => {
  for (const value of [null, undefined, 1, false, {}, []]) {
    assert.throws(() => hashToken(value, { pepper }), TokenCageError);
  }
});

test('hashToken accepts token input at the documented length ceiling', () => {
  const encoded = hashToken('x'.repeat(4096), { pepper });
  assert.equal(verifyTokenHash('x'.repeat(4096), encoded, { pepper }), true);
});

test('hashToken rejects token input above the documented length ceiling', () => {
  assert.throws(() => hashToken('x'.repeat(4097), { pepper }), (error) => error.code === CODE.LIMIT_EXCEEDED);
  assert.equal(verifyTokenHash('x'.repeat(4097), 'tc1$hmac-sha256$v1$' + 'A'.repeat(43), { pepper }), false);
});

for (const options of [
  undefined,
  {},
  { version: 'v1' },
  { pepper, unknown: true },
  { pepper, algorithm: 'sha256' },
  { pepper, scrypt: {} },
  null,
  []
]) {
  test('invalid hmac hash options rejected: ' + JSON.stringify(options), () => {
    assert.throws(() => hashToken(token, options), TokenCageError);
  });
}

test('hmac comparison implementation uses timingSafeEqual', () => {
  const source = fs.readFileSync(path.join(root, 'src', 'index.mjs'), 'utf8');
  assert.equal(source.includes('crypto.timingSafeEqual'), true);
});

test('hmac encoded digest uses canonical unpadded base64url', () => {
  const encoded = hashToken(token, { pepper });
  const digest = encoded.split('$')[3];
  assert.equal(digest.includes('='), false);
  assert.equal(digest.includes('+'), false);
  assert.equal(digest.includes('/'), false);
  assert.equal(digest.length, 43);
});

test('hmac async hash matches sync hash for identical input', async () => {
  const sync = hashToken(token, { pepper, version: 'v1' });
  const asyncValue = await hashTokenAsync(token, { pepper, version: 'v1' });
  assert.equal(asyncValue, sync);
});

test('hmac async verification accepts correct token', async () => {
  const encoded = hashToken(token, { pepper });
  assert.equal(await verifyTokenHashAsync(token, encoded, { pepper }), true);
});

test('scrypt hash has the documented self-describing shape', () => {
  const encoded = hashToken('492810', { algorithm: 'scrypt' });
  assert.match(encoded, /^tc1\$scrypt\$N=16384,r=8,p=1\$[A-Za-z0-9\-_]{22}\$[A-Za-z0-9\-_]{43}$/);
});

test('scrypt hashes of the same code differ because salts are random', () => {
  const first = hashToken('492810', { algorithm: 'scrypt' });
  const second = hashToken('492810', { algorithm: 'scrypt' });
  assert.notEqual(first, second);
  assert.notEqual(first.split('$')[3], second.split('$')[3]);
});

test('scrypt verification accepts the correct code', () => {
  const encoded = hashToken('492810', { algorithm: 'scrypt' });
  assert.equal(verifyTokenHash('492810', encoded), true);
});

test('scrypt verification rejects a wrong code', () => {
  const encoded = hashToken('492810', { algorithm: 'scrypt' });
  assert.equal(verifyTokenHash('492811', encoded), false);
});

test('scrypt async hash and verify round trip', async () => {
  const encoded = await hashTokenAsync('492810', { algorithm: 'scrypt' });
  assert.equal(await verifyTokenHashAsync('492810', encoded), true);
  assert.equal(await verifyTokenHashAsync('492811', encoded), false);
});

test('scrypt sync verifier accepts an async-produced hash', async () => {
  const encoded = await hashTokenAsync('492810', { algorithm: 'scrypt' });
  assert.equal(verifyTokenHash('492810', encoded), true);
});

test('scrypt async verifier accepts a sync-produced hash', async () => {
  const encoded = hashToken('492810', { algorithm: 'scrypt' });
  assert.equal(await verifyTokenHashAsync('492810', encoded), true);
});

test('stronger in-bound scrypt parameters are encoded and verified', () => {
  const encoded = hashToken('492810', { algorithm: 'scrypt', scrypt: { N: 16384, r: 8, p: 2 } });
  assert.match(encoded, /^tc1\$scrypt\$N=16384,r=8,p=2\$/);
  assert.equal(verifyTokenHash('492810', encoded), true);
});

for (const params of [
  { N: 8192 },
  { N: 16383 },
  { N: 16385 },
  { N: 65537 },
  { N: 131072 },
  { r: 7 },
  { r: 17 },
  { p: 0 },
  { p: 5 },
  { N: 65536, r: 16, p: 4 },
  { N: 16384, r: 8, p: 1, extra: true }
]) {
  test('out-of-policy scrypt parameters rejected: ' + JSON.stringify(params), () => {
    assert.throws(() => hashToken('492810', { algorithm: 'scrypt', scrypt: params }), TokenCageError);
  });
}

for (const encoded of [
  '',
  'tc1$scrypt',
  'tc1$scrypt$N=16384,r=8,p=1',
  'tc1$scrypt$N=16384,r=8,p=1$' + 'A'.repeat(22),
  'tc1$scrypt$N=8192,r=8,p=1$' + 'A'.repeat(22) + '$' + 'A'.repeat(43),
  'tc1$scrypt$N=16384,r=7,p=1$' + 'A'.repeat(22) + '$' + 'A'.repeat(43),
  'tc1$scrypt$N=16384,r=8,p=5$' + 'A'.repeat(22) + '$' + 'A'.repeat(43),
  'tc1$scrypt$r=8,N=16384,p=1$' + 'A'.repeat(22) + '$' + 'A'.repeat(43),
  'tc1$scrypt$N=16384,r=8,p=1$' + 'A'.repeat(21) + '$' + 'A'.repeat(43),
  'tc1$scrypt$N=16384,r=8,p=1$' + 'A'.repeat(22) + '$' + 'A'.repeat(42),
  'tc1$scrypt$N=16384,r=8,p=1$' + 'A'.repeat(22) + '$' + 'A'.repeat(42) + '+'
]) {
  test('malformed or out-of-policy scrypt hash returns false: ' + encoded.slice(0, 58), () => {
    assert.equal(verifyTokenHash('492810', encoded), false);
  });
}

test('scrypt verification rejects mutation in derived key', () => {
  const encoded = hashToken('492810', { algorithm: 'scrypt' });
  const parts = encoded.split('$');
  parts[4] = (parts[4][0] === 'A' ? 'B' : 'A') + parts[4].slice(1);
  assert.equal(verifyTokenHash('492810', parts.join('$')), false);
});

test('scrypt verification rejects mutation in salt', () => {
  const encoded = hashToken('492810', { algorithm: 'scrypt' });
  const parts = encoded.split('$');
  parts[3] = (parts[3][0] === 'A' ? 'B' : 'A') + parts[3].slice(1);
  assert.equal(verifyTokenHash('492810', parts.join('$')), false);
});

test('scrypt verification rejects mutation in parameters', () => {
  const encoded = hashToken('492810', { algorithm: 'scrypt' });
  const mutated = encoded.replace('p=1', 'p=2');
  assert.equal(verifyTokenHash('492810', mutated), false);
});

for (const options of [
  { algorithm: 'scrypt', pepper },
  { algorithm: 'scrypt', version: 'v1' },
  { algorithm: 'scrypt', unknown: true },
  { algorithm: 'scrypt', scrypt: null },
  { algorithm: 'scrypt', scrypt: [] }
]) {
  test('invalid scrypt hash options rejected: ' + JSON.stringify(options), () => {
    assert.throws(() => hashToken('492810', options), TokenCageError);
  });
}

test('hash option validation happens before expensive scrypt work', () => {
  const start = performance.now();
  assert.throws(() => hashToken('492810', { algorithm: 'scrypt', scrypt: { N: 8192 } }), TokenCageError);
  assert.equal(performance.now() - start < 100, true);
});

test('encoded hashes over the parser length ceiling return false', () => {
  assert.equal(verifyTokenHash(token, 'tc1$hmac-sha256$v1$' + 'A'.repeat(600), { pepper }), false);
});

test('hashToken default algorithm is hmac-sha256', () => {
  assert.match(hashToken(token, { pepper }), /^tc1\$hmac-sha256\$/);
});

test('hashToken rejects unknown algorithm', () => {
  assert.throws(() => hashToken(token, { algorithm: 'plain', pepper }), TokenCageError);
});
