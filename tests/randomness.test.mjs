import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { esm, root } from './helpers.mjs';

const { generateToken, generateTokenDetails, validateKeyId } = esm;
const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function secretBody(token) {
  const body = token.slice(token.lastIndexOf('_') + 1);
  return body.slice(0, -6);
}

test('one hundred generated tokens are unique in one batch', () => {
  const values = new Set();
  for (let i = 0; i < 100; i += 1) values.add(generateToken({ prefix: 'testapp' }));
  assert.equal(values.size, 100);
});

test('one hundred generated key ids are unique in one batch', () => {
  const values = new Set();
  for (let i = 0; i < 100; i += 1) values.add(generateTokenDetails({ prefix: 'testapp', keyId: true }).keyId);
  assert.equal(values.size, 100);
});

test('generated secret bodies contain only base62 characters', () => {
  for (let i = 0; i < 100; i += 1) {
    assert.match(secretBody(generateToken({ prefix: 'testapp' })), /^[0-9A-Za-z]+$/);
  }
});

test('generated tokens do not contain dash or underscore inside the secret body', () => {
  for (let i = 0; i < 50; i += 1) {
    const body = secretBody(generateToken({ prefix: 'testapp' }));
    assert.equal(body.includes('-'), false);
    assert.equal(body.includes('_'), false);
  }
});

test('large sample observes every base62 alphabet character', () => {
  const seen = new Set();
  for (let i = 0; i < 150; i += 1) {
    for (const ch of secretBody(generateToken({ prefix: 'testapp' }))) seen.add(ch);
  }
  assert.equal(seen.size, 62);
});

test('large sample distribution has no severe single-character skew', () => {
  const counts = new Map();
  let total = 0;
  for (let i = 0; i < 150; i += 1) {
    for (const ch of secretBody(generateToken({ prefix: 'testapp' }))) {
      counts.set(ch, (counts.get(ch) || 0) + 1);
      total += 1;
    }
  }
  const expected = total / 62;
  let chiSquare = 0;
  for (const ch of alphabet) {
    const observed = counts.get(ch) || 0;
    chiSquare += ((observed - expected) ** 2) / expected;
  }
  assert.equal(chiSquare < 140, true, 'chi-square statistic was ' + chiSquare);
});

for (const bytes of [16, 24, 32, 48, 64]) {
  test('secret character length is stable for byte budget ' + bytes, () => {
    const details = generateTokenDetails({ prefix: 'testapp', bytes });
    assert.equal(secretBody(details.token).length, details.secretLength);
    assert.equal(details.entropyBits >= bytes * 8, true);
  });
}

for (let i = 0; i < 25; i += 1) {
  test('generated key id is canonical in sample ' + i, () => {
    const keyId = generateTokenDetails({ prefix: 'testapp', keyId: true }).keyId;
    assert.equal(validateKeyId(keyId).valid, true);
  });
}

test('source uses node:crypto randomBytes', () => {
  const source = fs.readFileSync(path.join(root, 'src', 'index.mjs'), 'utf8');
  assert.equal(source.includes("import crypto from 'node:crypto'"), true);
  assert.equal(source.includes('crypto.randomBytes'), true);
});

test('source does not use Math.random or pseudo random generation', () => {
  const source = fs.readFileSync(path.join(root, 'src', 'index.mjs'), 'utf8');
  assert.equal(source.includes('Math.random'), false);
  assert.equal(source.includes('pseudoRandomBytes'), false);
});

test('base62 rejection sampling rejects the biased remainder region', () => {
  const source = fs.readFileSync(path.join(root, 'src', 'index.mjs'), 'utf8');
  assert.equal(source.includes('BASE62_REJECTION_LIMIT = 248'), true);
  assert.equal(source.includes('byte >= BASE62_REJECTION_LIMIT'), true);
});

test('base62 modulo is applied only after rejection sampling', () => {
  const source = fs.readFileSync(path.join(root, 'src', 'index.mjs'), 'utf8');
  const randomFunction = source.slice(source.indexOf('function randomBase62'), source.indexOf('function randomKeyId'));
  assert.equal(randomFunction.indexOf('byte >= BASE62_REJECTION_LIMIT') < randomFunction.indexOf('byte % 62'), true);
});

test('token generation output is not sequential across repeated calls', () => {
  const first = secretBody(generateToken({ prefix: 'testapp' }));
  const second = secretBody(generateToken({ prefix: 'testapp' }));
  assert.notEqual(first, second);
  let differences = 0;
  for (let i = 0; i < first.length; i += 1) {
    if (first[i] !== second[i]) differences += 1;
  }
  assert.equal(differences > 20, true, 'only ' + differences + ' characters differed');
});

test('generated token details are frozen against accidental mutation', () => {
  const details = generateTokenDetails({ prefix: 'testapp' });
  assert.throws(() => {
    details.token = 'changed';
  }, TypeError);
});

test('generated token lengths stay inside the default inspection bound', () => {
  for (const bytes of [16, 32, 64]) {
    const details = generateTokenDetails({ prefix: 'a' + 'x'.repeat(23), bytes, keyId: true });
    assert.equal(details.token.length <= 256, true);
  }
});

test('base62 alphabet order used by checksums is explicit in source', () => {
  const source = fs.readFileSync(path.join(root, 'src', 'index.mjs'), 'utf8');
  assert.equal(source.includes("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"), true);
});
