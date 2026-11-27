import test from 'node:test';
import assert from 'node:assert/strict';
import { esm, strongPepper, secondStrongPepper, mint } from './helpers.mjs';

const {
  createTokenRecord,
  verifyTokenRecord,
  hasScopes,
  hashToken,
  TokenCageError,
  CODE,
  RESULT_CODE
} = esm;

const pepperV1 = strongPepper();
const pepperV2 = secondStrongPepper();
const tokenDetails = mint();
const token = tokenDetails.token;
const NOW = Date.parse('2026-11-27T00:00:00.000Z');

function createBase(overrides = {}) {
  return createTokenRecord(token, {
    pepper: pepperV1,
    version: 'v1',
    scopes: ['read', 'write'],
    now: NOW,
    ttlMs: 60000,
    ...overrides
  });
}

function verifyBase(record, overrides = {}) {
  return verifyTokenRecord(token, record, {
    pepper: pepperV1,
    version: 'v1',
    now: NOW + 1000,
    requiredScopes: ['read'],
    ...overrides
  });
}

test('createTokenRecord creates the documented storage shape', () => {
  const record = createBase();
  assert.equal(record.type, 'tokencage-record');
  assert.equal(record.version, 1);
  assert.match(record.hash, /^tc1\$hmac-sha256\$v1\$/);
  assert.equal(record.prefix, 'testapp');
  assert.equal(record.keyId, tokenDetails.keyId);
  assert.deepEqual(record.scopes, ['read', 'write']);
  assert.equal(record.createdAt, '2026-11-27T00:00:00.000Z');
  assert.equal(record.expiresAt, '2026-11-27T00:01:00.000Z');
  assert.equal(record.revokedAt, null);
  assert.equal(record.lastUsedAt, null);
});

test('createTokenRecord never stores the raw token', () => {
  const record = createBase();
  assert.equal(JSON.stringify(record).includes(token), false);
  assert.equal(Object.values(record).includes(token), false);
});

test('createTokenRecord deduplicates scopes while preserving order', () => {
  const record = createBase({ scopes: ['read', 'write', 'read', 'admin:users', 'write'] });
  assert.deepEqual(record.scopes, ['read', 'write', 'admin:users']);
});

test('createTokenRecord accepts explicit expiresAt', () => {
  const record = createBase({ ttlMs: undefined, expiresAt: '2026-11-27T00:05:00.000Z' });
  assert.equal(record.expiresAt, '2026-11-27T00:05:00.000Z');
});

test('createTokenRecord accepts null expiresAt', () => {
  const record = createBase({ ttlMs: undefined, expiresAt: null });
  assert.equal(record.expiresAt, null);
});

test('createTokenRecord supports scrypt for short codes with requireFormat false', () => {
  const record = createTokenRecord('492810', {
    algorithm: 'scrypt',
    requireFormat: false,
    scopes: ['login'],
    now: NOW,
    ttlMs: 300000
  });
  assert.match(record.hash, /^tc1\$scrypt\$/);
  assert.equal(record.prefix, null);
  assert.equal(record.keyId, null);
});

test('createTokenRecord can bind an opaque secret when requireFormat is false', () => {
  const record = createTokenRecord('opaque-session-secret', {
    pepper: pepperV1,
    requireFormat: false,
    now: NOW
  });
  assert.equal(record.prefix, null);
  assert.equal(record.keyId, null);
  assert.match(record.hash, /^tc1\$hmac-sha256\$/);
});

test('createTokenRecord rejects a malformed tokencage token by default', () => {
  assert.throws(() => createTokenRecord('not-a-token', { pepper: pepperV1 }), TokenCageError);
});

for (const [label, scopes] of [
  ['not array', 'read'],
  ['wildcard', ['*']],
  ['uppercase', ['Read']],
  ['space', ['read reports']],
  ['empty', ['']],
  ['too long', ['a'.repeat(65)]],
  ['non-string', [1]],
  ['prototype word with uppercase', ['Constructor']],
  ['too many', Array.from({ length: 65 }, (_, i) => 'scope' + i)]
]) {
  test('invalid create scopes rejected: ' + label, () => {
    assert.throws(() => createBase({ scopes }), TokenCageError);
  });
}

for (const [label, mutation] of [
  ['expiresAt and ttlMs together', { expiresAt: '2026-11-27T00:05:00.000Z', ttlMs: 1000 }],
  ['expiresAt before creation', { ttlMs: undefined, expiresAt: '2026-11-26T23:59:00.000Z' }],
  ['expiresAt equal to creation', { ttlMs: undefined, expiresAt: '2026-11-27T00:00:00.000Z' }],
  ['zero ttlMs', { ttlMs: 0 }],
  ['negative ttlMs', { ttlMs: -1 }],
  ['huge ttlMs', { ttlMs: 31536000001 }],
  ['future createdAt', { createdAt: NOW + 1000 }]
]) {
  test('invalid record time options rejected: ' + label, () => {
    assert.throws(() => createBase(mutation), TokenCageError);
  });
}


test('invalid calendar dates are rejected in create options', () => {
  assert.throws(() => createBase({ ttlMs: undefined, expiresAt: '2026-02-30T00:00:00.000Z' }), (error) => error.code === CODE.INVALID_OPTIONS);
  assert.throws(() => createBase({ createdAt: '2026-11-27T24:00:00.000Z' }), (error) => error.code === CODE.INVALID_OPTIONS);
});

test('invalid calendar dates make stored records invalid', () => {
  const record = createBase();
  record.createdAt = '2026-02-30T00:00:00.000Z';
  const result = verifyBase(record);
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.INVALID_RECORD);
});

test('valid ISO offsets are canonical inputs without changing the instant', () => {
  const record = createBase({ ttlMs: undefined, expiresAt: '2026-11-27T05:01:00.000+05:00' });
  assert.equal(record.expiresAt, '2026-11-27T00:01:00.000Z');
});

test('verifyTokenRecord accepts a valid unexpired scoped token', () => {
  const result = verifyBase(createBase());
  assert.equal(result.valid, true, result.reason);
  assert.equal(result.code, RESULT_CODE.OK);
  assert.equal(result.needsRehash, false);
  assert.equal(result.keyId, tokenDetails.keyId);
  assert.equal(result.prefix, 'testapp');
  assert.equal(result.record.hash, createBase().hash);
});

test('verifyTokenRecord rejects the wrong token', () => {
  const result = verifyTokenRecord(mint().token, createBase(), {
    pepper: pepperV1,
    now: NOW + 1000
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.HASH_MISMATCH);
});

test('verifyTokenRecord rejects an expired record at exact expiry', () => {
  const result = verifyBase(createBase(), { now: NOW + 60000 });
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.EXPIRED);
});

test('clock skew can tolerate a small expired boundary difference', () => {
  const result = verifyBase(createBase(), { now: NOW + 60500, clockSkewMs: 1000 });
  assert.equal(result.valid, true);
});

test('clock skew boundary itself is expired', () => {
  const result = verifyBase(createBase(), { now: NOW + 61000, clockSkewMs: 1000 });
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.EXPIRED);
});

for (const skew of [-1, 300001, 1.5, '1000']) {
  test('invalid clock skew rejected: ' + String(skew), () => {
    assert.throws(() => verifyBase(createBase(), { clockSkewMs: skew }), TokenCageError);
  });
}

test('revoked record fails even before expiry', () => {
  const record = createBase();
  record.revokedAt = '2026-11-27T00:00:30.000Z';
  const result = verifyBase(record);
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.REVOKED);
});

test('future createdAt beyond skew fails closed', () => {
  const record = createBase();
  record.createdAt = '2026-11-27T00:01:00.000Z';
  record.expiresAt = '2026-11-27T00:02:00.000Z';
  const result = verifyBase(record, { now: NOW });
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.NOT_YET_VALID);
});

test('future createdAt inside clock skew is tolerated', () => {
  const record = createBase();
  record.createdAt = '2026-11-27T00:00:00.500Z';
  const result = verifyBase(record, { now: NOW, clockSkewMs: 1000 });
  assert.equal(result.valid, true);
});

test('future lastUsedAt beyond skew makes the record invalid', () => {
  const record = createBase();
  record.lastUsedAt = '2026-11-27T00:10:00.000Z';
  const result = verifyBase(record);
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.INVALID_RECORD);
});

test('past lastUsedAt is accepted and does not affect validity', () => {
  const record = createBase();
  record.lastUsedAt = '2026-11-27T00:00:00.500Z';
  const result = verifyBase(record);
  assert.equal(result.valid, true);
});

test('missing required scope fails closed', () => {
  const result = verifyBase(createBase(), { requiredScopes: ['admin'] });
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.INSUFFICIENT_SCOPES);
});

test('multiple required scopes must all be present', () => {
  assert.equal(verifyBase(createBase(), { requiredScopes: ['read', 'write'] }).valid, true);
  assert.equal(verifyBase(createBase(), { requiredScopes: ['read', 'admin'] }).valid, false);
});

test('wildcard required scope does not match ordinary scopes', () => {
  assert.equal(hasScopes(['read', 'write'], ['*']), false);
});

test('wildcard stored scope does not match ordinary required scopes', () => {
  assert.equal(hasScopes(['*'], ['read']), false);
});

test('scope matching is exact and case sensitive', () => {
  assert.equal(hasScopes(['read'], ['read']), true);
  assert.equal(hasScopes(['read'], ['Read']), false);
  assert.equal(hasScopes(['read'], ['read:reports']), false);
});

for (const [held, required, expected] of [
  [[], [], true],
  [['read'], [], true],
  [[], ['read'], false],
  [['read', 'write'], ['write'], true],
  [['read'], ['read', 'read'], true],
  [['read', 'read'], ['read'], true],
  [['__proto__'], ['__proto__'], true],
  [['constructor'], ['prototype'], false]
]) {
  test('hasScopes matrix ' + JSON.stringify(held) + ' / ' + JSON.stringify(required), () => {
    assert.equal(hasScopes(held, required), expected);
  });
}

for (const [held, required] of [
  [null, []],
  [[], null],
  ['read', ['read']],
  [['read'], 'read'],
  [[1], ['1']],
  [['read'], [1]]
]) {
  test('hasScopes fails closed for invalid inputs', () => {
    assert.equal(hasScopes(held, required), false);
  });
}

function malformedRecords() {
  const base = createBase();
  const entries = [];
  const add = (label, mutate) => {
    const copy = JSON.parse(JSON.stringify(base));
    mutate(copy);
    entries.push([label, copy]);
  };
  add('unknown field', (r) => { r.extra = true; });
  add('wrong type', (r) => { r.type = 'other'; });
  add('wrong schema', (r) => { r.version = 2; });
  add('bad hash', (r) => { r.hash = 'bad'; });
  add('prefix number', (r) => { r.prefix = 1; });
  add('bad key id', (r) => { r.keyId = 'abcdefghij'; });
  add('scopes missing', (r) => { delete r.scopes; });
  add('scopes string', (r) => { r.scopes = 'read'; });
  add('bad createdAt', (r) => { r.createdAt = 'not a date'; });
  add('expires before creation', (r) => { r.expiresAt = r.createdAt; });
  add('bad expiresAt', (r) => { r.expiresAt = 'tomorrow'; });
  add('bad revokedAt', (r) => { r.revokedAt = 'yesterday'; });
  add('lastUsed before creation', (r) => { r.lastUsedAt = '2026-11-26T00:00:00.000Z'; });
  return entries;
}

for (const [label, record] of malformedRecords()) {
  test('malformed stored record rejected: ' + label, () => {
    const result = verifyBase(record);
    assert.equal(result.valid, false);
    assert.equal(result.code, RESULT_CODE.INVALID_RECORD);
    assert.equal(result.record, null);
  });
}

for (const record of [null, undefined, [], 'record', 1]) {
  test('non-object stored record rejected: ' + String(record), () => {
    const result = verifyBase(record);
    assert.equal(result.valid, false);
    assert.equal(result.code, RESULT_CODE.INVALID_RECORD);
  });
}

test('verifyTokenRecord does not mutate the input record', () => {
  const record = createBase();
  const before = JSON.stringify(record);
  verifyBase(record);
  assert.equal(JSON.stringify(record), before);
});

test('verifyTokenRecord returned record is a safe copy', () => {
  const record = createBase();
  const result = verifyBase(record);
  assert.notEqual(result.record, record);
  result.record.scopes.push('mutated');
  assert.equal(record.scopes.includes('mutated'), false);
});

test('record verification enforces expected prefix', () => {
  const result = verifyBase(createBase(), { prefix: 'other' });
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.INVALID_FORMAT);
});

test('record verification enforces key id expectation', () => {
  const result = verifyBase(createBase(), { keyId: false });
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.INVALID_FORMAT);
});

test('record verification can skip format enforcement for opaque secrets', () => {
  const record = createTokenRecord('opaque-session-secret', {
    pepper: pepperV1,
    requireFormat: false,
    now: NOW
  });
  const result = verifyTokenRecord('opaque-session-secret', record, {
    pepper: pepperV1,
    requireFormat: false,
    now: NOW
  });
  assert.equal(result.valid, true);
});

test('scrypt record verification accepts correct code', () => {
  const record = createTokenRecord('492810', {
    algorithm: 'scrypt',
    requireFormat: false,
    now: NOW,
    scopes: ['login']
  });
  const result = verifyTokenRecord('492810', record, {
    requireFormat: false,
    requiredScopes: ['login'],
    now: NOW
  });
  assert.equal(result.valid, true);
});

test('scrypt record verification rejects wrong code', () => {
  const record = createTokenRecord('492810', {
    algorithm: 'scrypt',
    requireFormat: false,
    now: NOW
  });
  const result = verifyTokenRecord('492811', record, {
    requireFormat: false,
    now: NOW
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.HASH_MISMATCH);
});


test('verifyTokenRecord rejects mismatched stored prefix metadata', () => {
  const record = createBase();
  record.prefix = 'other';
  const result = verifyBase(record);
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.HASH_MISMATCH);
});

test('verifyTokenRecord rejects mismatched stored key id metadata', () => {
  const record = createBase();
  record.keyId = 'A123456789';
  const result = verifyBase(record);
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.HASH_MISMATCH);
});

test('verifyTokenRecord rejects key id metadata without prefix metadata', () => {
  const record = createBase();
  record.prefix = null;
  const result = verifyBase(record);
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.INVALID_RECORD);
});


test('verifyTokenRecord rejects format metadata bound to an opaque secret', () => {
  const record = createTokenRecord('opaque-secret-for-binding', {
    algorithm: 'scrypt',
    requireFormat: false
  });
  record.prefix = 'testapp';
  const result = verifyTokenRecord('opaque-secret-for-binding', record, {
    requireFormat: false
  });
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.HASH_MISMATCH);
});

test('retired hmac record returns needsRehash and nextHash', () => {
  const record = createBase();
  const result = verifyTokenRecord(token, record, {
    peppers: { v1: pepperV1, v2: pepperV2 },
    currentVersion: 'v2',
    now: NOW + 1000
  });
  assert.equal(result.valid, true);
  assert.equal(result.needsRehash, true);
  assert.match(result.nextHash, /^tc1\$hmac-sha256\$v2\$/);
});

test('record result does not mutate stored hash while returning nextHash', () => {
  const record = createBase();
  const before = record.hash;
  const result = verifyTokenRecord(token, record, {
    peppers: { v1: pepperV1, v2: pepperV2 },
    currentVersion: 'v2',
    now: NOW + 1000
  });
  assert.equal(result.needsRehash, true);
  assert.equal(record.hash, before);
  assert.equal(result.record.hash, before);
});

test('current hmac record does not need rehash', () => {
  const record = createBase({ pepper: pepperV2, version: 'v2' });
  const result = verifyTokenRecord(token, record, {
    peppers: { v1: pepperV1, v2: pepperV2 },
    currentVersion: 'v2',
    now: NOW + 1000
  });
  assert.equal(result.valid, true);
  assert.equal(result.needsRehash, false);
  assert.equal(result.nextHash, null);
});

for (const options of [
  { unknown: true },
  { requiredScopes: 'read' },
  { keyId: 'true' },
  { requireFormat: 'yes' },
  null,
  []
]) {
  test('invalid record verification options rejected: ' + JSON.stringify(options), () => {
    assert.throws(() => verifyTokenRecord(token, createBase(), options), TokenCageError);
  });
}

test('record verification rejects invalid token input without throwing', () => {
  for (const value of [null, undefined, '', 1, {}, []]) {
    const result = verifyTokenRecord(value, createBase(), { pepper: pepperV1, now: NOW });
    assert.equal(result.valid, false);
    assert.equal(result.code, RESULT_CODE.INVALID_INPUT);
  }
});

test('hash record carries no pepper material in JSON', () => {
  const output = JSON.stringify(createBase());
  assert.equal(output.includes(pepperV1), false);
});
