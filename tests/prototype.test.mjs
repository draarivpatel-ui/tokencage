import test from 'node:test';
import assert from 'node:assert/strict';
import { esm, mint, strongPepper } from './helpers.mjs';

const {
  generateTokenDetails,
  hashToken,
  createTokenVerifier,
  createTokenRecord,
  verifyTokenRecord,
  hasScopes,
  CODE,
  RESULT_CODE
} = esm;

const pepper = strongPepper();
const NOW = Date.parse('2026-11-27T00:00:00.000Z');

function inherited(key, value) {
  const prototype = {};
  prototype[key] = value;
  return Object.create(prototype);
}

function sparseWithInheritedZero(value) {
  const output = new Array(1);
  Object.setPrototypeOf(output, { 0: value });
  return output;
}

test('inherited generation options are rejected instead of used', () => {
  assert.throws(() => generateTokenDetails(inherited('prefix', 'polluted')), (error) => error.code === CODE.INVALID_OPTIONS);
});

test('inherited pepper options are rejected instead of used', () => {
  const token = mint().token;
  assert.throws(() => hashToken(token, inherited('pepper', pepper)), (error) => error.code === CODE.INVALID_OPTIONS);
  assert.throws(() => createTokenVerifier(inherited('pepper', pepper)), (error) => error.code === CODE.INVALID_OPTIONS);
});

test('inherited entries in a pepper rotation list are rejected', () => {
  const entries = sparseWithInheritedZero({ version: 'v1', pepper });
  assert.throws(() => createTokenVerifier({ peppers: entries }), (error) => error.code === CODE.INVALID_OPTIONS);
});

test('sparse scope arrays cannot inherit authorization entries', () => {
  const token = mint().token;
  const sparseScopes = sparseWithInheritedZero('read');
  assert.equal(hasScopes(sparseScopes, ['read']), false);
  assert.throws(() => createTokenRecord(token, { pepper, scopes: sparseScopes, now: NOW }), (error) => error.code === CODE.INVALID_OPTIONS);

  const record = createTokenRecord(token, { pepper, scopes: ['read'], now: NOW, ttlMs: 60000 });
  record.scopes = sparseScopes;
  const result = verifyTokenRecord(token, record, { pepper, now: NOW + 1000 });
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.INVALID_RECORD);
});

test('sparse required scope arrays cannot inherit requirements or authority', () => {
  const sparseRequired = sparseWithInheritedZero('read');
  assert.equal(hasScopes(['read'], sparseRequired), false);
});

test('a record inherited through its prototype is not accepted as stored data', () => {
  const details = mint();
  const record = createTokenRecord(details.token, { pepper, scopes: ['read'], now: NOW, ttlMs: 60000 });
  const inheritedRecord = Object.create(record);
  const result = verifyTokenRecord(details.token, inheritedRecord, { pepper, now: NOW + 1000 });
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.INVALID_RECORD);
});
