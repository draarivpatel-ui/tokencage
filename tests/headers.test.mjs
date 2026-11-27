import test from 'node:test';
import assert from 'node:assert/strict';
import { esm, mint } from './helpers.mjs';

const { extractBearerToken, extractApiKeyHeader, TokenCageError, CODE } = esm;
const token = mint().token;

test('extractBearerToken parses a direct Bearer header value', () => {
  assert.equal(extractBearerToken('Bearer ' + token), token);
});

test('extractBearerToken parses a lowercase authorization object key', () => {
  assert.equal(extractBearerToken({ authorization: 'Bearer ' + token }), token);
});

test('extractBearerToken parses a mixed-case authorization object key', () => {
  assert.equal(extractBearerToken({ Authorization: 'Bearer ' + token }), token);
});

test('extractBearerToken parses a single-value array', () => {
  assert.equal(extractBearerToken(['Bearer ' + token]), token);
});

test('extractBearerToken parses a Map header collection', () => {
  const map = new Map([['authorization', 'Bearer ' + token]]);
  assert.equal(extractBearerToken(map), token);
});

test('extractBearerToken parses a Headers-like object', () => {
  const headers = new (class {
    get(name) { return name.toLowerCase() === 'authorization' ? 'Bearer ' + token : null; }
  })();
  assert.equal(extractBearerToken(headers), token);
});

for (const scheme of ['Bearer', 'bearer', 'BEARER', 'BeArEr']) {
  test('Bearer scheme case is accepted: ' + scheme, () => {
    assert.equal(extractBearerToken(scheme + ' ' + token), token);
  });
}

test('multiple spaces after the Bearer scheme are RFC whitespace and accepted', () => {
  assert.equal(extractBearerToken('Bearer   ' + token), token);
});

for (const token68 of ['abc', 'abc123', 'a-b_c.d~e', 'a+b/c', 'abc=', 'abc==']) {
  test('valid token68 accepted: ' + token68, () => {
    assert.equal(extractBearerToken('Bearer ' + token68), token68);
  });
}

test('tokencage underscore separators are valid token68 characters', () => {
  assert.equal(token.includes('_'), true);
  assert.equal(extractBearerToken('Bearer ' + token), token);
});

for (const header of ['Basic abc', 'Digest abc', 'BearerX' + token, ' bearer ' + token]) {
  test('non-Bearer authorization scheme returns null: ' + header.slice(0, 12), () => {
    assert.equal(extractBearerToken(header), null);
  });
}

for (const input of [{}, { authorization: null }, { authorization: undefined }, [], new Map()]) {
  test('missing authorization returns null for ' + Object.prototype.toString.call(input), () => {
    assert.equal(extractBearerToken(input), null);
  });
}

for (const [label, input] of [
  ['object with duplicate casing', { Authorization: 'Bearer a', authorization: 'Bearer b' }],
  ['array with two values', ['Bearer a', 'Bearer b']],
  ['object value array with two values', { authorization: ['Bearer a', 'Bearer b'] }],
  ['map with duplicate casing', new Map([['Authorization', 'Bearer a'], ['authorization', 'Bearer b']])]
]) {
  test('multiple credential headers are rejected: ' + label, () => {
    assert.throws(() => extractBearerToken(input), TokenCageError);
  });
}

test('credential arrays cannot inherit their single value', () => {
  const values = new Array(1);
  Object.setPrototypeOf(values, { 0: 'Bearer ' + token });
  assert.throws(() => extractBearerToken(values), TokenCageError);
  assert.throws(() => extractBearerToken({ authorization: values }), TokenCageError);
});

for (const [label, header] of [
  ['empty', ''],
  ['scheme only', 'Bearer'],
  ['scheme and spaces only', 'Bearer   '],
  ['embedded space', 'Bearer abc def'],
  ['leading token space then empty', 'Bearer  '],
  ['comma combined values', 'Bearer abc,Bearer def'],
  ['equals inside token', 'Bearer ab=cd'],
  ['three trailing padding characters', 'Bearer abc==='],
  ['four trailing padding characters', 'Bearer a===='],
  ['exclamation character', 'Bearer abc!'],
  ['quote character', 'Bearer abc"'],
  ['unicode', 'Bearer abcé'],
  ['carriage return', 'Bearer abc\rdef'],
  ['line feed', 'Bearer abc\ndef'],
  ['CRLF pair', 'Bearer abc\r\ndef'],
  ['tab after scheme', 'Bearer\tabc'],
  ['tab inside token', 'Bearer abc\tdef'],
  ['nul inside token', 'Bearer abc\0def']
]) {
  test('malformed Bearer input rejected: ' + label, () => {
    assert.throws(() => extractBearerToken(header), TokenCageError);
  });
}

test('Bearer input at maxLength exactly is accepted', () => {
  const header = 'Bearer ' + token;
  assert.equal(extractBearerToken(header, { maxLength: header.length }), token);
});

test('Bearer input over maxLength is rejected', () => {
  const header = 'Bearer ' + token;
  assert.throws(() => extractBearerToken(header, { maxLength: header.length - 1 }), (error) => error.code === CODE.LIMIT_EXCEEDED);
});

test('Bearer input over the default length bound is rejected', () => {
  const header = 'Bearer ' + 'a'.repeat(2048);
  assert.throws(() => extractBearerToken(header), (error) => error.code === CODE.LIMIT_EXCEEDED);
});

for (const maxLength of [0, 15, 8193, 16.5, '1024']) {
  test('invalid Bearer maxLength rejected: ' + String(maxLength), () => {
    assert.throws(() => extractBearerToken('Bearer ' + token, { maxLength }), TokenCageError);
  });
}

for (const input of [null, undefined, 1, false, { authorization: 1 }, { authorization: {} }]) {
  test('invalid header input rejected: ' + String(input), () => {
    assert.throws(() => extractBearerToken(input), TokenCageError);
  });
}

test('Bearer errors do not echo token material', () => {
  const secretish = token;
  try {
    extractBearerToken('Bearer ' + secretish + ' space');
    assert.unreachable('expected extraction to throw');
  } catch (error) {
    assert.equal(error.message.includes(secretish), false);
    assert.equal(JSON.stringify(error).includes(secretish), false);
  }
});

test('extractApiKeyHeader parses a direct value', () => {
  assert.equal(extractApiKeyHeader(token), token);
});

test('extractApiKeyHeader parses the default x-api-key object key', () => {
  assert.equal(extractApiKeyHeader({ 'x-api-key': token }), token);
});

test('extractApiKeyHeader matches object keys case-insensitively', () => {
  assert.equal(extractApiKeyHeader({ 'X-Api-Key': token }), token);
});

test('extractApiKeyHeader parses a custom header name', () => {
  assert.equal(extractApiKeyHeader({ 'x-acme-key': token }, { name: 'x-acme-key' }), token);
});

test('extractApiKeyHeader custom matching is case-insensitive', () => {
  assert.equal(extractApiKeyHeader({ 'X-ACME-KEY': token }, { name: 'x-acme-key' }), token);
});

test('extractApiKeyHeader parses a Map', () => {
  assert.equal(extractApiKeyHeader(new Map([['x-api-key', token]])), token);
});

test('extractApiKeyHeader parses a Headers-like object', () => {
  const headers = new (class {
    get(name) { return name.toLowerCase() === 'x-api-key' ? token : null; }
  })();
  assert.equal(extractApiKeyHeader(headers), token);
});

test('extractApiKeyHeader returns null when the configured header is absent', () => {
  assert.equal(extractApiKeyHeader({ authorization: token }), null);
  assert.equal(extractApiKeyHeader({}, { name: 'x-missing' }), null);
});

for (const token68 of ['abc', 'abc123', 'a-b_c.d~e', 'a+b/c', 'abc=', 'abc==']) {
  test('valid API key token accepted: ' + token68, () => {
    assert.equal(extractApiKeyHeader({ 'x-api-key': token68 }), token68);
  });
}

for (const [label, value] of [
  ['empty', ''],
  ['embedded space', 'abc def'],
  ['leading space', ' abc'],
  ['trailing space', 'abc '],
  ['comma', 'abc,def'],
  ['equals inside', 'ab=cd'],
  ['exclamation', 'abc!'],
  ['unicode', 'abcé'],
  ['carriage return', 'abc\rdef'],
  ['line feed', 'abc\ndef'],
  ['CRLF pair', 'abc\r\ndef'],
  ['tab', 'abc\tdef'],
  ['nul', 'abc\0def']
]) {
  test('malformed API key value rejected: ' + label, () => {
    assert.throws(() => extractApiKeyHeader({ 'x-api-key': value }), TokenCageError);
  });
}

for (const [label, input] of [
  ['object duplicate casing', { 'X-API-Key': 'a', 'x-api-key': 'b' }],
  ['array duplicate values', ['a', 'b']],
  ['object array duplicate values', { 'x-api-key': ['a', 'b'] }]
]) {
  test('multiple API key headers rejected: ' + label, () => {
    assert.throws(() => extractApiKeyHeader(input), TokenCageError);
  });
}

for (const name of ['', 'bad name', 'bad\tname', 'é', 'x'.repeat(65), 1, null]) {
  test('invalid API key header name rejected: ' + String(name), () => {
    assert.throws(() => extractApiKeyHeader({ 'x-api-key': token }, { name }), TokenCageError);
  });
}

test('API key input at maxLength exactly is accepted', () => {
  assert.equal(extractApiKeyHeader({ 'x-api-key': token }, { maxLength: token.length }), token);
});

test('API key input over maxLength is rejected', () => {
  assert.throws(() => extractApiKeyHeader({ 'x-api-key': token }, { maxLength: token.length - 1 }), (error) => error.code === CODE.LIMIT_EXCEEDED);
});

test('API key errors do not echo key material', () => {
  try {
    extractApiKeyHeader({ 'x-api-key': token + ' space' });
    assert.unreachable('expected extraction to throw');
  } catch (error) {
    assert.equal(error.message.includes(token), false);
    assert.equal(JSON.stringify(error).includes(token), false);
  }
});
