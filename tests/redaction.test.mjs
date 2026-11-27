import test from 'node:test';
import assert from 'node:assert/strict';
import util from 'node:util';
import { esm, mint, flipChar } from './helpers.mjs';

const { redactToken, maskToken, TokenValue, createTokenValue, generateTokenDetails, TokenCageError } = esm;

function secretOf(token) {
  const body = token.slice(token.lastIndexOf('_') + 1);
  return body.slice(0, -6);
}


test('GeneratedTokenDetails util.inspect redacts the token property while JSON generation output remains usable', () => {
  const details = generateTokenDetails({ prefix: 'testapp', keyId: true });
  const inspected = util.inspect(details);
  assert.equal(inspected.includes(details.token), false);
  assert.equal(inspected.includes(details.redacted), true);
  assert.equal(JSON.parse(JSON.stringify(details)).token, details.token);
});

test('redactToken renders prefix key id ellipsis and last four for keyed tokens', () => {
  const details = mint();
  const secret = secretOf(details.token);
  assert.equal(redactToken(details.token), details.prefix + '_' + details.keyId + '_...' + secret.slice(-4));
});

test('redactToken renders prefix ellipsis and last four for unkeyed tokens', () => {
  const details = generateTokenDetails({ prefix: 'testapp', keyId: false });
  const secret = secretOf(details.token);
  assert.equal(redactToken(details.token), details.prefix + '_...' + secret.slice(-4));
});

test('redactToken never exposes more than four secret characters', () => {
  const details = mint();
  const redacted = redactToken(details.token);
  const secret = secretOf(details.token);
  for (let length = 5; length <= secret.length; length += 1) {
    assert.equal(redacted.includes(secret.slice(-length)), false);
  }
});

test('redactToken output is not a substring of the original token', () => {
  const details = mint();
  const redacted = redactToken(details.token);
  assert.equal(details.token.includes(redacted), false);
});

test('maskToken is an exact redaction alias', () => {
  const details = mint();
  assert.equal(maskToken(details.token), redactToken(details.token));
});

for (const value of [null, undefined, '', 1, false, {}, [], 'short', 'not-a-token']) {
  test('redactToken is fully redacted for invalid input: ' + String(value), () => {
    assert.equal(redactToken(value), '[REDACTED]');
  });
}

test('redactToken fully redacts a checksum-mutated token', () => {
  const details = mint();
  const mutated = flipChar(details.token, details.token.length - 1);
  assert.equal(redactToken(mutated), '[REDACTED]');
});

test('redactToken honors an expected prefix', () => {
  const details = mint();
  assert.equal(redactToken(details.token, { prefix: 'other' }), '[REDACTED]');
  assert.notEqual(redactToken(details.token, { prefix: 'testapp' }), '[REDACTED]');
});

test('redactToken rejects invalid options without exposing input', () => {
  const details = mint();
  assert.throws(() => redactToken(details.token, { unknown: true }), TokenCageError);
});

test('TokenValue reveal is the only explicit raw accessor', () => {
  const details = mint();
  const wrapped = new TokenValue(details.token);
  assert.equal(wrapped.reveal(), details.token);
});

test('TokenValue toString redacts', () => {
  const details = mint();
  const wrapped = new TokenValue(details.token);
  assert.equal(wrapped.toString(), redactToken(details.token));
  assert.notEqual(wrapped.toString(), details.token);
});

test('TokenValue template conversion redacts', () => {
  const details = mint();
  const wrapped = new TokenValue(details.token);
  assert.equal(String(wrapped), redactToken(details.token));
  assert.equal(wrapped + '', redactToken(details.token));
});

test('TokenValue valueOf redacts rather than exposing raw bytes', () => {
  const details = mint();
  assert.equal(new TokenValue(details.token).valueOf(), redactToken(details.token));
});

test('TokenValue JSON serialization redacts', () => {
  const details = mint();
  const output = JSON.stringify({ credential: new TokenValue(details.token) });
  assert.equal(output.includes(details.token), false);
  assert.equal(output.includes(redactToken(details.token)), true);
});

test('TokenValue util.inspect redacts through the custom inspect symbol', () => {
  const details = mint();
  const output = util.inspect(new TokenValue(details.token));
  assert.equal(output.includes(details.token), false);
  assert.equal(output.includes(redactToken(details.token)), true);
});

test('TokenValue console formatting does not expose raw token', () => {
  const details = mint();
  const output = util.format('%s %j %o', new TokenValue(details.token), new TokenValue(details.token), new TokenValue(details.token));
  assert.equal(output.includes(details.token), false);
});

test('TokenValue object keys do not expose token material', () => {
  const details = mint();
  const wrapped = new TokenValue(details.token);
  assert.deepEqual(Object.keys(wrapped), []);
  assert.equal(JSON.stringify(Object.getOwnPropertyNames(wrapped)).includes(details.token), false);
});

test('TokenValue is frozen', () => {
  const details = mint();
  const wrapped = new TokenValue(details.token);
  assert.equal(Object.isFrozen(wrapped), true);
});

test('createTokenValue returns a TokenValue instance', () => {
  const details = mint();
  const wrapped = createTokenValue(details.token);
  assert.equal(wrapped instanceof TokenValue, true);
  assert.equal(wrapped.reveal(), details.token);
});

for (const value of [null, undefined, '', 1, false, {}, []]) {
  test('TokenValue constructor rejects invalid input: ' + String(value), () => {
    assert.throws(() => new TokenValue(value), TokenCageError);
  });
}

test('TokenValue accepts an opaque non-tokencage string but redacts it fully', () => {
  const wrapped = new TokenValue('opaque-value');
  assert.equal(wrapped.reveal(), 'opaque-value');
  assert.equal(String(wrapped), '[REDACTED]');
});

test('TokenValue redacts short secrets fully', () => {
  const wrapped = new TokenValue('abc');
  assert.equal(String(wrapped), '[REDACTED]');
  assert.equal(JSON.stringify(wrapped), '"[REDACTED]"');
});

test('redaction output does not include checksum tail beyond the selected secret suffix', () => {
  const details = mint();
  const checksumTail = details.token.slice(-4);
  const secretTail = secretOf(details.token).slice(-4);
  if (checksumTail !== secretTail) {
    assert.equal(redactToken(details.token).endsWith(checksumTail), false);
  }
  assert.equal(redactToken(details.token).endsWith(secretTail), true);
});
