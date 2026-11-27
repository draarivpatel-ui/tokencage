import test from 'node:test';
import assert from 'node:assert/strict';
import { esm, strongPepper, secondStrongPepper, mint } from './helpers.mjs';

const {
  createTokenVerifier,
  verifyAndRotate,
  createTokenCage,
  hashToken,
  generateTokenDetails,
  inspectToken,
  TokenCageError,
  CODE,
  RESULT_CODE
} = esm;

const pepperV1 = strongPepper();
const pepperV2 = secondStrongPepper();
const token = mint().token;

function rotatingVerifier() {
  return createTokenVerifier({
    currentVersion: 'v2',
    peppers: {
      v2: pepperV2,
      v1: pepperV1
    }
  });
}

test('verifier exposes current version and ordered version labels', () => {
  const verifier = rotatingVerifier();
  assert.equal(verifier.currentVersion, 'v2');
  assert.deepEqual(Array.from(verifier.versions), ['v2', 'v1']);
  assert.equal(verifier.hasVersion('v1'), true);
  assert.equal(verifier.hasVersion('missing'), false);
});

test('verifier object is frozen', () => {
  const verifier = rotatingVerifier();
  assert.equal(Object.isFrozen(verifier), true);
  assert.throws(() => {
    verifier.currentVersion = 'v3';
  }, TypeError);
});

test('verifier versions array cannot be usefully mutated', () => {
  const verifier = rotatingVerifier();
  assert.throws(() => {
    verifier.versions.push('v3');
  }, TypeError);
});

test('verifier does not expose pepper material in JSON', () => {
  const verifier = rotatingVerifier();
  const output = JSON.stringify(verifier);
  assert.equal(output.includes(pepperV1), false);
  assert.equal(output.includes(pepperV2), false);
});

test('verifier hash uses the current version', () => {
  const verifier = rotatingVerifier();
  assert.match(verifier.hash(token), /^tc1\$hmac-sha256\$v2\$/);
});

test('single pepper convenience config defaults to v1', () => {
  const verifier = createTokenVerifier({ pepper: pepperV1 });
  assert.equal(verifier.currentVersion, 'v1');
  assert.deepEqual(Array.from(verifier.versions), ['v1']);
});

test('single pepper convenience config honors explicit version', () => {
  const verifier = createTokenVerifier({ pepper: pepperV1, version: 'custom' });
  assert.equal(verifier.currentVersion, 'custom');
});

test('pepper entry list is accepted', () => {
  const verifier = createTokenVerifier({
    currentVersion: 'v2',
    peppers: [
      { version: 'v1', pepper: pepperV1 },
      { version: 'v2', pepper: pepperV2 }
    ]
  });
  assert.equal(verifier.hasVersion('v1'), true);
  assert.equal(verifier.hasVersion('v2'), true);
});

test('current version hash verifies without rehash', () => {
  const verifier = rotatingVerifier();
  const encoded = verifier.hash(token);
  const result = verifier.verifyAndRotate(token, encoded);
  assert.equal(result.valid, true);
  assert.equal(result.needsRehash, false);
  assert.equal(result.nextHash, null);
  assert.equal(result.version, 'v2');
});

test('retired version hash verifies and returns nextHash', () => {
  const verifier = rotatingVerifier();
  const oldHash = hashToken(token, { pepper: pepperV1, version: 'v1' });
  const result = verifier.verifyAndRotate(token, oldHash);
  assert.equal(result.valid, true);
  assert.equal(result.needsRehash, true);
  assert.equal(typeof result.nextHash, 'string');
  assert.match(result.nextHash, /^tc1\$hmac-sha256\$v2\$/);
  assert.equal(verifier.verify(token, result.nextHash), true);
});

test('rotation result includes key id and prefix for tokencage tokens', () => {
  const verifier = rotatingVerifier();
  const details = mint();
  const oldHash = hashToken(details.token, { pepper: pepperV1, version: 'v1' });
  const result = verifier.verifyAndRotate(details.token, oldHash);
  assert.equal(result.valid, true);
  assert.equal(result.keyId, details.keyId);
  assert.equal(result.prefix, details.prefix);
});

test('rotation still verifies opaque non-tokencage tokens with null metadata', () => {
  const verifier = rotatingVerifier();
  const opaque = 'opaque-session-value';
  const encoded = hashToken(opaque, { pepper: pepperV2, version: 'v2' });
  const result = verifier.verifyAndRotate(opaque, encoded);
  assert.equal(result.valid, true);
  assert.equal(result.keyId, null);
  assert.equal(result.prefix, null);
});

test('wrong token against retired hash is invalid and has no nextHash', () => {
  const verifier = rotatingVerifier();
  const oldHash = hashToken(token, { pepper: pepperV1, version: 'v1' });
  const result = verifier.verifyAndRotate(mint().token, oldHash);
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.HASH_MISMATCH);
  assert.equal(result.needsRehash, false);
  assert.equal(result.nextHash, null);
});

test('unknown version is invalid even when recomputed with a configured pepper', () => {
  const verifier = rotatingVerifier();
  const encoded = hashToken(token, { pepper: pepperV2, version: 'v9' });
  const result = verifier.verifyAndRotate(token, encoded);
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.UNKNOWN_KEY_VERSION);
  assert.equal(result.version, 'v9');
});

test('verify returns boolean false for unknown version', () => {
  const verifier = rotatingVerifier();
  const encoded = hashToken(token, { pepper: pepperV2, version: 'v9' });
  assert.equal(verifier.verify(token, encoded), false);
});

test('malformed encoded hash is invalid in rotation result', () => {
  const verifier = rotatingVerifier();
  const result = verifier.verifyAndRotate(token, 'not-a-hash');
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.INVALID_HASH);
});

test('scrypt hash is not accepted for pepper rotation', () => {
  const verifier = rotatingVerifier();
  const encoded = hashToken('492810', { algorithm: 'scrypt' });
  const result = verifier.verifyAndRotate('492810', encoded);
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.UNSUPPORTED_ALGORITHM);
});

for (const badToken of [null, undefined, '', 1, {}, []]) {
  test('rotation rejects invalid token input without throwing: ' + String(badToken), () => {
    const verifier = rotatingVerifier();
    const result = verifier.verifyAndRotate(badToken, verifier.hash(token));
    assert.equal(result.valid, false);
    assert.equal(result.code, RESULT_CODE.INVALID_INPUT);
  });
}

for (const [label, config] of [
  ['missing config', undefined],
  ['empty config', {}],
  ['pepper and peppers together', { pepper: pepperV1, peppers: { v1: pepperV1 } }],
  ['empty peppers object', { peppers: {} }],
  ['empty peppers array', { peppers: [] }],
  ['duplicate array versions', { peppers: [{ version: 'v1', pepper: pepperV1 }, { version: 'v1', pepper: pepperV2 }] }],
  ['missing current for multiple', { peppers: { v1: pepperV1, v2: pepperV2 } }],
  ['current not in map', { currentVersion: 'v3', peppers: { v1: pepperV1, v2: pepperV2 } }],
  ['weak retired pepper', { currentVersion: 'v2', peppers: { v1: 'weak', v2: pepperV2 } }],
  ['unknown key', { pepper: pepperV1, extra: true }],
  ['null config', null],
  ['array config', []]
]) {
  test('invalid verifier config rejected: ' + label, () => {
    assert.throws(() => createTokenVerifier(config), TokenCageError);
  });
}

test('standalone verifyAndRotate matches verifier behavior', () => {
  const encoded = hashToken(token, { pepper: pepperV1, version: 'v1' });
  const result = verifyAndRotate(token, encoded, {
    currentVersion: 'v2',
    peppers: { v1: pepperV1, v2: pepperV2 }
  });
  assert.equal(result.valid, true);
  assert.equal(result.needsRehash, true);
});

test('standalone verifyAndRotate requires valid config', () => {
  assert.throws(() => verifyAndRotate(token, 'tc1$hmac-sha256$v1$' + 'A'.repeat(43), {}), TokenCageError);
});

test('prototype-adjacent version labels do not mutate Object prototype', () => {
  const verifier = createTokenVerifier({
    currentVersion: 'constructor',
    peppers: [{ version: 'constructor', pepper: pepperV1 }]
  });
  const encoded = verifier.hash(token);
  assert.equal(verifier.verify(token, encoded), true);
  assert.equal({}.pepper, undefined);
});

test('createTokenCage generates inspectable tokens', () => {
  const cage = createTokenCage({ prefix: 'testapp', keyId: true, pepper: pepperV1 });
  const details = cage.generate();
  assert.equal(details.prefix, 'testapp');
  assert.equal(cage.inspect(details.token).valid, true);
  assert.equal(cage.isValidFormat(details.token), true);
});

test('createTokenCage enforces prefix expectation', () => {
  const cage = createTokenCage({ prefix: 'testapp', keyId: true, pepper: pepperV1 });
  const other = generateTokenDetails({ prefix: 'other', keyId: true });
  assert.equal(cage.inspect(other.token).valid, false);
});

test('createTokenCage hash and verify round trip', () => {
  const cage = createTokenCage({ prefix: 'testapp', keyId: true, pepper: pepperV1 });
  const details = cage.generate();
  const encoded = cage.hash(details.token);
  assert.equal(cage.verify(details.token, encoded), true);
  assert.equal(cage.verify(mint().token, encoded), false);
});

test('createTokenCage verifyAndRotate rejects wrong format before hash verification', () => {
  const cage = createTokenCage({ prefix: 'testapp', keyId: true, pepper: pepperV1 });
  const opaque = 'opaque-token';
  const encoded = hashToken(opaque, { pepper: pepperV1, version: 'v1' });
  const result = cage.verifyAndRotate(opaque, encoded);
  assert.equal(result.valid, false);
  assert.equal(result.code, RESULT_CODE.INVALID_FORMAT);
});

test('createTokenCage rotates a retired pepper', () => {
  const cage = createTokenCage({
    prefix: 'testapp',
    keyId: true,
    currentVersion: 'v2',
    peppers: { v1: pepperV1, v2: pepperV2 }
  });
  const details = cage.generate();
  const oldHash = hashToken(details.token, { pepper: pepperV1, version: 'v1' });
  const result = cage.verifyAndRotate(details.token, oldHash);
  assert.equal(result.valid, true);
  assert.equal(result.needsRehash, true);
});


test('generation-only cage can create and verify scrypt records without pepper configuration', () => {
  const cage = createTokenCage({ prefix: 'testapp' });
  const details = cage.generate();
  const record = cage.createRecord(details.token, { algorithm: 'scrypt' });
  const result = cage.verifyRecord(details.token, record);
  assert.equal(result.valid, true);
  assert.equal(result.needsRehash, false);
});

test('generation-only cage can generate and inspect but not hash', () => {
  const cage = createTokenCage({ prefix: 'testapp' });
  const details = cage.generate();
  assert.equal(cage.isValidFormat(details.token), true);
  assert.throws(() => cage.hash(details.token), (error) => error.code === CODE.CONFIGURATION);
});

test('createTokenCage generation overrides bytes inside the cage length bound', () => {
  const cage = createTokenCage({ prefix: 'testapp', bytes: 16, keyId: false });
  const details = cage.generate({ bytes: 24 });
  assert.equal(details.bytes, 24);
  assert.equal(details.hasKeyId, false);
  assert.equal(cage.inspect(details.token).valid, true);
});

test('createTokenCage rejects byte overrides outside the cage length bound', () => {
  const cage = createTokenCage({ prefix: 'testapp', bytes: 16, maxTokenLength: 64 });
  assert.throws(() => cage.generate({ bytes: 64 }), (error) => error.code === CODE.INVALID_OPTIONS);
});

test('createTokenCage rejects key id generation overrides', () => {
  const cage = createTokenCage({ prefix: 'testapp', bytes: 16, keyId: false });
  assert.throws(() => cage.generate({ keyId: true }), (error) => error.code === CODE.INVALID_OPTIONS);
});

test('createTokenCage rejects invalid generation override keys', () => {
  const cage = createTokenCage({ prefix: 'testapp' });
  assert.throws(() => cage.generate({ prefix: 'other' }), TokenCageError);
});

for (const [label, config] of [
  ['missing prefix', { pepper: pepperV1 }],
  ['invalid prefix', { prefix: 'Bad', pepper: pepperV1 }],
  ['vendor prefix', { prefix: 'npm', pepper: pepperV1 }],
  ['weak entropy', { prefix: 'testapp', bytes: 8, pepper: pepperV1 }],
  ['too small maxTokenLength', { prefix: 'testapp', maxTokenLength: 31, pepper: pepperV1 }],
  ['unknown key', { prefix: 'testapp', pepper: pepperV1, extra: true }]
]) {
  test('invalid cage config rejected: ' + label, () => {
    assert.throws(() => createTokenCage(config), TokenCageError);
  });
}

test('cage redact uses the cage format policy', () => {
  const cage = createTokenCage({ prefix: 'testapp', keyId: true });
  const details = cage.generate();
  assert.equal(cage.redact(details.token), details.redacted);
});
