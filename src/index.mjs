import crypto from 'node:crypto';

export const CODE = Object.freeze({
  INVALID_INPUT: 'ERR_TOKENCAGE_INVALID_INPUT',
  INVALID_OPTIONS: 'ERR_TOKENCAGE_INVALID_OPTIONS',
  INVALID_PREFIX: 'ERR_TOKENCAGE_INVALID_PREFIX',
  VENDOR_PREFIX: 'ERR_TOKENCAGE_VENDOR_PREFIX',
  INVALID_KEY_ID: 'ERR_TOKENCAGE_INVALID_KEY_ID',
  WEAK_ENTROPY: 'ERR_TOKENCAGE_WEAK_ENTROPY',
  WEAK_PEPPER: 'ERR_TOKENCAGE_WEAK_PEPPER',
  INVALID_TOKEN: 'ERR_TOKENCAGE_INVALID_TOKEN',
  INVALID_HASH: 'ERR_TOKENCAGE_INVALID_HASH',
  INVALID_RECORD: 'ERR_TOKENCAGE_INVALID_RECORD',
  LIMIT_EXCEEDED: 'ERR_TOKENCAGE_LIMIT_EXCEEDED',
  CONFIGURATION: 'ERR_TOKENCAGE_CONFIGURATION'
});

export const RESULT_CODE = Object.freeze({
  OK: 'ok',
  INVALID_INPUT: 'invalid-input',
  INVALID_FORMAT: 'invalid-format',
  INVALID_HASH: 'invalid-hash',
  HASH_MISMATCH: 'hash-mismatch',
  UNKNOWN_KEY_VERSION: 'unknown-key-version',
  UNSUPPORTED_ALGORITHM: 'unsupported-algorithm',
  INVALID_RECORD: 'invalid-record',
  REVOKED: 'revoked',
  EXPIRED: 'expired',
  NOT_YET_VALID: 'not-yet-valid',
  INSUFFICIENT_SCOPES: 'insufficient-scopes'
});

const BASE62_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const BASE62_BITS = Math.log2(62);
const BASE62_REJECTION_LIMIT = 248;
const CHECKSUM_LENGTH = 6;
const KEY_ID_LENGTH = 10;
const MIN_BYTES = 16;
const DEFAULT_BYTES = 32;
const MAX_BYTES = 64;
const MIN_SECRET_CHARS = Math.ceil((MIN_BYTES * 8) / BASE62_BITS);
const MAX_SECRET_CHARS = Math.ceil((MAX_BYTES * 8) / BASE62_BITS);
const DEFAULT_MAX_TOKEN_LENGTH = 256;
const MAX_TOKEN_LENGTH_LIMIT = 1024;
const MAX_SECRET_INPUT_LENGTH = 4096;
const MAX_HASH_INPUT_LENGTH = 4096;
const MAX_ENCODED_HASH_LENGTH = 512;
const DEFAULT_HEADER_MAX_LENGTH = 1024;
const MAX_HEADER_LENGTH = 8192;
const MIN_HEADER_LENGTH = 16;
const MAX_SCOPES = 64;
const MAX_SCOPE_LENGTH = 64;
const MAX_CLOCK_SKEW_MS = 300000;
const MAX_TTL_MS = 31536000000;
const MAX_PEPPER_BYTES = 256;
const MIN_PEPPER_BYTES = 32;
const MAX_PEPPER_VERSIONS = 32;
const HMAC_DIGEST_LENGTH = 32;
const SCRYPT_SALT_LENGTH = 16;
const SCRYPT_KEY_LENGTH = 32;
const SCRYPT_DEFAULTS = Object.freeze({ N: 16384, r: 8, p: 1 });
const SCRYPT_MAX_MEMORY_BYTES = 64 * 1024 * 1024;
const TOKEN68_RE = /^[A-Za-z0-9._~+/\-]+={0,2}$/;
const HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const VERSION_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;
const PREFIX_RE = /^[a-z][a-z0-9_]{1,23}$/;
const BASE62_RE = /^[0-9A-Za-z]+$/;
const SCOPE_RE = /^[a-z0-9][a-z0-9:._-]{0,63}$/;
const ISO_TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?(Z|([+-])(\d{2}):(\d{2}))$/;
const VENDOR_LIKE_PREFIXES = Object.freeze(['ghp', 'gho', 'sk_live', 'akia', 'xoxb', 'aiza', 'npm', 'pypi']);

const CRC32_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i += 1) {
  let value = i;
  for (let bit = 0; bit < 8; bit += 1) {
    value = (value & 1) ? ((value >>> 1) ^ 0xEDB88320) : (value >>> 1);
  }
  CRC32_TABLE[i] = value >>> 0;
}

export class TokenCageError extends Error {
  constructor(code, reason, details = {}) {
    super(reason);
    this.name = 'TokenCageError';
    this.code = code;
    this.reason = reason;
    if (details.field !== undefined) this.field = details.field;
    if (details.limit !== undefined) this.limit = details.limit;
    if (details.actual !== undefined) this.actual = details.actual;
  }

  toJSON() {
    const output = {
      name: this.name,
      code: this.code,
      reason: this.reason,
      message: this.message
    };
    if (this.field !== undefined) output.field = this.field;
    if (this.limit !== undefined) output.limit = this.limit;
    if (this.actual !== undefined) output.actual = this.actual;
    return output;
  }
}

function fail(code, reason, details) {
  throw new TokenCageError(code, reason, details);
}

function invalidInput(reason) {
  fail(CODE.INVALID_INPUT, reason);
}

function invalidOptions(reason, field) {
  fail(CODE.INVALID_OPTIONS, reason, field === undefined ? undefined : { field });
}

function isObjectLike(value) {
  return value !== null && (typeof value === 'object' || typeof value === 'function');
}

function optionsObject(options, label) {
  if (options === undefined) return {};
  if (!isObjectLike(options) || Array.isArray(options)) invalidInput(label + ' must be an object');
  return options;
}

function assertKnownKeys(options, allowedKeys) {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) invalidOptions('options contain an unknown key');
  }
  for (const key of allowed) {
    if (!Object.hasOwn(options, key) && key in options) {
      invalidOptions('options must use own properties rather than inherited properties', key);
    }
  }
}

function booleanValue(value, fallback, field) {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') invalidOptions(field + ' must be a boolean', field);
  return value;
}

function integerValue(value, fallback, min, max, field) {
  if (value === undefined) return fallback;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max) {
    invalidOptions(field + ' must be a safe integer in range', field);
  }
  return value;
}

function isBase62(text) {
  return BASE62_RE.test(text);
}

function crc32Ascii(text) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < text.length; i += 1) {
    crc = (CRC32_TABLE[(crc ^ text.charCodeAt(i)) & 0xFF] ^ (crc >>> 8)) >>> 0;
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function encodeBase62Uint32(value) {
  let remaining = value >>> 0;
  let output = '';
  do {
    output = BASE62_ALPHABET[remaining % 62] + output;
    remaining = Math.floor(remaining / 62);
  } while (remaining > 0);
  return output.padStart(CHECKSUM_LENGTH, '0');
}

function randomBase62(length) {
  let output = '';
  while (output.length < length) {
    const needed = length - output.length;
    const bytes = crypto.randomBytes(Math.max(16, needed * 2));
    for (const byte of bytes) {
      if (byte >= BASE62_REJECTION_LIMIT) continue;
      output += BASE62_ALPHABET[byte % 62];
      if (output.length === length) break;
    }
  }
  return output;
}

function randomKeyId() {
  for (let attempt = 0; attempt < 4096; attempt += 1) {
    const candidate = randomBase62(KEY_ID_LENGTH);
    if (/[A-Z]/.test(candidate)) return candidate;
  }
  fail(CODE.CONFIGURATION, 'unable to generate a canonical key id');
}

function checksumPayload(prefix, keyId, secret) {
  return 'tc1\n' + prefix + '\n' + (keyId === null ? '' : keyId) + '\n' + secret;
}

function tokenChecksum(prefix, keyId, secret) {
  return encodeBase62Uint32(crc32Ascii(checksumPayload(prefix, keyId, secret)));
}

function isVendorLikePrefix(prefix) {
  for (const vendor of VENDOR_LIKE_PREFIXES) {
    if (prefix === vendor || prefix.startsWith(vendor + '_')) return true;
  }
  return false;
}

export function validatePrefix(prefix, options) {
  const opts = optionsObject(options, 'prefix validation options');
  assertKnownKeys(opts, ['allowVendorLikePrefix']);
  const allowVendorLike = booleanValue(opts.allowVendorLikePrefix, false, 'allowVendorLikePrefix');
  if (typeof prefix !== 'string') {
    return { valid: false, code: 'invalid-type', reason: 'prefix must be a string', vendorLike: false, warnings: [] };
  }
  const vendorLike = isVendorLikePrefix(prefix);
  if (!PREFIX_RE.test(prefix) || prefix.endsWith('_') || prefix.includes('__')) {
    return { valid: false, code: 'invalid-format', reason: 'prefix must match lowercase ASCII token prefix rules', vendorLike, warnings: [] };
  }
  if (vendorLike && !allowVendorLike) {
    return { valid: false, code: 'vendor-prefix', reason: 'prefix resembles a third-party vendor token prefix', vendorLike, warnings: [] };
  }
  const warnings = vendorLike ? ['prefix resembles a third-party vendor token prefix'] : [];
  return { valid: true, code: 'ok', reason: 'ok', vendorLike, warnings };
}

function assertValidPrefix(prefix, allowVendorLikePrefix) {
  const result = validatePrefix(prefix, { allowVendorLikePrefix });
  if (result.valid) return result;
  if (result.code === 'vendor-prefix') fail(CODE.VENDOR_PREFIX, result.reason);
  fail(CODE.INVALID_PREFIX, result.reason);
}

export function validateKeyId(keyId) {
  if (typeof keyId !== 'string') {
    return { valid: false, code: 'invalid-type', reason: 'key id must be a string' };
  }
  if (keyId.length !== KEY_ID_LENGTH) {
    return { valid: false, code: 'invalid-length', reason: 'key id must be exactly 10 base62 characters' };
  }
  if (!isBase62(keyId)) {
    return { valid: false, code: 'invalid-character', reason: 'key id must contain only base62 characters' };
  }
  if (!/[A-Z]/.test(keyId)) {
    return { valid: false, code: 'non-canonical', reason: 'key id must contain at least one uppercase letter' };
  }
  return { valid: true, code: 'ok', reason: 'ok' };
}

function normalizeByteCount(value) {
  if (value === undefined) return DEFAULT_BYTES;
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value > MAX_BYTES) {
    invalidOptions('bytes must be a safe integer in range', 'bytes');
  }
  if (value < MIN_BYTES) {
    fail(CODE.WEAK_ENTROPY, 'token entropy is below the 128 bit floor', { field: 'bytes', limit: MIN_BYTES, actual: value });
  }
  return value;
}

function secretLengthForBytes(bytes) {
  return Math.ceil((bytes * 8) / BASE62_BITS);
}

function normalizeInspectOptions(options) {
  const opts = optionsObject(options, 'inspect options');
  assertKnownKeys(opts, ['prefix', 'keyId', 'maxLength', 'allowVendorLikePrefix']);
  let prefix;
  if (opts.prefix !== undefined) {
    const result = validatePrefix(opts.prefix, { allowVendorLikePrefix: true });
    if (!result.valid) invalidOptions('prefix expectation is not a valid token prefix', 'prefix');
    prefix = opts.prefix;
  }
  let keyId;
  if (opts.keyId !== undefined) {
    if (typeof opts.keyId !== 'boolean') invalidOptions('keyId must be a boolean', 'keyId');
    keyId = opts.keyId;
  }
  const maxLength = integerValue(opts.maxLength, DEFAULT_MAX_TOKEN_LENGTH, CHECKSUM_LENGTH + MIN_SECRET_CHARS + 3, MAX_TOKEN_LENGTH_LIMIT, 'maxLength');
  const allowVendorLikePrefix = booleanValue(opts.allowVendorLikePrefix, false, 'allowVendorLikePrefix');
  return { prefix, keyId, maxLength, allowVendorLikePrefix };
}

function inspectFailure(code, reason, length) {
  return {
    valid: false,
    code,
    reason,
    format: 'tokencage-v1',
    prefix: null,
    keyId: null,
    hasKeyId: false,
    secretLength: 0,
    entropyBits: 0,
    length,
    redacted: '[REDACTED]',
    warnings: [],
    secret: null
  };
}

function parseToken(token, options) {
  const opts = normalizeInspectOptions(options);
  if (typeof token !== 'string') return inspectFailure('invalid-type', 'token must be a string', 0);
  if (token.length > opts.maxLength) return inspectFailure('too-long', 'token exceeds the configured length bound', token.length);
  if (token.length === 0) return inspectFailure('invalid-shape', 'token is empty', 0);
  for (let i = 0; i < token.length; i += 1) {
    const code = token.charCodeAt(i);
    if (code < 33 || code > 126) return inspectFailure('invalid-character', 'token contains whitespace, control or non-ASCII characters', token.length);
  }
  const bodyStart = token.lastIndexOf('_');
  if (bodyStart <= 0 || bodyStart === token.length - 1) {
    return inspectFailure('invalid-shape', 'token does not contain a prefix and body separator', token.length);
  }
  const left = token.slice(0, bodyStart);
  const body = token.slice(bodyStart + 1);
  if (body.length < MIN_SECRET_CHARS + CHECKSUM_LENGTH || body.length > MAX_SECRET_CHARS + CHECKSUM_LENGTH) {
    return inspectFailure('invalid-shape', 'token body length is outside the supported range', token.length);
  }
  if (!isBase62(body)) {
    return inspectFailure('invalid-character', 'token body must contain only base62 characters', token.length);
  }
  const secret = body.slice(0, -CHECKSUM_LENGTH);
  const checksum = body.slice(-CHECKSUM_LENGTH);
  let prefix = left;
  let keyId = null;
  const keyIdSeparator = left.lastIndexOf('_');
  if (keyIdSeparator > 0) {
    const candidate = left.slice(keyIdSeparator + 1);
    const candidatePrefix = left.slice(0, keyIdSeparator);
    if (candidate.length === KEY_ID_LENGTH && isBase62(candidate) && /[A-Z]/.test(candidate)) {
      keyId = candidate;
      prefix = candidatePrefix;
    }
  }
  const hasKeyId = keyId !== null;
  const prefixResult = validatePrefix(prefix, { allowVendorLikePrefix: opts.allowVendorLikePrefix });
  if (!prefixResult.valid) {
    const failed = inspectFailure(prefixResult.code === 'vendor-prefix' ? 'vendor-prefix' : 'invalid-prefix', prefixResult.reason, token.length);
    failed.prefix = prefix;
    failed.keyId = keyId;
    failed.hasKeyId = hasKeyId;
    failed.secretLength = secret.length;
    failed.entropyBits = Math.floor(secret.length * BASE62_BITS);
    return failed;
  }
  if (opts.prefix !== undefined && prefix !== opts.prefix) {
    const failed = inspectFailure('prefix-mismatch', 'token prefix does not match the expected prefix', token.length);
    failed.prefix = prefix;
    failed.keyId = keyId;
    failed.hasKeyId = hasKeyId;
    failed.secretLength = secret.length;
    failed.entropyBits = Math.floor(secret.length * BASE62_BITS);
    return failed;
  }
  if (opts.keyId === true && !hasKeyId) {
    const failed = inspectFailure('key-id-missing', 'token does not carry a key id', token.length);
    failed.prefix = prefix;
    failed.secretLength = secret.length;
    failed.entropyBits = Math.floor(secret.length * BASE62_BITS);
    return failed;
  }
  if (opts.keyId === false && hasKeyId) {
    const failed = inspectFailure('key-id-unexpected', 'token carries an unexpected key id', token.length);
    failed.prefix = prefix;
    failed.keyId = keyId;
    failed.hasKeyId = true;
    failed.secretLength = secret.length;
    failed.entropyBits = Math.floor(secret.length * BASE62_BITS);
    return failed;
  }
  const expectedChecksum = tokenChecksum(prefix, keyId, secret);
  const actualBuffer = Buffer.from(checksum, 'ascii');
  const expectedBuffer = Buffer.from(expectedChecksum, 'ascii');
  const checksumMatches = actualBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(actualBuffer, expectedBuffer);
  const entropyBits = Math.floor(secret.length * BASE62_BITS);
  const output = {
    valid: checksumMatches,
    code: checksumMatches ? 'ok' : 'checksum-mismatch',
    reason: checksumMatches ? 'ok' : 'token checksum does not match its payload',
    format: 'tokencage-v1',
    prefix,
    keyId,
    hasKeyId,
    secretLength: secret.length,
    entropyBits,
    length: token.length,
    redacted: '[REDACTED]',
    warnings: prefixResult.warnings.slice(),
    secret
  };
  return output;
}

function redactParsed(parsed) {
  if (!parsed || !parsed.valid || typeof parsed.secret !== 'string' || parsed.secret.length < 12) return '[REDACTED]';
  const last4 = parsed.secret.slice(-4);
  if (parsed.hasKeyId) return parsed.prefix + '_' + parsed.keyId + '_...' + last4;
  return parsed.prefix + '_...' + last4;
}

function publicInspection(parsed) {
  return {
    valid: parsed.valid,
    code: parsed.code,
    reason: parsed.reason,
    format: parsed.format,
    prefix: parsed.prefix,
    keyId: parsed.keyId,
    hasKeyId: parsed.hasKeyId,
    secretLength: parsed.secretLength,
    entropyBits: parsed.entropyBits,
    length: parsed.length,
    redacted: redactParsed(parsed),
    warnings: parsed.warnings.slice()
  };
}

export function inspectToken(token, options) {
  return publicInspection(parseToken(token, options));
}

export function isValidTokenFormat(token, options) {
  return inspectToken(token, options).valid;
}

export function generateTokenDetails(options) {
  const opts = optionsObject(options, 'generate options');
  assertKnownKeys(opts, ['prefix', 'bytes', 'keyId', 'allowVendorLikePrefix']);
  if (opts.prefix === undefined) invalidOptions('prefix is required', 'prefix');
  const allowVendorLikePrefix = booleanValue(opts.allowVendorLikePrefix, false, 'allowVendorLikePrefix');
  const prefixResult = assertValidPrefix(opts.prefix, allowVendorLikePrefix);
  const bytes = normalizeByteCount(opts.bytes);
  const useKeyId = booleanValue(opts.keyId, false, 'keyId');
  const secretLength = secretLengthForBytes(bytes);
  const secret = randomBase62(secretLength);
  const keyId = useKeyId ? randomKeyId() : null;
  const checksum = tokenChecksum(opts.prefix, keyId, secret);
  const body = secret + checksum;
  const token = opts.prefix + '_' + (keyId === null ? '' : keyId + '_') + body;
  const parsed = parseToken(token, { allowVendorLikePrefix });
  const details = {
    token,
    prefix: opts.prefix,
    keyId,
    hasKeyId: useKeyId,
    bytes,
    secretLength,
    entropyBits: Math.floor(secretLength * BASE62_BITS),
    format: 'tokencage-v1',
    redacted: redactParsed(parsed),
    warnings: prefixResult.warnings.slice()
  };
  Object.defineProperty(details, Symbol.for('nodejs.util.inspect.custom'), {
    enumerable: false,
    value: () => ({ ...details, token: details.redacted })
  });
  return Object.freeze(details);
}

export function generateToken(options) {
  return generateTokenDetails(options).token;
}

function encodeBase64Url(buffer) {
  return Buffer.from(buffer).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64Url(text, expectedLength) {
  if (typeof text !== 'string' || text.length === 0 || !/^[A-Za-z0-9\-_]+$/.test(text)) return null;
  let base64 = text.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) base64 += '=';
  let decoded;
  try {
    decoded = Buffer.from(base64, 'base64');
  } catch {
    return null;
  }
  if (decoded.length !== expectedLength) return null;
  if (encodeBase64Url(decoded) !== text) return null;
  return decoded;
}

function byteLengthOfPepper(pepper) {
  if (typeof pepper === 'string') return Buffer.byteLength(pepper, 'utf8');
  if (pepper instanceof Uint8Array) return pepper.length;
  return 0;
}

function pepperToBuffer(pepper) {
  if (typeof pepper === 'string') return Buffer.from(pepper, 'utf8');
  if (pepper instanceof Uint8Array) return Buffer.from(pepper);
  return null;
}

function shannonEntropyBitsPerByte(buffer) {
  const counts = new Map();
  for (const byte of buffer) counts.set(byte, (counts.get(byte) || 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / buffer.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function mostlyPeriodic(buffer) {
  const maxPeriod = Math.min(16, Math.floor(buffer.length / 2));
  for (let period = 1; period <= maxPeriod; period += 1) {
    let same = 0;
    let total = 0;
    for (let i = period; i < buffer.length; i += 1) {
      total += 1;
      if (buffer[i] === buffer[i - period]) same += 1;
    }
    if (total > 0 && same / total > 0.95) return true;
  }
  return false;
}

function mostlySequential(buffer) {
  let sequential = 0;
  for (let i = 1; i < buffer.length; i += 1) {
    const diff = buffer[i] - buffer[i - 1];
    if (diff === 1 || diff === -1) sequential += 1;
  }
  return buffer.length > 1 && sequential / (buffer.length - 1) > 0.7;
}

function assessPepperBuffer(buffer) {
  const lengthBytes = buffer.length;
  const uniqueBytes = new Set(buffer).size;
  const entropyBitsPerByte = shannonEntropyBitsPerByte(buffer);
  const reasons = [];
  if (lengthBytes < MIN_PEPPER_BYTES) reasons.push('pepper is shorter than 32 bytes');
  if (lengthBytes > MAX_PEPPER_BYTES) reasons.push('pepper is longer than 256 bytes');
  if (uniqueBytes < 16) reasons.push('pepper does not contain enough distinct byte values');
  if (entropyBitsPerByte < 3) reasons.push('pepper byte distribution is too regular');
  if (mostlyPeriodic(buffer)) reasons.push('pepper is mostly repeating');
  if (mostlySequential(buffer)) reasons.push('pepper is mostly sequential');
  return {
    valid: reasons.length === 0,
    code: reasons.length === 0 ? 'ok' : 'weak-pepper',
    reason: reasons.length === 0 ? 'ok' : reasons[0],
    lengthBytes,
    entropyBitsPerByte: Math.round(entropyBitsPerByte * 100) / 100,
    uniqueBytes,
    warnings: []
  };
}

export function validatePepper(pepper) {
  if (byteLengthOfPepper(pepper) === 0) {
    return { valid: false, code: 'invalid-type', reason: 'pepper must be a string or byte array', lengthBytes: 0, entropyBitsPerByte: 0, uniqueBytes: 0, warnings: [] };
  }
  return assessPepperBuffer(pepperToBuffer(pepper));
}

function assertStrongPepper(pepper) {
  const buffer = pepperToBuffer(pepper);
  if (buffer === null) {
    fail(CODE.WEAK_PEPPER, 'pepper does not meet tokencage strength requirements');
  }
  const result = assessPepperBuffer(buffer);
  if (!result.valid) {
    fail(CODE.WEAK_PEPPER, 'pepper does not meet tokencage strength requirements');
  }
  return buffer;
}

function validateVersion(version, fallback) {
  if (version === undefined) {
    if (fallback !== undefined) return fallback;
    invalidOptions('version is required', 'version');
  }
  if (typeof version !== 'string' || !VERSION_RE.test(version)) {
    invalidOptions('version must be a safe version label', 'version');
  }
  return version;
}

function validateSecretInput(secret, label) {
  if (typeof secret !== 'string' || secret.length === 0) invalidInput(label + ' must be a non-empty string');
  if (secret.length > MAX_SECRET_INPUT_LENGTH) {
    fail(CODE.LIMIT_EXCEEDED, label + ' exceeds the input length bound', { limit: MAX_SECRET_INPUT_LENGTH, actual: secret.length });
  }
}

function safeSecretForVerify(secret) {
  return typeof secret === 'string' && secret.length > 0 && secret.length <= MAX_HASH_INPUT_LENGTH;
}

function validateScryptParams(params) {
  if (!Number.isSafeInteger(params.N) || params.N < 16384 || params.N > 65536 || (params.N & (params.N - 1)) !== 0) return false;
  if (!Number.isSafeInteger(params.r) || params.r < 8 || params.r > 16) return false;
  if (!Number.isSafeInteger(params.p) || params.p < 1 || params.p > 4) return false;
  return 128 * params.N * params.r * params.p <= SCRYPT_MAX_MEMORY_BYTES;
}

function normalizeScryptOptions(value) {
  if (value === undefined) return { ...SCRYPT_DEFAULTS };
  const opts = optionsObject(value, 'scrypt options');
  assertKnownKeys(opts, ['N', 'r', 'p']);
  const params = {
    N: integerValue(opts.N, SCRYPT_DEFAULTS.N, 1, Number.MAX_SAFE_INTEGER, 'scrypt.N'),
    r: integerValue(opts.r, SCRYPT_DEFAULTS.r, 1, Number.MAX_SAFE_INTEGER, 'scrypt.r'),
    p: integerValue(opts.p, SCRYPT_DEFAULTS.p, 1, Number.MAX_SAFE_INTEGER, 'scrypt.p')
  };
  if (!validateScryptParams(params)) {
    invalidOptions('scrypt parameters are below the hardened floor or above the memory ceiling', 'scrypt');
  }
  return params;
}

function scryptMaxMemory(params) {
  return Math.min(SCRYPT_MAX_MEMORY_BYTES + 1024 * 1024, 128 * params.N * params.r * params.p + 1024 * 1024);
}

function scryptDigestSync(secret, salt, params) {
  try {
    return crypto.scryptSync(secret, salt, SCRYPT_KEY_LENGTH, {
      N: params.N,
      r: params.r,
      p: params.p,
      maxmem: scryptMaxMemory(params)
    });
  } catch {
    fail(CODE.CONFIGURATION, 'scrypt key derivation failed');
  }
}

function scryptDigestAsync(secret, salt, params) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(secret, salt, SCRYPT_KEY_LENGTH, {
      N: params.N,
      r: params.r,
      p: params.p,
      maxmem: scryptMaxMemory(params)
    }, (error, derivedKey) => {
      if (error) {
        const wrapped = new TokenCageError(CODE.CONFIGURATION, 'scrypt key derivation failed');
        reject(wrapped);
        return;
      }
      resolve(derivedKey);
    });
  });
}

function normalizeHashOptions(options) {
  const opts = optionsObject(options, 'hash options');
  assertKnownKeys(opts, ['algorithm', 'pepper', 'version', 'scrypt']);
  const algorithm = opts.algorithm === undefined ? 'hmac-sha256' : opts.algorithm;
  if (algorithm !== 'hmac-sha256' && algorithm !== 'scrypt') invalidOptions('algorithm must be hmac-sha256 or scrypt', 'algorithm');
  if (algorithm === 'hmac-sha256') {
    if (opts.scrypt !== undefined) invalidOptions('scrypt options are not valid for hmac-sha256', 'scrypt');
    if (opts.pepper === undefined) invalidOptions('pepper is required for hmac-sha256', 'pepper');
    const pepper = assertStrongPepper(opts.pepper);
    const version = validateVersion(opts.version, 'v1');
    return { algorithm, pepper, version };
  }
  if (opts.pepper !== undefined) invalidOptions('pepper is not used by the scrypt format', 'pepper');
  if (opts.version !== undefined) invalidOptions('version is not used by the scrypt format', 'version');
  return { algorithm, scrypt: normalizeScryptOptions(opts.scrypt) };
}

function hmacSha256(secret, pepper) {
  return crypto.createHmac('sha256', pepper).update(secret, 'utf8').digest();
}

function hashTokenValidated(secret, normalized) {
  if (normalized.algorithm === 'hmac-sha256') {
    const digest = hmacSha256(secret, normalized.pepper);
    return 'tc1$hmac-sha256$' + normalized.version + '$' + encodeBase64Url(digest);
  }
  const salt = crypto.randomBytes(SCRYPT_SALT_LENGTH);
  const derived = scryptDigestSync(secret, salt, normalized.scrypt);
  const params = 'N=' + normalized.scrypt.N + ',r=' + normalized.scrypt.r + ',p=' + normalized.scrypt.p;
  return 'tc1$scrypt$' + params + '$' + encodeBase64Url(salt) + '$' + encodeBase64Url(derived);
}

async function hashTokenValidatedAsync(secret, normalized) {
  if (normalized.algorithm === 'hmac-sha256') return hashTokenValidated(secret, normalized);
  const salt = crypto.randomBytes(SCRYPT_SALT_LENGTH);
  const derived = await scryptDigestAsync(secret, salt, normalized.scrypt);
  const params = 'N=' + normalized.scrypt.N + ',r=' + normalized.scrypt.r + ',p=' + normalized.scrypt.p;
  return 'tc1$scrypt$' + params + '$' + encodeBase64Url(salt) + '$' + encodeBase64Url(derived);
}

export function hashToken(token, options) {
  validateSecretInput(token, 'token');
  return hashTokenValidated(token, normalizeHashOptions(options));
}

export async function hashTokenAsync(token, options) {
  validateSecretInput(token, 'token');
  return hashTokenValidatedAsync(token, normalizeHashOptions(options));
}

function parseEncodedHash(encodedHash) {
  if (typeof encodedHash !== 'string' || encodedHash.length === 0 || encodedHash.length > MAX_ENCODED_HASH_LENGTH) return null;
  const parts = encodedHash.split('$');
  if (parts[0] !== 'tc1') return null;
  if (parts.length === 4 && parts[1] === 'hmac-sha256') {
    if (!VERSION_RE.test(parts[2])) return null;
    const digest = decodeBase64Url(parts[3], HMAC_DIGEST_LENGTH);
    if (digest === null) return null;
    return { algorithm: 'hmac-sha256', version: parts[2], digest };
  }
  if (parts.length === 5 && parts[1] === 'scrypt') {
    const match = /^N=(\d+),r=(\d+),p=(\d+)$/.exec(parts[2]);
    if (!match) return null;
    const params = { N: Number(match[1]), r: Number(match[2]), p: Number(match[3]) };
    if (!validateScryptParams(params)) return null;
    const salt = decodeBase64Url(parts[3], SCRYPT_SALT_LENGTH);
    const digest = decodeBase64Url(parts[4], SCRYPT_KEY_LENGTH);
    if (salt === null || digest === null) return null;
    return { algorithm: 'scrypt', params, salt, digest };
  }
  return null;
}

function buffersEqualConstantTime(left, right) {
  if (!Buffer.isBuffer(left) || !Buffer.isBuffer(right) || left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function normalizeVerifierConfig(config) {
  const opts = optionsObject(config, 'verifier config');
  assertKnownKeys(opts, ['pepper', 'version', 'peppers', 'currentVersion']);
  const entries = [];
  if (opts.pepper !== undefined && opts.peppers !== undefined) invalidOptions('use either pepper or peppers, not both', 'peppers');
  if (opts.pepper !== undefined) {
    const version = validateVersion(opts.version, opts.currentVersion === undefined ? 'v1' : opts.currentVersion);
    entries.push({ version, pepper: opts.pepper });
  } else if (opts.peppers !== undefined) {
    if (Array.isArray(opts.peppers)) {
      if (opts.peppers.length === 0 || opts.peppers.length > MAX_PEPPER_VERSIONS) invalidOptions('peppers list is empty or too large', 'peppers');
      for (let index = 0; index < opts.peppers.length; index += 1) {
        if (!Object.hasOwn(opts.peppers, index)) invalidOptions('peppers list cannot contain holes or inherited entries', 'peppers');
        const item = optionsObject(opts.peppers[index], 'pepper entry');
        assertKnownKeys(item, ['version', 'pepper']);
        entries.push({ version: validateVersion(item.version), pepper: item.pepper });
      }
    } else {
      const map = optionsObject(opts.peppers, 'peppers');
      const versions = Object.keys(map);
      if (versions.length === 0 || versions.length > MAX_PEPPER_VERSIONS) invalidOptions('peppers map is empty or too large', 'peppers');
      for (const version of versions) {
        entries.push({ version: validateVersion(version), pepper: map[version] });
      }
    }
  } else {
    invalidOptions('a pepper or peppers map is required', 'peppers');
  }
  const seen = new Set();
  const pepperMap = new Map();
  for (const entry of entries) {
    if (seen.has(entry.version)) invalidOptions('pepper versions must be unique', 'peppers');
    seen.add(entry.version);
    pepperMap.set(entry.version, assertStrongPepper(entry.pepper));
  }
  let currentVersion = opts.currentVersion;
  if (currentVersion === undefined) {
    if (entries.length !== 1) invalidOptions('currentVersion is required when multiple peppers are configured', 'currentVersion');
    currentVersion = entries[0].version;
  }
  currentVersion = validateVersion(currentVersion);
  if (!pepperMap.has(currentVersion)) invalidOptions('currentVersion must exist in peppers', 'currentVersion');
  return {
    currentVersion,
    versions: Object.freeze(Array.from(pepperMap.keys())),
    pepperMap,
    currentPepper: pepperMap.get(currentVersion)
  };
}

function rotationResult(valid, reason, code, extra) {
  return {
    valid,
    reason,
    code,
    needsRehash: false,
    nextHash: null,
    keyId: null,
    prefix: null,
    version: null,
    ...extra
  };
}

function verifierVerifyAndRotate(normalized, token, encodedHash) {
  if (!safeSecretForVerify(token)) {
    return rotationResult(false, 'token is missing or exceeds the input length bound', RESULT_CODE.INVALID_INPUT);
  }
  const parsed = parseEncodedHash(encodedHash);
  if (parsed === null) {
    return rotationResult(false, 'encoded hash is malformed or unsupported', RESULT_CODE.INVALID_HASH);
  }
  if (parsed.algorithm !== 'hmac-sha256') {
    return rotationResult(false, 'pepper rotation applies only to hmac-sha256 records', RESULT_CODE.UNSUPPORTED_ALGORITHM, { version: null });
  }
  const pepper = normalized.pepperMap.get(parsed.version);
  const digest = hmacSha256(token, pepper === undefined ? normalized.currentPepper : pepper);
  const digestMatches = buffersEqualConstantTime(digest, parsed.digest);
  if (pepper === undefined) {
    return rotationResult(false, 'encoded hash uses an unknown key version', RESULT_CODE.UNKNOWN_KEY_VERSION, { version: parsed.version });
  }
  if (!digestMatches) {
    return rotationResult(false, 'token does not match the stored hash', RESULT_CODE.HASH_MISMATCH, { version: parsed.version });
  }
  const inspection = inspectToken(token);
  const needsRehash = parsed.version !== normalized.currentVersion;
  const nextHash = needsRehash
    ? 'tc1$hmac-sha256$' + normalized.currentVersion + '$' + encodeBase64Url(hmacSha256(token, normalized.currentPepper))
    : null;
  return rotationResult(true, 'ok', RESULT_CODE.OK, {
    needsRehash,
    nextHash,
    keyId: inspection.valid ? inspection.keyId : null,
    prefix: inspection.valid ? inspection.prefix : null,
    version: parsed.version
  });
}

export function createTokenVerifier(config) {
  const normalized = normalizeVerifierConfig(config);
  return Object.freeze({
    currentVersion: normalized.currentVersion,
    versions: normalized.versions,
    hasVersion(version) {
      return normalized.pepperMap.has(version);
    },
    hash(token) {
      validateSecretInput(token, 'token');
      return 'tc1$hmac-sha256$' + normalized.currentVersion + '$' + encodeBase64Url(hmacSha256(token, normalized.currentPepper));
    },
    verify(token, encodedHash) {
      return verifierVerifyAndRotate(normalized, token, encodedHash).valid;
    },
    verifyAndRotate(token, encodedHash) {
      return verifierVerifyAndRotate(normalized, token, encodedHash);
    }
  });
}

export function verifyAndRotate(token, encodedHash, config) {
  return createTokenVerifier(config).verifyAndRotate(token, encodedHash);
}

export function verifyTokenHash(token, encodedHash, options) {
  if (!safeSecretForVerify(token) || typeof encodedHash !== 'string') return false;
  const parsed = parseEncodedHash(encodedHash);
  if (parsed === null) return false;
  if (parsed.algorithm === 'scrypt') {
    const candidate = scryptDigestSync(token, parsed.salt, parsed.params);
    return buffersEqualConstantTime(candidate, parsed.digest);
  }
  const normalized = normalizeVerifierConfig(options);
  return verifierVerifyAndRotate(normalized, token, encodedHash).valid;
}

export async function verifyTokenHashAsync(token, encodedHash, options) {
  if (!safeSecretForVerify(token) || typeof encodedHash !== 'string') return false;
  const parsed = parseEncodedHash(encodedHash);
  if (parsed === null) return false;
  if (parsed.algorithm === 'scrypt') {
    const candidate = await scryptDigestAsync(token, parsed.salt, parsed.params);
    return buffersEqualConstantTime(candidate, parsed.digest);
  }
  const normalized = normalizeVerifierConfig(options);
  return verifierVerifyAndRotate(normalized, token, encodedHash).valid;
}

function normalizeScopes(scopes, field) {
  if (scopes === undefined) return [];
  if (!Array.isArray(scopes) || scopes.length > MAX_SCOPES) invalidOptions(field + ' must be an array within the scope count bound', field);
  const output = [];
  const seen = new Set();
  for (let index = 0; index < scopes.length; index += 1) {
    if (!Object.hasOwn(scopes, index)) invalidOptions(field + ' cannot contain holes or inherited entries', field);
    const scope = scopes[index];
    if (typeof scope !== 'string' || scope.length > MAX_SCOPE_LENGTH || !SCOPE_RE.test(scope)) {
      invalidOptions(field + ' contains an invalid scope', field);
    }
    if (!seen.has(scope)) {
      seen.add(scope);
      output.push(scope);
    }
  }
  return output;
}

export function hasScopes(recordScopes, requiredScopes) {
  if (!Array.isArray(recordScopes) || !Array.isArray(requiredScopes)) return false;
  const held = new Set();
  for (let index = 0; index < recordScopes.length; index += 1) {
    if (!Object.hasOwn(recordScopes, index)) return false;
    const scope = recordScopes[index];
    if (typeof scope !== 'string') return false;
    held.add(scope);
  }
  for (let index = 0; index < requiredScopes.length; index += 1) {
    if (!Object.hasOwn(requiredScopes, index)) return false;
    const scope = requiredScopes[index];
    if (typeof scope !== 'string' || !held.has(scope)) return false;
  }
  return true;
}

function strictIsoMs(value) {
  if (typeof value !== 'string') return null;
  const match = ISO_TIME_RE.exec(value);
  if (match === null) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const millisecond = match[7] === undefined ? 0 : Number(match[7].padEnd(3, '0'));
  if (year < 1970 || year > 2100 || month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || second > 59) return null;
  const utcMs = Date.UTC(year, month - 1, day, hour, minute, second, millisecond);
  const roundTrip = new Date(utcMs);
  if (
    roundTrip.getUTCFullYear() !== year ||
    roundTrip.getUTCMonth() !== month - 1 ||
    roundTrip.getUTCDate() !== day ||
    roundTrip.getUTCHours() !== hour ||
    roundTrip.getUTCMinutes() !== minute ||
    roundTrip.getUTCSeconds() !== second
  ) return null;
  let offsetMs = 0;
  if (match[8] !== 'Z') {
    const offsetHour = Number(match[10]);
    const offsetMinute = Number(match[11]);
    if (offsetHour > 23 || offsetMinute > 59) return null;
    offsetMs = (offsetHour * 60 + offsetMinute) * 60000;
    if (match[9] === '-') offsetMs = -offsetMs;
  }
  const ms = utcMs - offsetMs;
  return ms >= 0 && ms <= 4102444800000 ? ms : null;
}

function looseTimeMs(value, field) {
  if (value instanceof Date) {
    const ms = value.getTime();
    if (Number.isSafeInteger(ms) && ms >= 0 && ms <= 4102444800000) return ms;
    invalidOptions(field + ' must be a valid date', field);
  }
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= 4102444800000) return value;
  if (typeof value === 'string') {
    const ms = strictIsoMs(value);
    if (ms !== null) return ms;
  }
  invalidOptions(field + ' must be a valid date, timestamp or ISO time string', field);
}

function isoFromMs(ms) {
  return new Date(ms).toISOString();
}

function normalizeCreateRecordOptions(options) {
  const opts = optionsObject(options, 'record options');
  assertKnownKeys(opts, [
    'algorithm', 'pepper', 'version', 'scrypt', 'scopes', 'createdAt', 'now', 'expiresAt', 'ttlMs',
    'prefix', 'keyId', 'requireFormat', 'allowVendorLikePrefix'
  ]);
  const requireFormat = booleanValue(opts.requireFormat, true, 'requireFormat');
  let keyId;
  if (opts.keyId !== undefined) {
    if (typeof opts.keyId !== 'boolean') invalidOptions('keyId must be a boolean', 'keyId');
    keyId = opts.keyId;
  }
  const nowMs = opts.now === undefined ? Date.now() : looseTimeMs(opts.now, 'now');
  const createdMs = opts.createdAt === undefined ? nowMs : looseTimeMs(opts.createdAt, 'createdAt');
  if (createdMs > nowMs) invalidOptions('createdAt cannot be in the future', 'createdAt');
  let expiresMs = null;
  if (opts.expiresAt !== undefined && opts.expiresAt !== null && opts.ttlMs !== undefined) invalidOptions('use either expiresAt or ttlMs, not both', 'expiresAt');
  if (opts.expiresAt !== undefined && opts.expiresAt !== null) expiresMs = looseTimeMs(opts.expiresAt, 'expiresAt');
  if (opts.ttlMs !== undefined) {
    const ttlMs = integerValue(opts.ttlMs, undefined, 1, MAX_TTL_MS, 'ttlMs');
    expiresMs = createdMs + ttlMs;
  }
  if (expiresMs !== null && expiresMs <= createdMs) invalidOptions('expiresAt must be after createdAt', 'expiresAt');
  return {
    hashOptions: {
      algorithm: opts.algorithm,
      pepper: opts.pepper,
      version: opts.version,
      scrypt: opts.scrypt
    },
    scopes: normalizeScopes(opts.scopes, 'scopes'),
    createdMs,
    expiresMs,
    prefix: opts.prefix,
    keyId,
    requireFormat,
    allowVendorLikePrefix: booleanValue(opts.allowVendorLikePrefix, false, 'allowVendorLikePrefix')
  };
}

export function createTokenRecord(token, options) {
  validateSecretInput(token, 'token');
  const normalized = normalizeCreateRecordOptions(options);
  const inspectOptions = {
    prefix: normalized.prefix,
    keyId: normalized.keyId,
    allowVendorLikePrefix: normalized.allowVendorLikePrefix
  };
  const inspection = inspectToken(token, inspectOptions);
  if (normalized.requireFormat && !inspection.valid) {
    fail(CODE.INVALID_TOKEN, 'token does not satisfy tokencage format requirements');
  }
  const hashOptions = {};
  for (const key of ['algorithm', 'pepper', 'version', 'scrypt']) {
    if (normalized.hashOptions[key] !== undefined) hashOptions[key] = normalized.hashOptions[key];
  }
  const hash = hashToken(token, hashOptions);
  return {
    type: 'tokencage-record',
    version: 1,
    hash,
    prefix: inspection.valid ? inspection.prefix : null,
    keyId: inspection.valid ? inspection.keyId : null,
    scopes: normalized.scopes.slice(),
    createdAt: isoFromMs(normalized.createdMs),
    expiresAt: normalized.expiresMs === null ? null : isoFromMs(normalized.expiresMs),
    revokedAt: null,
    lastUsedAt: null
  };
}

const RECORD_KEYS = Object.freeze(['type', 'version', 'hash', 'prefix', 'keyId', 'scopes', 'createdAt', 'expiresAt', 'revokedAt', 'lastUsedAt']);

function normalizeStoredRecord(record) {
  if (!isObjectLike(record) || Array.isArray(record)) return { ok: false, reason: 'record must be an object' };
  for (const key of RECORD_KEYS) {
    if (!Object.hasOwn(record, key) && key in record) return { ok: false, reason: 'record fields must be own properties' };
  }
  for (const key of Object.keys(record)) {
    if (!RECORD_KEYS.includes(key)) return { ok: false, reason: 'record contains an unknown field' };
  }
  if (record.type !== 'tokencage-record' || record.version !== 1) return { ok: false, reason: 'record type or schema version is unsupported' };
  if (typeof record.hash !== 'string' || parseEncodedHash(record.hash) === null) return { ok: false, reason: 'record hash is malformed' };
  if (record.prefix !== null && (typeof record.prefix !== 'string' || !validatePrefix(record.prefix, { allowVendorLikePrefix: true }).valid)) return { ok: false, reason: 'record prefix is invalid' };
  if (record.keyId !== null && (typeof record.keyId !== 'string' || !validateKeyId(record.keyId).valid)) return { ok: false, reason: 'record key id is invalid' };
  if (record.keyId !== null && record.prefix === null) return { ok: false, reason: 'record key id cannot exist without a prefix' };
  if (!Array.isArray(record.scopes)) return { ok: false, reason: 'record scopes are invalid' };
  let scopes;
  try {
    scopes = normalizeScopes(record.scopes, 'record.scopes');
  } catch {
    return { ok: false, reason: 'record scopes are invalid' };
  }
  const createdMs = strictIsoMs(record.createdAt);
  if (createdMs === null) return { ok: false, reason: 'record createdAt is invalid' };
  let expiresMs = null;
  if (record.expiresAt !== null) {
    expiresMs = strictIsoMs(record.expiresAt);
    if (expiresMs === null) return { ok: false, reason: 'record expiresAt is invalid' };
    if (expiresMs <= createdMs) return { ok: false, reason: 'record expiry is not after creation' };
  }
  let revokedMs = null;
  if (record.revokedAt !== null) {
    revokedMs = strictIsoMs(record.revokedAt);
    if (revokedMs === null) return { ok: false, reason: 'record revokedAt is invalid' };
  }
  let lastUsedMs = null;
  if (record.lastUsedAt !== null) {
    lastUsedMs = strictIsoMs(record.lastUsedAt);
    if (lastUsedMs === null) return { ok: false, reason: 'record lastUsedAt is invalid' };
    if (lastUsedMs < createdMs) return { ok: false, reason: 'record lastUsedAt precedes creation' };
  }
  return {
    ok: true,
    record: {
      type: 'tokencage-record',
      version: 1,
      hash: record.hash,
      prefix: record.prefix,
      keyId: record.keyId,
      scopes,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      revokedAt: record.revokedAt,
      lastUsedAt: record.lastUsedAt
    },
    createdMs,
    expiresMs,
    revokedMs,
    lastUsedMs
  };
}

function recordResult(valid, reason, code, needsRehash, record, extra) {
  return {
    valid,
    reason,
    code,
    needsRehash,
    nextHash: null,
    keyId: null,
    prefix: null,
    record,
    ...extra
  };
}

function normalizeVerifyRecordOptions(options) {
  const opts = optionsObject(options, 'record verification options');
  assertKnownKeys(opts, [
    'pepper', 'version', 'peppers', 'currentVersion', 'requiredScopes', 'now', 'clockSkewMs',
    'prefix', 'keyId', 'requireFormat', 'allowVendorLikePrefix'
  ]);
  const clockSkewMs = integerValue(opts.clockSkewMs, 0, 0, MAX_CLOCK_SKEW_MS, 'clockSkewMs');
  const nowMs = opts.now === undefined ? Date.now() : looseTimeMs(opts.now, 'now');
  let keyId;
  if (opts.keyId !== undefined) {
    if (typeof opts.keyId !== 'boolean') invalidOptions('keyId must be a boolean', 'keyId');
    keyId = opts.keyId;
  }
  return {
    verifierConfig: {
      pepper: opts.pepper,
      version: opts.version,
      peppers: opts.peppers,
      currentVersion: opts.currentVersion
    },
    requiredScopes: normalizeScopes(opts.requiredScopes, 'requiredScopes'),
    nowMs,
    clockSkewMs,
    prefix: opts.prefix,
    keyId,
    requireFormat: booleanValue(opts.requireFormat, true, 'requireFormat'),
    allowVendorLikePrefix: booleanValue(opts.allowVendorLikePrefix, false, 'allowVendorLikePrefix')
  };
}

export function verifyTokenRecord(token, record, options) {
  const normalized = normalizeVerifyRecordOptions(options);
  if (!safeSecretForVerify(token)) {
    return recordResult(false, 'token is missing or exceeds the input length bound', RESULT_CODE.INVALID_INPUT, false, null);
  }
  const stored = normalizeStoredRecord(record);
  if (!stored.ok) {
    return recordResult(false, stored.reason, RESULT_CODE.INVALID_RECORD, false, null);
  }
  const safeRecord = {
    ...stored.record,
    scopes: stored.record.scopes.slice()
  };
  if (stored.revokedMs !== null) {
    return recordResult(false, 'token record has been revoked', RESULT_CODE.REVOKED, false, safeRecord);
  }
  if (normalized.nowMs < stored.createdMs - normalized.clockSkewMs) {
    return recordResult(false, 'token record creation time is beyond the clock skew bound', RESULT_CODE.NOT_YET_VALID, false, safeRecord);
  }
  if (stored.expiresMs !== null && normalized.nowMs >= stored.expiresMs + normalized.clockSkewMs) {
    return recordResult(false, 'token record has expired', RESULT_CODE.EXPIRED, false, safeRecord);
  }
  if (stored.lastUsedMs !== null && stored.lastUsedMs > normalized.nowMs + normalized.clockSkewMs) {
    return recordResult(false, 'record lastUsedAt is beyond the clock skew bound', RESULT_CODE.INVALID_RECORD, false, safeRecord);
  }
  if (!hasScopes(stored.record.scopes, normalized.requiredScopes)) {
    return recordResult(false, 'token record does not carry every required scope', RESULT_CODE.INSUFFICIENT_SCOPES, false, safeRecord);
  }
  const inspection = inspectToken(token, {
    prefix: normalized.prefix,
    keyId: normalized.keyId,
    allowVendorLikePrefix: normalized.allowVendorLikePrefix
  });
  if (normalized.requireFormat && !inspection.valid) {
    return recordResult(false, 'token does not satisfy tokencage format requirements', RESULT_CODE.INVALID_FORMAT, false, safeRecord);
  }
  const metadataMismatch = inspection.valid
    ? stored.record.prefix !== inspection.prefix || stored.record.keyId !== inspection.keyId
    : stored.record.prefix !== null || stored.record.keyId !== null;
  if (metadataMismatch) {
    return recordResult(false, 'record metadata does not match the presented token', RESULT_CODE.HASH_MISMATCH, false, safeRecord);
  }
  const parsedHash = parseEncodedHash(stored.record.hash);
  if (parsedHash.algorithm === 'scrypt') {
    const matches = verifyTokenHash(token, stored.record.hash);
    if (!matches) {
      return recordResult(false, 'token does not match the stored hash', RESULT_CODE.HASH_MISMATCH, false, safeRecord);
    }
    return recordResult(true, 'ok', RESULT_CODE.OK, false, safeRecord, {
      keyId: inspection.valid ? inspection.keyId : null,
      prefix: inspection.valid ? inspection.prefix : null
    });
  }
  const verifierConfig = {};
  for (const key of ['pepper', 'version', 'peppers', 'currentVersion']) {
    if (normalized.verifierConfig[key] !== undefined) verifierConfig[key] = normalized.verifierConfig[key];
  }
  const rotation = verifyAndRotate(token, stored.record.hash, verifierConfig);
  if (!rotation.valid) {
    return recordResult(false, rotation.reason, rotation.code, false, safeRecord);
  }
  return recordResult(true, 'ok', RESULT_CODE.OK, rotation.needsRehash, safeRecord, {
    nextHash: rotation.nextHash,
    keyId: inspection.valid ? inspection.keyId : rotation.keyId,
    prefix: inspection.valid ? inspection.prefix : rotation.prefix
  });
}

function normalizeHeaderOptions(options, extraKeys) {
  const opts = optionsObject(options, 'header extraction options');
  assertKnownKeys(opts, ['maxLength', ...extraKeys]);
  const maxLength = integerValue(opts.maxLength, DEFAULT_HEADER_MAX_LENGTH, MIN_HEADER_LENGTH, MAX_HEADER_LENGTH, 'maxLength');
  return { opts, maxLength };
}

function singleHeaderArrayValue(values) {
  if (values.length !== 1) fail(CODE.INVALID_INPUT, 'multiple credential header values are not accepted');
  if (!Object.hasOwn(values, 0)) invalidInput('credential header value cannot be inherited');
  return values[0];
}

function collectHeaderValue(input, name) {
  const wanted = name.toLowerCase();
  if (typeof input === 'string') return { present: true, value: input };
  if (Array.isArray(input)) {
    if (input.length === 0) return { present: false, value: null };
    const value = singleHeaderArrayValue(input);
    if (typeof value !== 'string') invalidInput('credential header value must be a string');
    return { present: true, value };
  }
  if (!isObjectLike(input)) invalidInput('headers must be a string, array, map or object');
  if (input instanceof Map) {
    let found;
    let count = 0;
    for (const [key, value] of input.entries()) {
      if (typeof key === 'string' && key.toLowerCase() === wanted) {
        count += 1;
        found = value;
      }
    }
    if (count > 1) fail(CODE.INVALID_INPUT, 'multiple credential headers are not accepted');
    if (count === 0 || found === undefined || found === null) return { present: false, value: null };
    if (Array.isArray(found)) {
      found = singleHeaderArrayValue(found);
    }
    if (typeof found !== 'string') invalidInput('credential header value must be a string');
    return { present: true, value: found };
  }
  if (typeof input.get === 'function' && Object.keys(input).length === 0) {
    const value = input.get(name);
    if (value === null || value === undefined) return { present: false, value: null };
    if (typeof value !== 'string') invalidInput('credential header value must be a string');
    return { present: true, value };
  }
  let found;
  let count = 0;
  for (const key of Object.keys(input)) {
    if (key.toLowerCase() === wanted) {
      count += 1;
      found = input[key];
    }
  }
  if (count > 1) fail(CODE.INVALID_INPUT, 'multiple credential headers are not accepted');
  if (count === 0 || found === undefined || found === null) return { present: false, value: null };
  if (Array.isArray(found)) {
    found = singleHeaderArrayValue(found);
  }
  if (typeof found !== 'string') invalidInput('credential header value must be a string');
  return { present: true, value: found };
}

function assertAsciiHeaderValue(value, maxLength) {
  if (value.length > maxLength) {
    fail(CODE.LIMIT_EXCEEDED, 'credential header exceeds the configured length bound', { limit: maxLength, actual: value.length });
  }
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 32 || code > 126) invalidInput('credential header contains control or non-ASCII characters');
  }
}

function validToken68(value) {
  if (!TOKEN68_RE.test(value)) return false;
  const firstEquals = value.indexOf('=');
  if (firstEquals !== -1) {
    for (let i = firstEquals; i < value.length; i += 1) {
      if (value[i] !== '=') return false;
    }
  }
  return true;
}

export function extractBearerToken(input, options) {
  const { maxLength } = normalizeHeaderOptions(options, []);
  const collected = collectHeaderValue(input, 'authorization');
  if (!collected.present) return null;
  const value = collected.value;
  assertAsciiHeaderValue(value, maxLength);
  if (value.length === 0) invalidInput('authorization header is empty');
  if (value.slice(0, 6).toLowerCase() !== 'bearer') return null;
  if (value.length === 6) invalidInput('bearer authorization header is missing a token');
  if (value[6] !== ' ') return null;
  let index = 6;
  while (index < value.length && value[index] === ' ') index += 1;
  const token = value.slice(index);
  if (token.length === 0) invalidInput('bearer authorization header is missing a token');
  if (!validToken68(token)) invalidInput('bearer token contains characters outside the RFC 6750 token68 syntax');
  return token;
}

export function extractApiKeyHeader(input, options) {
  const { opts, maxLength } = normalizeHeaderOptions(options, ['name']);
  const name = opts.name === undefined ? 'x-api-key' : opts.name;
  if (typeof name !== 'string' || name.length === 0 || name.length > 64 || !HEADER_NAME_RE.test(name)) {
    invalidOptions('API key header name is not a valid HTTP field name', 'name');
  }
  const collected = collectHeaderValue(input, name);
  if (!collected.present) return null;
  const value = collected.value;
  assertAsciiHeaderValue(value, maxLength);
  if (value.length === 0) invalidInput('API key header is empty');
  if (!validToken68(value)) invalidInput('API key header contains whitespace or characters outside the opaque token syntax');
  return value;
}

export function redactToken(token, options) {
  const parsed = parseToken(token, options);
  return redactParsed(parsed);
}

export function maskToken(token, options) {
  return redactToken(token, options);
}

export class TokenValue {
  #token;

  constructor(token) {
    validateSecretInput(token, 'token');
    this.#token = token;
    Object.freeze(this);
  }

  reveal() {
    return this.#token;
  }

  toString() {
    return redactToken(this.#token);
  }

  toJSON() {
    return this.toString();
  }

  valueOf() {
    return this.toString();
  }

  [Symbol.for('nodejs.util.inspect.custom')]() {
    return this.toString();
  }
}

export function createTokenValue(token) {
  return new TokenValue(token);
}

function verifierConfigFromNormalized(normalized) {
  const peppers = Object.create(null);
  for (const [version, pepper] of normalized.pepperMap.entries()) peppers[version] = pepper;
  return { peppers, currentVersion: normalized.currentVersion };
}

function rotationUnavailable() {
  fail(CODE.CONFIGURATION, 'this token cage was created without pepper configuration');
}

export function createTokenCage(config) {
  const opts = optionsObject(config, 'token cage config');
  assertKnownKeys(opts, ['prefix', 'bytes', 'keyId', 'allowVendorLikePrefix', 'maxTokenLength', 'pepper', 'version', 'peppers', 'currentVersion']);
  if (opts.prefix === undefined) invalidOptions('prefix is required', 'prefix');
  const allowVendorLikePrefix = booleanValue(opts.allowVendorLikePrefix, false, 'allowVendorLikePrefix');
  assertValidPrefix(opts.prefix, allowVendorLikePrefix);
  const bytes = normalizeByteCount(opts.bytes);
  const useKeyId = booleanValue(opts.keyId, false, 'keyId');
  const maxTokenLength = integerValue(opts.maxTokenLength, DEFAULT_MAX_TOKEN_LENGTH, CHECKSUM_LENGTH + MIN_SECRET_CHARS + 3, MAX_TOKEN_LENGTH_LIMIT, 'maxTokenLength');
  const generatedLength = opts.prefix.length + 1 + (useKeyId ? KEY_ID_LENGTH + 1 : 0) + secretLengthForBytes(bytes) + CHECKSUM_LENGTH;
  if (generatedLength > maxTokenLength) {
    invalidOptions('maxTokenLength is smaller than the token shape this cage generates', 'maxTokenLength');
  }
  const hasPepperConfig = opts.pepper !== undefined || opts.peppers !== undefined;
  let verifier = null;
  let verifierNormalized = null;
  if (hasPepperConfig) {
    verifierNormalized = normalizeVerifierConfig({
      pepper: opts.pepper,
      version: opts.version,
      peppers: opts.peppers,
      currentVersion: opts.currentVersion
    });
    verifier = createTokenVerifier(verifierConfigFromNormalized(verifierNormalized));
  }
  const inspectOptions = Object.freeze({
    prefix: opts.prefix,
    keyId: useKeyId,
    maxLength: maxTokenLength,
    allowVendorLikePrefix
  });
  return Object.freeze({
    prefix: opts.prefix,
    bytes,
    keyId: useKeyId,
    generate(overrides) {
      const overrideOptions = optionsObject(overrides, 'generate overrides');
      assertKnownKeys(overrideOptions, ['bytes']);
      const overrideBytes = overrideOptions.bytes === undefined ? bytes : normalizeByteCount(overrideOptions.bytes);
      const overrideLength = opts.prefix.length + 1 + (useKeyId ? KEY_ID_LENGTH + 1 : 0) + secretLengthForBytes(overrideBytes) + CHECKSUM_LENGTH;
      if (overrideLength > maxTokenLength) {
        invalidOptions('byte override exceeds the cage token length bound', 'bytes');
      }
      return generateTokenDetails({
        prefix: opts.prefix,
        bytes: overrideBytes,
        keyId: useKeyId,
        allowVendorLikePrefix
      });
    },
    inspect(token) {
      return inspectToken(token, inspectOptions);
    },
    isValidFormat(token) {
      return isValidTokenFormat(token, inspectOptions);
    },
    redact(token) {
      return redactToken(token, inspectOptions);
    },
    hash(token) {
      if (verifier === null) rotationUnavailable();
      return verifier.hash(token);
    },
    verify(token, encodedHash) {
      if (verifier === null) rotationUnavailable();
      return verifier.verify(token, encodedHash);
    },
    verifyAndRotate(token, encodedHash) {
      if (verifier === null) rotationUnavailable();
      const inspection = inspectToken(token, inspectOptions);
      if (!inspection.valid) {
        return rotationResult(false, 'token does not satisfy tokencage format requirements', RESULT_CODE.INVALID_FORMAT);
      }
      return verifier.verifyAndRotate(token, encodedHash);
    },
    createRecord(token, recordOptions) {
      const recordOpts = optionsObject(recordOptions, 'record options');
      const algorithm = !Object.hasOwn(recordOpts, 'algorithm') || recordOpts.algorithm === undefined ? 'hmac-sha256' : recordOpts.algorithm;
      const merged = { ...recordOpts, prefix: opts.prefix, keyId: useKeyId, allowVendorLikePrefix };
      if (algorithm === 'hmac-sha256') {
        if (verifierNormalized === null) rotationUnavailable();
        merged.pepper = verifierNormalized.currentPepper;
        merged.version = verifierNormalized.currentVersion;
      }
      return createTokenRecord(token, merged);
    },
    verifyRecord(token, record, recordOptions) {
      const merged = {
        ...(recordOptions === undefined ? {} : recordOptions),
        prefix: opts.prefix,
        keyId: useKeyId,
        allowVendorLikePrefix
      };
      const parsedHash = record && typeof record === 'object' && typeof record.hash === 'string' ? parseEncodedHash(record.hash) : null;
      if (parsedHash !== null && parsedHash.algorithm === 'hmac-sha256') {
        if (verifierNormalized === null) rotationUnavailable();
        Object.assign(merged, verifierConfigFromNormalized(verifierNormalized));
      }
      return verifyTokenRecord(token, record, merged);
    }
  });
}

const tokencage = Object.freeze({
  CODE,
  RESULT_CODE,
  TokenCageError,
  validatePrefix,
  validateKeyId,
  validatePepper,
  generateToken,
  generateTokenDetails,
  inspectToken,
  isValidTokenFormat,
  hashToken,
  hashTokenAsync,
  verifyTokenHash,
  verifyTokenHashAsync,
  createTokenVerifier,
  verifyAndRotate,
  createTokenRecord,
  verifyTokenRecord,
  hasScopes,
  redactToken,
  maskToken,
  TokenValue,
  createTokenValue,
  extractBearerToken,
  extractApiKeyHeader,
  createTokenCage
});

export default tokencage;
