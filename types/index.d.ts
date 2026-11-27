  export type PepperInput = string | Uint8Array;
  export type TimeInput = Date | number | string;
  export type HashAlgorithm = 'hmac-sha256' | 'scrypt';

  export interface TokenCageCodes {
    readonly INVALID_INPUT: 'ERR_TOKENCAGE_INVALID_INPUT';
    readonly INVALID_OPTIONS: 'ERR_TOKENCAGE_INVALID_OPTIONS';
    readonly INVALID_PREFIX: 'ERR_TOKENCAGE_INVALID_PREFIX';
    readonly VENDOR_PREFIX: 'ERR_TOKENCAGE_VENDOR_PREFIX';
    readonly INVALID_KEY_ID: 'ERR_TOKENCAGE_INVALID_KEY_ID';
    readonly WEAK_ENTROPY: 'ERR_TOKENCAGE_WEAK_ENTROPY';
    readonly WEAK_PEPPER: 'ERR_TOKENCAGE_WEAK_PEPPER';
    readonly INVALID_TOKEN: 'ERR_TOKENCAGE_INVALID_TOKEN';
    readonly INVALID_HASH: 'ERR_TOKENCAGE_INVALID_HASH';
    readonly INVALID_RECORD: 'ERR_TOKENCAGE_INVALID_RECORD';
    readonly LIMIT_EXCEEDED: 'ERR_TOKENCAGE_LIMIT_EXCEEDED';
    readonly CONFIGURATION: 'ERR_TOKENCAGE_CONFIGURATION';
  }

  export interface ResultCodes {
    readonly OK: 'ok';
    readonly INVALID_INPUT: 'invalid-input';
    readonly INVALID_FORMAT: 'invalid-format';
    readonly INVALID_HASH: 'invalid-hash';
    readonly HASH_MISMATCH: 'hash-mismatch';
    readonly UNKNOWN_KEY_VERSION: 'unknown-key-version';
    readonly UNSUPPORTED_ALGORITHM: 'unsupported-algorithm';
    readonly INVALID_RECORD: 'invalid-record';
    readonly REVOKED: 'revoked';
    readonly EXPIRED: 'expired';
    readonly NOT_YET_VALID: 'not-yet-valid';
    readonly INSUFFICIENT_SCOPES: 'insufficient-scopes';
  }

  export const CODE: TokenCageCodes;
  export const RESULT_CODE: ResultCodes;

  export class TokenCageError extends Error {
    readonly code: string;
    readonly reason: string;
    readonly field?: string;
    readonly limit?: number;
    readonly actual?: number;
    constructor(code: string, reason: string, details?: { field?: string; limit?: number; actual?: number });
    toJSON(): {
      name: string;
      code: string;
      reason: string;
      message: string;
      field?: string;
      limit?: number;
      actual?: number;
    };
  }

  export interface ValidationResult {
    valid: boolean;
    code: string;
    reason: string;
  }

  export interface PrefixValidationResult extends ValidationResult {
    vendorLike: boolean;
    warnings: string[];
  }

  export interface PepperValidationResult extends ValidationResult {
    lengthBytes: number;
    entropyBitsPerByte: number;
    uniqueBytes: number;
    warnings: string[];
  }

  export interface PrefixValidationOptions {
    allowVendorLikePrefix?: boolean;
  }

  export function validatePrefix(prefix: unknown, options?: PrefixValidationOptions): PrefixValidationResult;
  export function validateKeyId(keyId: unknown): ValidationResult;
  export function validatePepper(pepper: unknown): PepperValidationResult;

  export interface GenerateTokenOptions {
    prefix: string;
    bytes?: number;
    keyId?: boolean;
    allowVendorLikePrefix?: boolean;
  }

  export interface GeneratedTokenDetails {
    token: string;
    prefix: string;
    keyId: string | null;
    hasKeyId: boolean;
    bytes: number;
    secretLength: number;
    entropyBits: number;
    format: 'tokencage-v1';
    redacted: string;
    warnings: string[];
  }

  export function generateToken(options: GenerateTokenOptions): string;
  export function generateTokenDetails(options: GenerateTokenOptions): GeneratedTokenDetails;

  export interface InspectTokenOptions {
    prefix?: string;
    keyId?: boolean;
    maxLength?: number;
    allowVendorLikePrefix?: boolean;
  }

  export interface TokenInspection {
    valid: boolean;
    code: string;
    reason: string;
    format: 'tokencage-v1';
    prefix: string | null;
    keyId: string | null;
    hasKeyId: boolean;
    secretLength: number;
    entropyBits: number;
    length: number;
    redacted: string;
    warnings: string[];
  }

  export function inspectToken(token: unknown, options?: InspectTokenOptions): TokenInspection;
  export function isValidTokenFormat(token: unknown, options?: InspectTokenOptions): boolean;

  export interface ScryptOptions {
    N?: number;
    r?: number;
    p?: number;
  }

  export interface HmacHashTokenOptions {
    algorithm?: 'hmac-sha256';
    pepper: PepperInput;
    version?: string;
    scrypt?: never;
  }

  export interface ScryptHashTokenOptions {
    algorithm: 'scrypt';
    pepper?: never;
    version?: never;
    scrypt?: ScryptOptions;
  }

  export type HashTokenOptions = HmacHashTokenOptions | ScryptHashTokenOptions;

  export function hashToken(token: string, options: HashTokenOptions): string;
  export function hashTokenAsync(token: string, options: HashTokenOptions): Promise<string>;

  export interface PepperVersionEntry {
    version: string;
    pepper: PepperInput;
  }

  export interface TokenVerifierConfig {
    pepper?: PepperInput;
    version?: string;
    peppers?: Record<string, PepperInput> | PepperVersionEntry[];
    currentVersion?: string;
  }

  export interface VerifyTokenHashOptions extends TokenVerifierConfig {}

  export function verifyTokenHash(token: unknown, encodedHash: unknown, options?: VerifyTokenHashOptions): boolean;
  export function verifyTokenHashAsync(token: unknown, encodedHash: unknown, options?: VerifyTokenHashOptions): Promise<boolean>;

  export interface RotationResult {
    valid: boolean;
    reason: string;
    code: string;
    needsRehash: boolean;
    nextHash: string | null;
    keyId: string | null;
    prefix: string | null;
    version: string | null;
  }

  export interface TokenVerifier {
    readonly currentVersion: string;
    readonly versions: readonly string[];
    hasVersion(version: string): boolean;
    hash(token: string): string;
    verify(token: unknown, encodedHash: unknown): boolean;
    verifyAndRotate(token: unknown, encodedHash: unknown): RotationResult;
  }

  export function createTokenVerifier(config: TokenVerifierConfig): TokenVerifier;
  export function verifyAndRotate(token: unknown, encodedHash: unknown, config: TokenVerifierConfig): RotationResult;

  export interface TokenRecord {
    type: 'tokencage-record';
    version: 1;
    hash: string;
    prefix: string | null;
    keyId: string | null;
    scopes: string[];
    createdAt: string;
    expiresAt: string | null;
    revokedAt: string | null;
    lastUsedAt: string | null;
  }

  export interface TokenRecordOptionsBase {
    scopes?: string[];
    createdAt?: TimeInput;
    now?: TimeInput;
    expiresAt?: TimeInput | null;
    ttlMs?: number;
    prefix?: string;
    keyId?: boolean;
    requireFormat?: boolean;
    allowVendorLikePrefix?: boolean;
  }

  export type CreateTokenRecordOptions = TokenRecordOptionsBase & HashTokenOptions;

  export interface CageHmacCreateTokenRecordOptions extends TokenRecordOptionsBase {
    algorithm?: 'hmac-sha256';
    scrypt?: never;
  }

  export interface CageScryptCreateTokenRecordOptions extends TokenRecordOptionsBase {
    algorithm: 'scrypt';
    scrypt?: ScryptOptions;
  }

  export type CageCreateTokenRecordOptions = CageHmacCreateTokenRecordOptions | CageScryptCreateTokenRecordOptions;

  export function createTokenRecord(token: string, options: CreateTokenRecordOptions): TokenRecord;

  export interface VerifyTokenRecordOptions extends TokenVerifierConfig {
    requiredScopes?: string[];
    now?: TimeInput;
    clockSkewMs?: number;
    prefix?: string;
    keyId?: boolean;
    requireFormat?: boolean;
    allowVendorLikePrefix?: boolean;
  }

  export interface TokenRecordVerification {
    valid: boolean;
    reason: string;
    code: string;
    needsRehash: boolean;
    nextHash: string | null;
    keyId: string | null;
    prefix: string | null;
    record: TokenRecord | null;
  }

  export function verifyTokenRecord(token: unknown, record: unknown, options?: VerifyTokenRecordOptions): TokenRecordVerification;
  export function hasScopes(recordScopes: unknown, requiredScopes: unknown): boolean;

  export function redactToken(token: unknown, options?: InspectTokenOptions): string;
  export function maskToken(token: unknown, options?: InspectTokenOptions): string;

  export class TokenValue {
    constructor(token: string);
    reveal(): string;
    toString(): string;
    toJSON(): string;
    valueOf(): string;
  }

  export function createTokenValue(token: string): TokenValue;

  export interface ExtractHeaderOptions {
    maxLength?: number;
  }

  export interface ExtractApiKeyHeaderOptions extends ExtractHeaderOptions {
    name?: string;
  }

  export type HeaderInput = string | string[] | Record<string, unknown> | Map<string, unknown> | { get(name: string): string | null };

  export function extractBearerToken(input: HeaderInput, options?: ExtractHeaderOptions): string | null;
  export function extractApiKeyHeader(input: HeaderInput, options?: ExtractApiKeyHeaderOptions): string | null;

  export interface TokenCageConfig extends TokenVerifierConfig {
    prefix: string;
    bytes?: number;
    keyId?: boolean;
    allowVendorLikePrefix?: boolean;
    maxTokenLength?: number;
  }

  export interface GenerateOverrides {
    bytes?: number;
  }

  export interface TokenCage {
    readonly prefix: string;
    readonly bytes: number;
    readonly keyId: boolean;
    generate(overrides?: GenerateOverrides): GeneratedTokenDetails;
    inspect(token: unknown): TokenInspection;
    isValidFormat(token: unknown): boolean;
    redact(token: unknown): string;
    hash(token: string): string;
    verify(token: unknown, encodedHash: unknown): boolean;
    verifyAndRotate(token: unknown, encodedHash: unknown): RotationResult;
    createRecord(token: string, options?: CageCreateTokenRecordOptions): TokenRecord;
    verifyRecord(token: unknown, record: unknown, options?: VerifyTokenRecordOptions): TokenRecordVerification;
  }

  export function createTokenCage(config: TokenCageConfig): TokenCage;

  export interface TokenCageApi {
    readonly CODE: TokenCageCodes;
    readonly RESULT_CODE: ResultCodes;
    readonly TokenCageError: typeof TokenCageError;
    readonly validatePrefix: typeof validatePrefix;
    readonly validateKeyId: typeof validateKeyId;
    readonly validatePepper: typeof validatePepper;
    readonly generateToken: typeof generateToken;
    readonly generateTokenDetails: typeof generateTokenDetails;
    readonly inspectToken: typeof inspectToken;
    readonly isValidTokenFormat: typeof isValidTokenFormat;
    readonly hashToken: typeof hashToken;
    readonly hashTokenAsync: typeof hashTokenAsync;
    readonly verifyTokenHash: typeof verifyTokenHash;
    readonly verifyTokenHashAsync: typeof verifyTokenHashAsync;
    readonly createTokenVerifier: typeof createTokenVerifier;
    readonly verifyAndRotate: typeof verifyAndRotate;
    readonly createTokenRecord: typeof createTokenRecord;
    readonly verifyTokenRecord: typeof verifyTokenRecord;
    readonly hasScopes: typeof hasScopes;
    readonly redactToken: typeof redactToken;
    readonly maskToken: typeof maskToken;
    readonly TokenValue: typeof TokenValue;
    readonly createTokenValue: typeof createTokenValue;
    readonly extractBearerToken: typeof extractBearerToken;
    readonly extractApiKeyHeader: typeof extractApiKeyHeader;
    readonly createTokenCage: typeof createTokenCage;
  }

  const tokencage: TokenCageApi;
  export default tokencage;
