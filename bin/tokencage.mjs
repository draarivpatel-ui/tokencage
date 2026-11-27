#!/usr/bin/env node

import fs from 'node:fs';
import {
  generateTokenDetails,
  inspectToken,
  validatePrefix,
  validatePepper,
  TokenCageError
} from '../src/index.mjs';

const usage = `Usage:
  tokencage generate --prefix <p> [--bytes 32] [--key-id] [--json]
  tokencage inspect <token> [--prefix <p>] [--key-id|--no-key-id] [--json] [--show-prefix-only]
  tokencage lint-config --config <file.json> [--json]
  tokencage --version
  tokencage --help`;

function printUsage(stream) {
  stream.write(usage + '\n');
}

function exitUsage(message) {
  process.stderr.write('error: ' + message + '\n');
  printUsage(process.stderr);
  process.exit(2);
}

function parseArgs(args, booleanFlags, valueFlags) {
  const flags = new Map();
  const positional = [];
  for (let i = 0; i < args.length; i += 1) {
    const arg = args[i];
    if (!arg.startsWith('-')) {
      positional.push(arg);
      continue;
    }
    if (booleanFlags.includes(arg)) {
      flags.set(arg, true);
      continue;
    }
    if (valueFlags.includes(arg)) {
      if (i + 1 >= args.length || args[i + 1].startsWith('-')) exitUsage(arg + ' requires a value');
      flags.set(arg, args[i + 1]);
      i += 1;
      continue;
    }
    exitUsage('unknown option ' + arg);
  }
  return { flags, positional };
}

function writeJson(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

function safeError(error) {
  if (error instanceof TokenCageError) return error.reason;
  if (error instanceof Error) return error.message;
  return 'operation failed';
}

function parseBytes(value) {
  if (value === undefined) return undefined;
  if (!/^\d+$/.test(value)) exitUsage('--bytes must be a positive integer');
  return Number(value);
}

function commandGenerate(args) {
  const { flags, positional } = parseArgs(
    args,
    ['--key-id', '--json', '--allow-vendor-like-prefix'],
    ['--prefix', '--bytes']
  );
  if (positional.length !== 0) exitUsage('generate does not accept positional arguments');
  const prefix = flags.get('--prefix');
  if (prefix === undefined) exitUsage('generate requires --prefix');
  try {
    const details = generateTokenDetails({
      prefix,
      bytes: parseBytes(flags.get('--bytes')),
      keyId: flags.has('--key-id'),
      allowVendorLikePrefix: flags.has('--allow-vendor-like-prefix')
    });
    if (flags.has('--json')) {
      writeJson(details);
    } else {
      process.stdout.write(details.token + '\n');
    }
  } catch (error) {
    process.stderr.write('error: ' + safeError(error) + '\n');
    process.exit(1);
  }
}

function commandInspect(args) {
  const { flags, positional } = parseArgs(
    args,
    ['--json', '--show-prefix-only', '--key-id', '--no-key-id', '--allow-vendor-like-prefix'],
    ['--prefix']
  );
  if (positional.length !== 1) exitUsage('inspect requires exactly one token argument');
  if (flags.has('--key-id') && flags.has('--no-key-id')) exitUsage('use only one of --key-id or --no-key-id');
  try {
    const result = inspectToken(positional[0], {
      prefix: flags.get('--prefix'),
      keyId: flags.has('--key-id') ? true : flags.has('--no-key-id') ? false : undefined,
      allowVendorLikePrefix: flags.has('--allow-vendor-like-prefix')
    });
    if (flags.has('--json')) {
      writeJson(result);
    } else if (flags.has('--show-prefix-only')) {
      if (result.valid && result.prefix !== null) process.stdout.write(result.prefix + '\n');
    } else {
      process.stdout.write('valid: ' + (result.valid ? 'yes' : 'no') + '\n');
      process.stdout.write('prefix: ' + (result.prefix === null ? 'unknown' : result.prefix) + '\n');
      process.stdout.write('key id: ' + (result.keyId === null ? 'none' : result.keyId) + '\n');
      process.stdout.write('redacted: ' + result.redacted + '\n');
      process.stdout.write('entropy bits: ' + result.entropyBits + '\n');
      process.stdout.write('reason: ' + result.reason + '\n');
    }
    process.exit(result.valid ? 0 : 1);
  } catch (error) {
    process.stderr.write('error: ' + safeError(error) + '\n');
    process.exit(1);
  }
}

function finding(level, field, code, message) {
  return { level, field, code, message };
}

function auditPepperValue(findings, pepper, field) {
  const result = validatePepper(pepper);
  if (!result.valid) {
    findings.push(finding('error', field, result.code, 'pepper does not meet tokencage strength requirements'));
  }
}

function auditPeppers(findings, peppers) {
  if (Array.isArray(peppers)) {
    if (peppers.length === 0) findings.push(finding('error', 'peppers', 'empty-peppers', 'peppers list is empty'));
    if (peppers.length > 32) findings.push(finding('error', 'peppers', 'too-many-peppers', 'peppers list is too large'));
    const seen = new Set();
    peppers.forEach((entry, index) => {
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
        findings.push(finding('error', 'peppers.' + index, 'invalid-entry', 'pepper entry must be an object'));
        return;
      }
      if (typeof entry.version !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(entry.version)) {
        findings.push(finding('error', 'peppers.' + index + '.version', 'invalid-version', 'pepper version label is invalid'));
      } else if (seen.has(entry.version)) {
        findings.push(finding('error', 'peppers.' + index + '.version', 'duplicate-version', 'pepper versions must be unique'));
      } else {
        seen.add(entry.version);
      }
      auditPepperValue(findings, entry.pepper, 'peppers.' + index + '.pepper');
    });
    return;
  }
  if (peppers === null || typeof peppers !== 'object') {
    findings.push(finding('error', 'peppers', 'invalid-type', 'peppers must be an object or a list'));
    return;
  }
  const versions = Object.keys(peppers);
  if (versions.length === 0) findings.push(finding('error', 'peppers', 'empty-peppers', 'peppers map is empty'));
  if (versions.length > 32) findings.push(finding('error', 'peppers', 'too-many-peppers', 'peppers map is too large'));
  for (const version of versions) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(version)) {
      findings.push(finding('error', 'peppers', 'invalid-version', 'pepper version label is invalid'));
    }
    auditPepperValue(findings, peppers[version], 'peppers.' + version);
  }
}

function auditConfig(config) {
  const findings = [];
  if (config === null || typeof config !== 'object' || Array.isArray(config)) {
    findings.push(finding('error', 'config', 'invalid-type', 'configuration must be a JSON object'));
    return findings;
  }
  const allowed = new Set([
    'prefix', 'bytes', 'keyId', 'allowVendorLikePrefix', 'maxTokenLength',
    'pepper', 'version', 'peppers', 'currentVersion', 'expiresInSeconds', 'ttlMs'
  ]);
  for (const key of Object.keys(config)) {
    if (!allowed.has(key)) findings.push(finding('warning', key, 'unknown-key', 'configuration key is not recognized'));
  }
  if (typeof config.prefix !== 'string') {
    findings.push(finding('error', 'prefix', 'missing-prefix', 'prefix is required'));
  } else {
    const prefixResult = validatePrefix(config.prefix, { allowVendorLikePrefix: config.allowVendorLikePrefix === true });
    if (!prefixResult.valid) {
      findings.push(finding('error', 'prefix', prefixResult.code, prefixResult.reason));
    }
    for (const warning of prefixResult.warnings) {
      findings.push(finding('warning', 'prefix', 'vendor-like-prefix', warning));
    }
  }
  if (config.bytes !== undefined) {
    if (!Number.isSafeInteger(config.bytes) || config.bytes < 16 || config.bytes > 64) {
      findings.push(finding('error', 'bytes', 'invalid-entropy', 'bytes must be an integer from 16 through 64'));
    }
  }
  if (config.keyId !== undefined && typeof config.keyId !== 'boolean') {
    findings.push(finding('error', 'keyId', 'invalid-type', 'keyId must be a boolean'));
  }
  if (config.allowVendorLikePrefix !== undefined && typeof config.allowVendorLikePrefix !== 'boolean') {
    findings.push(finding('error', 'allowVendorLikePrefix', 'invalid-type', 'allowVendorLikePrefix must be a boolean'));
  }
  if (config.maxTokenLength !== undefined) {
    if (!Number.isSafeInteger(config.maxTokenLength) || config.maxTokenLength < 31 || config.maxTokenLength > 1024) {
      findings.push(finding('error', 'maxTokenLength', 'invalid-bound', 'maxTokenLength must be an integer from 31 through 1024'));
    }
  }
  if (config.pepper !== undefined) auditPepperValue(findings, config.pepper, 'pepper');
  if (config.peppers !== undefined) auditPeppers(findings, config.peppers);
  if (config.pepper !== undefined && config.peppers !== undefined) {
    findings.push(finding('error', 'peppers', 'duplicate-pepper-config', 'use either pepper or peppers, not both'));
  }
  if (config.pepper === undefined && config.peppers === undefined) {
    findings.push(finding('warning', 'pepper', 'missing-pepper', 'no pepper was audited; generation-only configs do not need one'));
  }
  if (config.version !== undefined && (typeof config.version !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(config.version))) {
    findings.push(finding('error', 'version', 'invalid-version', 'version label is invalid'));
  }
  if (config.currentVersion !== undefined && (typeof config.currentVersion !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(config.currentVersion))) {
    findings.push(finding('error', 'currentVersion', 'invalid-version', 'currentVersion label is invalid'));
  }
  const versionLabelValid = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/.test(value);
  const pepperVersions = [];
  if (Array.isArray(config.peppers)) {
    for (const entry of config.peppers) {
      if (entry !== null && typeof entry === 'object' && !Array.isArray(entry) && versionLabelValid(entry.version)) pepperVersions.push(entry.version);
    }
  } else if (config.peppers !== null && typeof config.peppers === 'object' && config.peppers !== undefined) {
    pepperVersions.push(...Object.keys(config.peppers).filter(versionLabelValid));
  }
  const uniquePepperVersions = new Set(pepperVersions);
  if (config.peppers !== undefined && uniquePepperVersions.size > 1 && config.currentVersion === undefined) {
    findings.push(finding('error', 'currentVersion', 'missing-current-version', 'currentVersion is required when multiple peppers are configured'));
  }
  if (config.peppers !== undefined && versionLabelValid(config.currentVersion) && !uniquePepperVersions.has(config.currentVersion)) {
    findings.push(finding('error', 'currentVersion', 'unknown-current-version', 'currentVersion must exist in peppers'));
  }
  if (config.pepper !== undefined && versionLabelValid(config.version) && versionLabelValid(config.currentVersion) && config.version !== config.currentVersion) {
    findings.push(finding('error', 'currentVersion', 'version-mismatch', 'version and currentVersion disagree for a single pepper'));
  }
  const bytesForShape = config.bytes === undefined ? 32 : config.bytes;
  if (typeof config.prefix === 'string' && Number.isSafeInteger(bytesForShape) && bytesForShape >= 16 && bytesForShape <= 64 && Number.isSafeInteger(config.maxTokenLength)) {
    const secretLength = Math.ceil((bytesForShape * 8) / Math.log2(62));
    const generatedLength = config.prefix.length + 1 + (config.keyId === true ? 11 : 0) + secretLength + 6;
    if (generatedLength > config.maxTokenLength) {
      findings.push(finding('error', 'maxTokenLength', 'length-too-small', 'maxTokenLength is smaller than the configured generated token shape'));
    }
  }
  for (const field of ['expiresInSeconds', 'ttlMs']) {
    if (config[field] === undefined) continue;
    const value = config[field];
    const valid = field === 'expiresInSeconds'
      ? Number.isSafeInteger(value) && value > 0 && value <= 31536000
      : Number.isSafeInteger(value) && value > 0 && value <= 31536000000;
    if (!valid) {
      findings.push(finding('error', field, 'invalid-expiry', field + ' must be a positive bounded integer'));
      continue;
    }
    const seconds = field === 'expiresInSeconds' ? value : Math.floor(value / 1000);
    if (seconds > 7776000) {
      findings.push(finding('warning', field, 'long-expiry', 'token lifetime is longer than 90 days'));
    }
  }
  if (config.expiresInSeconds !== undefined && config.ttlMs !== undefined) {
    findings.push(finding('error', 'expiresInSeconds', 'duplicate-expiry', 'use only one expiry field'));
  }
  return findings;
}

function commandLintConfig(args) {
  const { flags, positional } = parseArgs(args, ['--json'], ['--config']);
  if (positional.length !== 0) exitUsage('lint-config does not accept positional arguments');
  const configPath = flags.get('--config');
  if (configPath === undefined) exitUsage('lint-config requires --config');
  let config;
  try {
    const text = fs.readFileSync(configPath, 'utf8');
    if (text.length > 1048576) throw new Error('configuration file exceeds 1 MiB');
    config = JSON.parse(text);
  } catch (error) {
    process.stderr.write('error: unable to read or parse configuration\n');
    process.exit(1);
  }
  const findings = auditConfig(config);
  const errors = findings.filter((item) => item.level === 'error').length;
  const warnings = findings.filter((item) => item.level === 'warning').length;
  if (flags.has('--json')) {
    writeJson({ valid: errors === 0, errors, warnings, findings });
  } else {
    process.stdout.write('valid: ' + (errors === 0 ? 'yes' : 'no') + '\n');
    process.stdout.write('errors: ' + errors + '\n');
    process.stdout.write('warnings: ' + warnings + '\n');
    for (const item of findings) {
      process.stdout.write(item.level + ' ' + item.field + ': ' + item.message + '\n');
    }
  }
  process.exit(errors === 0 ? 0 : 1);
}

const args = process.argv.slice(2);
const command = args[0];
if (command === '--help' || command === '-h' || command === undefined) {
  printUsage(process.stdout);
  process.exit(0);
}
if (command === '--version' || command === '-v') {
  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  process.stdout.write('tokencage ' + pkg.version + '\n');
  process.exit(0);
}
if (command === 'generate') commandGenerate(args.slice(1));
else if (command === 'inspect') commandInspect(args.slice(1));
else if (command === 'lint-config') commandLintConfig(args.slice(1));
else exitUsage('unknown command ' + command);
