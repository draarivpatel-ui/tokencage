import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const esm = await import('../src/index.mjs');
const require = createRequire(import.meta.url);
export const cjs = require('../dist/index.cjs');
export const MODULES = Object.freeze([
  ['esm', esm],
  ['cjs', cjs]
]);

export function strongPepper() {
  return crypto.randomBytes(32).toString('base64url');
}

export function secondStrongPepper() {
  return crypto.randomBytes(32).toString('base64url');
}

export function mint(module = esm, options = {}) {
  return module.generateTokenDetails({ prefix: 'testapp', keyId: true, ...options });
}

export function flipChar(text, index) {
  const alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  const current = text[index];
  const replacement = alphabet[(alphabet.indexOf(current) + 1) % alphabet.length];
  return text.slice(0, index) + replacement + text.slice(index + 1);
}

export function runCli(args, options = {}) {
  const { spawnSync } = require('node:child_process');
  return spawnSync(process.execPath, [path.join(root, 'bin', 'tokencage.mjs'), ...args], {
    cwd: root,
    encoding: 'utf8',
    ...options
  });
}
