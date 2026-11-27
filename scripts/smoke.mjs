import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bin = path.join(root, 'bin', 'tokencage.mjs');
const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'tokencage-smoke-'));

try {
  const token = execFileSync(process.execPath, [bin, 'generate', '--prefix', 'smoke', '--key-id'], { encoding: 'utf8' }).trim();
  if (!token.startsWith('smoke_')) throw new Error('CLI generate returned an unexpected token shape');
  execFileSync(process.execPath, [bin, 'inspect', token, '--prefix', 'smoke', '--key-id', '--json'], { encoding: 'utf8' });
  const configPath = path.join(scratch, 'config.json');
  fs.writeFileSync(configPath, JSON.stringify({
    prefix: 'smoke',
    bytes: 32,
    keyId: true,
    pepper: crypto.randomBytes(32).toString('base64url'),
    ttlMs: 3600000
  }));
  execFileSync(process.execPath, [bin, 'lint-config', '--config', configPath, '--json'], { encoding: 'utf8' });
  process.stdout.write('tokencage CLI smoke passed\n');
} finally {
  fs.rmSync(scratch, { recursive: true, force: true });
}
