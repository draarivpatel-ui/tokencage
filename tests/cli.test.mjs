import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { runCli, mint, root } from './helpers.mjs';

const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'tokencage-cli-test-'));
after(() => {
  fs.rmSync(scratch, { recursive: true, force: true });
});

function writeConfig(name, value) {
  const file = path.join(scratch, name);
  fs.writeFileSync(file, JSON.stringify(value));
  return file;
}

test('CLI help exits zero and prints usage', () => {
  const result = runCli(['--help']);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /tokencage generate/);
  assert.match(result.stdout, /tokencage inspect/);
  assert.match(result.stdout, /lint-config/);
  assert.equal(result.stderr, '');
});

test('CLI with no command prints help and exits zero', () => {
  const result = runCli([]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /Usage:/);
});

test('CLI version exits zero', () => {
  const result = runCli(['--version']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), 'tokencage 1.0.0');
});

test('unknown CLI command exits with usage code 2', () => {
  const result = runCli(['unknown']);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /unknown command/);
});

test('unknown CLI command does not echo secret-looking or control-bearing input', () => {
  const sensitive = mint().token;
  const result = runCli([sensitive + '\x1b[31m']);
  assert.equal(result.status, 2);
  assert.equal(result.stderr.includes(sensitive), false);
  assert.equal(result.stderr.includes('\x1b'), false);
});

test('generate prints only the generated token by default', () => {
  const result = runCli(['generate', '--prefix', 'testapp']);
  assert.equal(result.status, 0);
  const token = result.stdout.trim();
  assert.match(token, /^testapp_[0-9A-Za-z]{49}$/);
  assert.equal(result.stderr, '');
});

test('generate --key-id creates a keyed token', () => {
  const result = runCli(['generate', '--prefix', 'testapp', '--key-id']);
  assert.equal(result.status, 0);
  assert.match(result.stdout.trim(), /^testapp_[0-9A-Za-z]{10}_[0-9A-Za-z]{49}$/);
});

test('generate --json emits complete metadata', () => {
  const result = runCli(['generate', '--prefix', 'testapp', '--key-id', '--json']);
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout);
  assert.equal(output.prefix, 'testapp');
  assert.equal(output.hasKeyId, true);
  assert.equal(output.bytes, 32);
  assert.equal(output.entropyBits, 256);
  assert.equal(typeof output.token, 'string');
  assert.equal(typeof output.redacted, 'string');
});

test('generate --bytes 16 honors the entropy floor', () => {
  const result = runCli(['generate', '--prefix', 'testapp', '--bytes', '16', '--json']);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).bytes, 16);
});

for (const args of [
  ['generate'],
  ['generate', '--bytes', '16'],
  ['generate', '--prefix'],
  ['generate', '--prefix', 'testapp', '--bytes'],
  ['generate', '--prefix', 'testapp', '--unknown'],
  ['generate', '--prefix', 'testapp', 'positional']
]) {
  test('generate usage error exits 2: ' + args.join(' '), () => {
    const result = runCli(args);
    assert.equal(result.status, 2);
  });
}

for (const args of [
  ['generate', '--prefix', 'Bad'],
  ['generate', '--prefix', 'testapp', '--bytes', '8'],
  ['generate', '--prefix', 'npm']
]) {
  test('generate validation error exits 1: ' + args.join(' '), () => {
    const result = runCli(args);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /^error: /);
  });
}

test('generate error does not echo a sensitive-looking supplied prefix', () => {
  const result = runCli(['generate', '--prefix', 'A_sensitive_prefix']);
  assert.equal(result.status, 1);
  assert.equal(result.stderr.includes('A_sensitive_prefix'), false);
});

test('inspect --json validates a generated token without echoing it', () => {
  const token = mint().token;
  const result = runCli(['inspect', token, '--json']);
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout);
  assert.equal(output.valid, true);
  assert.equal(result.stdout.includes(token), false);
});

test('inspect text output includes redaction but not raw token', () => {
  const token = mint().token;
  const result = runCli(['inspect', token]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /redacted: /);
  assert.equal(result.stdout.includes(token), false);
});

test('inspect --show-prefix-only prints only the prefix', () => {
  const token = mint().token;
  const result = runCli(['inspect', token, '--show-prefix-only']);
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'testapp\n');
});

test('inspect enforces expected prefix', () => {
  const token = mint().token;
  const result = runCli(['inspect', token, '--prefix', 'other']);
  assert.equal(result.status, 1);
});

test('inspect enforces key id presence', () => {
  const token = mint().token;
  const result = runCli(['inspect', token, '--no-key-id']);
  assert.equal(result.status, 1);
});

test('inspect malformed token exits 1 and emits valid false in json', () => {
  const result = runCli(['inspect', 'not-a-token', '--json']);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).valid, false);
});

test('inspect invalid token does not echo raw argument', () => {
  const raw = 'sensitive-looking malformed input';
  const result = runCli(['inspect', raw, '--json']);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes(raw), false);
  assert.equal(result.stderr.includes(raw), false);
});

for (const args of [
  ['inspect'],
  ['inspect', 'one', 'two'],
  ['inspect', 'one', '--key-id', '--no-key-id'],
  ['inspect', 'one', '--prefix'],
  ['inspect', 'one', '--unknown']
]) {
  test('inspect usage error exits 2: ' + args.join(' '), () => {
    assert.equal(runCli(args).status, 2);
  });
}

test('lint-config accepts a valid complete config', () => {
  const file = writeConfig('valid.json', {
    prefix: 'testapp',
    bytes: 32,
    keyId: true,
    pepper: crypto.randomBytes(32).toString('base64url'),
    ttlMs: 3600000
  });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 0, result.stderr + result.stdout);
  const output = JSON.parse(result.stdout);
  assert.equal(output.valid, true);
  assert.equal(output.errors, 0);
});

test('lint-config valid config does not print pepper material', () => {
  const pepper = crypto.randomBytes(32).toString('base64url');
  const file = writeConfig('valid-secret.json', { prefix: 'testapp', pepper });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.stdout.includes(pepper), false);
  assert.equal(result.stderr.includes(pepper), false);
});

test('lint-config warns when no pepper is present but exits zero', () => {
  const file = writeConfig('generation-only.json', { prefix: 'testapp', bytes: 32 });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 0);
  const output = JSON.parse(result.stdout);
  assert.equal(output.valid, true);
  assert.equal(output.warnings > 0, true);
});

test('lint-config rejects an invalid prefix', () => {
  const file = writeConfig('bad-prefix.json', { prefix: 'Bad' });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stdout).valid, false);
});

test('lint-config rejects weak entropy configuration', () => {
  const file = writeConfig('weak-entropy.json', { prefix: 'testapp', bytes: 8 });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 1);
});

test('lint-config rejects a weak pepper without printing it', () => {
  const weak = 'a'.repeat(32);
  const file = writeConfig('weak-pepper.json', { prefix: 'testapp', pepper: weak });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes(weak), false);
  assert.equal(result.stderr.includes(weak), false);
});


test('lint-config rejects conflicting pepper fields', () => {
  const pepper = crypto.randomBytes(32).toString('base64url');
  const file = writeConfig('conflicting-pepper.json', { prefix: 'testapp', pepper, peppers: { v1: pepper }, currentVersion: 'v1' });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 1);
  assert.equal(result.stdout.includes(pepper), false);
});

test('lint-config rejects missing currentVersion for multiple peppers', () => {
  const pepper = crypto.randomBytes(32).toString('base64url');
  const other = crypto.randomBytes(32).toString('base64url');
  const file = writeConfig('missing-current.json', { prefix: 'testapp', peppers: { v1: pepper, v2: other } });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 1);
});

test('lint-config rejects an unknown currentVersion', () => {
  const pepper = crypto.randomBytes(32).toString('base64url');
  const file = writeConfig('unknown-current.json', { prefix: 'testapp', peppers: { v1: pepper }, currentVersion: 'v2' });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 1);
});

test('lint-config rejects duplicate versions in a pepper list', () => {
  const pepper = crypto.randomBytes(32).toString('base64url');
  const other = crypto.randomBytes(32).toString('base64url');
  const file = writeConfig('duplicate-version.json', {
    prefix: 'testapp',
    peppers: [{ version: 'v1', pepper }, { version: 'v1', pepper: other }],
    currentVersion: 'v1'
  });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 1);
});

test('lint-config rejects maxTokenLength below the configured generated shape', () => {
  const pepper = crypto.randomBytes(32).toString('base64url');
  const file = writeConfig('small-max.json', { prefix: 'testapp', keyId: true, bytes: 64, maxTokenLength: 64, pepper });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 1);
});

test('lint-config accepts a coherent rotated pepper map', () => {
  const v1 = crypto.randomBytes(32).toString('base64url');
  const v2 = crypto.randomBytes(32).toString('base64url');
  const file = writeConfig('rotated.json', { prefix: 'testapp', peppers: { v1, v2 }, currentVersion: 'v2' });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal(JSON.parse(result.stdout).valid, true);
});

test('lint-config rejects duplicate expiry fields', () => {
  const file = writeConfig('duplicate-expiry.json', { prefix: 'testapp', expiresInSeconds: 60, ttlMs: 60000 });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 1);
});

test('lint-config warns for long-lived tokens', () => {
  const file = writeConfig('long-expiry.json', { prefix: 'testapp', expiresInSeconds: 31536000 });
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 0);
  assert.equal(JSON.parse(result.stdout).warnings > 0, true);
});

test('lint-config explains that unknown keys are ignored in text and JSON output', () => {
  const file = writeConfig('unknown-key.json', { prefix: 'testapp', unexpected: true });

  const textResult = runCli(['lint-config', '--config', file]);
  assert.equal(textResult.status, 0);
  assert.match(textResult.stdout, /warning unexpected: unknown configuration key is ignored by lint-config; remove it or correct the spelling before relying on this configuration/);

  const jsonResult = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(jsonResult.status, 0);
  const output = JSON.parse(jsonResult.stdout);
  const finding = output.findings.find((item) => item.code === 'unknown-key');
  assert.deepEqual(
    Object.keys(finding).sort(),
    ['code', 'field', 'level', 'message']
  );
  assert.equal(finding.level, 'warning');
  assert.equal(finding.field, 'unexpected');
  assert.match(finding.message, /ignored by lint-config/);
});

test('lint-config escapes control characters in unknown keys in text and JSON output', () => {
  const hostileKey = '\x1b[31mevil';
  const config = { prefix: 'testapp' };
  config[hostileKey] = true;
  const file = writeConfig('control-bearing-key.json', config);

  const textResult = runCli(['lint-config', '--config', file]);
  assert.equal(textResult.status, 0);
  assert.equal(textResult.stdout.includes('\x1b'), false);
  assert.match(textResult.stdout, /\\u001b\[31mevil/);
  assert.match(textResult.stdout, /ignored by lint-config/);

  const jsonResult = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(jsonResult.status, 0);
  assert.equal(jsonResult.stdout.includes('\x1b'), false);
  const output = JSON.parse(jsonResult.stdout);
  const finding = output.findings.find((item) => item.code === 'unknown-key');
  assert.equal(finding.field, '\\u001b[31mevil');
  assert.match(finding.message, /ignored by lint-config/);
  assert.deepEqual(
    Object.keys(finding).sort(),
    ['code', 'field', 'level', 'message']
  );
});

test('lint-config rejects a non-object JSON config', () => {
  const file = writeConfig('array.json', []);
  const result = runCli(['lint-config', '--config', file, '--json']);
  assert.equal(result.status, 1);
});

test('lint-config malformed JSON exits 1', () => {
  const file = path.join(scratch, 'malformed.json');
  fs.writeFileSync(file, '{"prefix":');
  const result = runCli(['lint-config', '--config', file]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unable to read or parse/);
});

test('lint-config missing file exits 1', () => {
  const result = runCli(['lint-config', '--config', path.join(scratch, 'missing.json')]);
  assert.equal(result.status, 1);
});

test('lint-config rejects a directory without treating it as configuration data', () => {
  const result = runCli(['lint-config', '--config', scratch]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unable to read or parse configuration/);
});

test('lint-config rejects an oversized regular file', () => {
  const file = path.join(scratch, 'oversized.json');
  fs.writeFileSync(file, '{"prefix":"testapp","padding":"' + 'x'.repeat(1048577) + '"}');
  const result = runCli(['lint-config', '--config', file]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unable to read or parse configuration/);
});

test('lint-config rejects a FIFO without blocking', () => {
  if (process.platform === 'win32') return;
  const fifo = path.join(scratch, 'input.fifo');
  const made = spawnSync('mkfifo', [fifo], { encoding: 'utf8' });
  assert.equal(made.status, 0, made.stderr);
  const result = runCli(['lint-config', '--config', fifo], { timeout: 5000 });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /unable to read or parse configuration/);
});

test('lint-config text output neutralizes terminal control characters in key names', () => {
  const hostileKey = '\x1b[31mevil';
  const config = { prefix: 'testapp' };
  config[hostileKey] = true;
  const file = writeConfig('ansi-key.json', config);
  const result = runCli(['lint-config', '--config', file]);
  assert.equal(result.status, 0);
  assert.equal(result.stdout.includes('\x1b'), false);
  assert.match(result.stdout, /\\u001b/);
});

test('lint-config text output summarizes counts', () => {
  const file = writeConfig('text.json', { prefix: 'testapp' });
  const result = runCli(['lint-config', '--config', file]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /valid: yes/);
  assert.match(result.stdout, /errors: 0/);
});

for (const args of [
  ['lint-config'],
  ['lint-config', '--config'],
  ['lint-config', '--config', 'x', 'positional'],
  ['lint-config', '--config', 'x', '--unknown']
]) {
  test('lint-config usage error exits 2: ' + args.join(' '), () => {
    assert.equal(runCli(args).status, 2);
  });
}

test('CLI smoke script passes', () => {
  const result = spawnSync(process.execPath, [path.join(root, 'scripts', 'smoke.mjs')], {
    cwd: root,
    encoding: 'utf8'
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /smoke passed/);
});
