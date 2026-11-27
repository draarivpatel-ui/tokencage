import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { root } from './helpers.mjs';

function listFiles(dir = root, prefix = '') {
  const output = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === '.git' || entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    const rel = prefix === '' ? entry.name : prefix + '/' + entry.name;
    if (entry.isDirectory()) output.push(...listFiles(full, rel));
    else if (entry.isFile()) output.push(rel);
  }
  return output.sort();
}

const files = listFiles();
const textFiles = files.filter((file) => !file.endsWith('.png') && !file.endsWith('.jpg'));

test('required package files exist', () => {
  for (const file of [
    'package.json', 'README.md', 'LICENSE', 'SECURITY.md', 'CONTRIBUTING.md',
    'docs/GOOD_FIRST_ISSUES.md', 'src/index.mjs', 'dist/index.cjs', 'types/index.d.ts',
    'bin/tokencage.mjs', 'scripts/build-cjs.mjs', 'scripts/smoke.mjs',
    '.github/workflows/ci.yml', '.github/PULL_REQUEST_TEMPLATE.md'
  ]) {
    assert.equal(fs.existsSync(path.join(root, file)), true, file);
  }
});

test('issue template directory contains bug feature and config templates', () => {
  for (const file of ['bug_report.yml', 'feature_request.yml', 'config.yml']) {
    assert.equal(fs.existsSync(path.join(root, '.github', 'ISSUE_TEMPLATE', file)), true, file);
  }
});

test('node_modules is absent from the repository checkout', () => {
  assert.equal(fs.existsSync(path.join(root, 'node_modules')), false);
});

test('no file uses CRLF line endings', () => {
  for (const file of textFiles) {
    const content = fs.readFileSync(path.join(root, file), 'utf8');
    assert.equal(content.includes('\r\n'), false, file);
    assert.equal(content.includes('\r'), false, file);
  }
});

test('no file contains em dash or en dash characters', () => {
  for (const file of textFiles) {
    const content = fs.readFileSync(path.join(root, file), 'utf8');
    assert.equal(content.includes(String.fromCharCode(0x2014)), false, file);
    assert.equal(content.includes(String.fromCharCode(0x2013)), false, file);
  }
});

test('no file contains local machine paths', () => {
  for (const file of textFiles) {
    const content = fs.readFileSync(path.join(root, file), 'utf8');
    assert.equal(content.includes('/Use' + 'rs/'), false, file);
    assert.equal(content.includes('/ho' + 'me/'), false, file);
    assert.equal(content.includes('C:\\Use' + 'rs\\'), false, file);
  }
});

test('no file contains private email addresses', () => {
  for (const file of textFiles) {
    const content = fs.readFileSync(path.join(root, file), 'utf8');
    assert.equal(content.includes('someone@' + 'gmail.com'), false, file);
    assert.equal(content.includes('handle-redacted286@' + 'gmail.com'), false, file);
  }
});

test('gitattributes enforces LF for required file types', () => {
  const content = fs.readFileSync(path.join(root, '.gitattributes'), 'utf8');
  for (const pattern of ['*.mjs text eol=lf', '*.cjs text eol=lf', '*.js text eol=lf', '*.ts text eol=lf', '*.json text eol=lf', '*.md text eol=lf', '*.yml text eol=lf']) {
    assert.equal(content.includes(pattern), true, pattern);
  }
});

test('gitignore excludes node_modules coverage archives and platform noise', () => {
  const content = fs.readFileSync(path.join(root, '.gitignore'), 'utf8');
  for (const entry of ['node_modules/', 'coverage/', '*.tgz', '.DS_Store']) {
    assert.equal(content.includes(entry), true, entry);
  }
});

test('CLI file is executable where executable bits exist and has a node shebang', () => {
  const file = path.join(root, 'bin', 'tokencage.mjs');
  if (process.platform !== 'win32') {
    const mode = fs.statSync(file).mode;
    assert.equal((mode & 0o111) !== 0, true);
  }
  assert.equal(fs.readFileSync(file, 'utf8').startsWith('#!/usr/bin/env node\n'), true);
});

test('LICENSE is MIT and copyright is project contributors', () => {
  const content = fs.readFileSync(path.join(root, 'LICENSE'), 'utf8');
  assert.match(content, /MIT License/);
  assert.match(content, /tokencage contributors/);
});

test('README documents the threat model', () => {
  const content = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.match(content, /## Threat model/);
  assert.match(content, /In scope:/);
  assert.match(content, /Out of scope:/);
});

test('README honestly avoids claiming prior npm publication', () => {
  const content = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.match(content, /does not claim that the package has already been published/);
  assert.equal(content.includes('## Status'), true);
});

test('README explains that CRC32 is not authentication', () => {
  const content = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.match(content, /CRC32 is only an accident detector, not authentication/);
});

test('README documents rotation nextHash handling', () => {
  const content = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.match(content, /Only store `nextHash` after the presented token verifies/);
});

test('README documents zero dependencies', () => {
  const content = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  assert.match(content, /Runtime dependencies: none/);
  assert.match(content, /Development dependencies: none/);
});

test('SECURITY documents private reporting and cryptographic inventory', () => {
  const content = fs.readFileSync(path.join(root, 'SECURITY.md'), 'utf8');
  assert.match(content, /private GitHub security advisory/);
  assert.match(content, /crypto\.randomBytes/);
  assert.match(content, /crypto\.timingSafeEqual/);
});

test('CONTRIBUTING documents the verification commands', () => {
  const content = fs.readFileSync(path.join(root, 'CONTRIBUTING.md'), 'utf8');
  for (const command of ['npm test', 'node scripts/build-cjs.mjs --check', 'npm run smoke', 'npm pack --dry-run']) {
    assert.equal(content.includes(command), true, command);
  }
});

test('good first issues file contains ten numbered starter specs', () => {
  const content = fs.readFileSync(path.join(root, 'docs', 'GOOD_FIRST_ISSUES.md'), 'utf8');
  const count = (content.match(/^## \d+\./gm) || []).length;
  assert.equal(count, 10);
});

test('CI covers required Node versions', () => {
  const content = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  for (const version of ['18', '20', '22', '24']) {
    assert.equal(content.includes(version), true, version);
  }
});

test('CI covers ubuntu and windows', () => {
  const content = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  assert.equal(content.includes('ubuntu-24.04'), true);
  assert.equal(content.includes('windows-latest'), true);
});

test('CI runs tests build check smoke and pack dry run', () => {
  const content = fs.readFileSync(path.join(root, '.github', 'workflows', 'ci.yml'), 'utf8');
  for (const command of ['npm test', 'node scripts/build-cjs.mjs --check', 'npm run smoke', 'npm pack --dry-run']) {
    assert.equal(content.includes(command), true, command);
  }
});

test('public package metadata contains no dependency install spec', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.deepEqual(pkg.dependencies, {});
  assert.deepEqual(pkg.devDependencies, {});
  assert.equal(pkg.optionalDependencies, undefined);
  assert.equal(pkg.peerDependencies, undefined);
});

test('source and generated build contain no network or filesystem writes', () => {
  for (const file of ['src/index.mjs', 'dist/index.cjs']) {
    const content = fs.readFileSync(path.join(root, file), 'utf8');
    assert.equal(content.includes('node:fs'), false, file);
    assert.equal(content.includes('node:http'), false, file);
    assert.equal(content.includes('node:https'), false, file);
    assert.equal(content.includes('fetch('), false, file);
  }
});

test('source does not use eval or dynamic code generation', () => {
  for (const file of ['src/index.mjs', 'dist/index.cjs']) {
    const content = fs.readFileSync(path.join(root, file), 'utf8');
    assert.equal(content.includes('eval('), false, file);
    assert.equal(content.includes('new Function'), false, file);
  }
});

test('repository text does not include example values with live vendor token shapes', () => {
  for (const file of textFiles) {
    const content = fs.readFileSync(path.join(root, file), 'utf8');
    assert.equal(/ghp_[0-9A-Za-z]{20,}/.test(content), false, file);
    assert.equal(/sk_live_[0-9A-Za-z]{20,}/.test(content), false, file);
    assert.equal(/xoxb-[0-9A-Za-z-]{20,}/.test(content), false, file);
    assert.equal(/AKIA[0-9A-Z]{16}/.test(content), false, file);
  }
});

test('test files use node test runner and no test dependency imports', () => {
  for (const file of files.filter((name) => name.startsWith('tests/') && name.endsWith('.mjs'))) {
    const content = fs.readFileSync(path.join(root, file), 'utf8');
    assert.equal(content.includes('node:test'), file === 'tests/helpers.mjs' ? false : true, file);
    assert.equal(content.includes('from \'node:test\''), file === 'tests/helpers.mjs' ? false : true, file);
  }
});
