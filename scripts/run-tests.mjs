import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const testsDirectory = path.join(root, 'tests');
const testFiles = fs.readdirSync(testsDirectory)
  .filter((name) => name.endsWith('.test.mjs'))
  .sort()
  .map((name) => path.join(testsDirectory, name));

if (testFiles.length === 0) {
  process.stderr.write('error: no test files found\n');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...testFiles], {
  cwd: root,
  stdio: 'inherit'
});

if (result.error) {
  process.stderr.write('error: unable to start the Node.js test runner\n');
  process.exit(1);
}

process.exit(result.status === null ? 1 : result.status);
