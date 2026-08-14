import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const archive = process.argv[2] ? resolve(process.argv[2]) : undefined;
if (!archive) throw new Error('archive path is required');
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const expectedVersion = JSON.parse(
  readFileSync(join(repositoryRoot, 'package.json'), 'utf8'),
).version;
const expected = [
  'package/LICENSE',
  'package/README.md',
  'package/dist/cli.js',
  'package/native/darwin-arm64/uno',
  'package/native/darwin-x64/uno',
  'package/native/linux-arm64-glibc/uno',
  'package/native/linux-arm64-musl/uno',
  'package/native/linux-x64-glibc/uno',
  'package/native/linux-x64-musl/uno',
  'package/native/win32-arm64/uno.exe',
  'package/native/win32-x64/uno.exe',
  'package/package.json',
].sort();
const actual = execFileSync('tar', ['-tzf', archive], { encoding: 'utf8' })
  .trim()
  .split('\n')
  .sort();
if (JSON.stringify(actual) !== JSON.stringify(expected)) {
  throw new Error(`unexpected package manifest:\n${actual.join('\n')}`);
}
const directory = mkdtempSync(join(tmpdir(), 'uno-package-'));
try {
  execFileSync('npm', ['install', '--ignore-scripts', '--no-audit', '--no-fund', archive], {
    cwd: directory,
    stdio: 'inherit',
  });
  const metadata = JSON.parse(
    readFileSync(join(directory, 'node_modules/@cntryl/uno/package.json'), 'utf8'),
  );
  if (metadata.version !== expectedVersion)
    throw new Error('installed package has the wrong version');
} finally {
  rmSync(directory, { recursive: true, force: true });
}
