import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, test } from 'vite-plus/test';

const repositoryRoot = process.cwd();
const packageJson = JSON.parse(
  readFileSync(path.join(repositoryRoot, 'package.json'), 'utf8'),
) as Record<string, unknown>;

describe('package metadata', () => {
  test('should support the npm launcher on Node.js 22 or later', () => {
    expect(packageJson.engines).toEqual({ node: '>=22.0.0' });

    const readme = readFileSync(path.join(repositoryRoot, 'README.md'), 'utf8');
    expect(readme).toContain('requires Node.js 22 or later');

    const developmentVersion = readFileSync(
      path.join(repositoryRoot, '.node-version'),
      'utf8',
    ).trim();
    expect(developmentVersion).toBe('22.22.2');
    for (const workflow of ['ci.yml', 'publish.yml']) {
      const source = readFileSync(path.join(repositoryRoot, '.github/workflows', workflow), 'utf8');
      expect(source).toContain(`node-version: '${developmentVersion}'`);
      expect(source).toContain('npm install --prefix "$NPM_PREFIX" npm@12.0.2');
      expect(source).toContain('echo "$NPM_PREFIX/node_modules/.bin" >> "$GITHUB_PATH"');
      expect(source).not.toContain('npm install --global npm@12.0.2');
    }
  });

  test('should publish a single built launcher with no lifecycle scripts given the root package.json fields', () => {
    expect(packageJson.name).toBe('@cntryl/uno');
    expect(packageJson.private).toBeUndefined();
    expect(packageJson.workspaces).toBeUndefined();
    expect(packageJson.bin).toEqual({ uno: 'dist/cli.js' });
    expect(packageJson.files).toEqual([
      'dist/cli.js',
      'native/darwin-arm64/uno',
      'native/darwin-x64/uno',
      'native/linux-arm64-glibc/uno',
      'native/linux-arm64-musl/uno',
      'native/linux-x64-glibc/uno',
      'native/linux-x64-musl/uno',
      'native/win32-arm64/uno.exe',
      'native/win32-x64/uno.exe',
      'README.md',
      'LICENSE',
    ]);
    expect(packageJson.optionalDependencies).toBeUndefined();
    for (const lifecycle of ['preinstall', 'install', 'postinstall']) {
      expect((packageJson.scripts as Record<string, string>)[lifecycle]).toBeUndefined();
    }
  });

  test('should keep the centralized go and npm release versions aligned', () => {
    const source = readFileSync(path.join(repositoryRoot, 'internal/version/version.go'), 'utf8');
    const goVersion = source.match(/^const Current = "([^"]+)"$/m)?.[1];
    expect(goVersion).toBe(packageJson.version);
  });

  test('should verify installed archives against package metadata without a stale version literal', () => {
    const verifier = readFileSync(path.join(repositoryRoot, 'scripts/verify-package.mjs'), 'utf8');
    expect(verifier).toContain('fileURLToPath(import.meta.url)');
    expect(verifier).toContain("readFileSync(join(repositoryRoot, 'package.json')");
    expect(verifier).not.toMatch(/metadata\.version !== '\\d+\.\\d+\.\\d+'/);
  });
});
