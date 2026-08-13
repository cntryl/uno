import { readFileSync } from 'node:fs';
import path from 'node:path';

import { describe, expect, test } from 'vite-plus/test';

const repositoryRoot = process.cwd();
const packageJson = JSON.parse(
  readFileSync(path.join(repositoryRoot, 'package.json'), 'utf8'),
) as Record<string, unknown>;

describe('package metadata', () => {
  test('should publish a single built launcher with no lifecycle scripts given the root package.json fields', () => {
    expect(packageJson.name).toBe('@cntryl/uno');
    expect(packageJson.private).toBeUndefined();
    expect(packageJson.workspaces).toBeUndefined();
    expect(packageJson.bin).toEqual({ uno: 'dist/cli.js' });
    expect(packageJson.files).toEqual([
      'dist/cli.js',
      'native/darwin-arm64/uno',
      'native/darwin-x64/uno',
      'native/linux-arm64/uno',
      'native/linux-x64/uno',
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
});
