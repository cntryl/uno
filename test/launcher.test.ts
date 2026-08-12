import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';

import { describe, expect, test, vi } from 'vite-plus/test';

import { resolveBinary, runBinary } from '../src/launcher.js';
import { LauncherError } from '../src/platform.js';

describe('resolveBinary', () => {
  test('reports a bundled platform binary that is missing', () => {
    expect(() =>
      resolveBinary({
        platform: 'darwin',
        arch: 'arm64',
        packageDirectory: '/tmp/uno-package',
      }),
    ).toThrowError(
      expect.objectContaining<Partial<LauncherError>>({ code: 'MISSING_PLATFORM_BINARY' }),
    );
  });

  test('selects a bundled platform binary', () => {
    expect(
      resolveBinary({
        platform: 'linux',
        arch: 'x64',
        packageDirectory: '/package',
        stat: () => ({ isFile: () => true }),
      }),
    ).toBe(path.join('/package', 'native', 'linux-x64', 'uno'));
  });
});

describe('runBinary', () => {
  test('directly spawns without a shell and returns the child exit code', () => {
    const spawn = vi.fn(() => ({ error: undefined, signal: null, status: 23 }));
    const args = ['publish', '--label', 'value with spaces', '$(not-a-command)'];

    expect(runBinary('/tmp/uno', args, { spawn })).toBe(23);
    expect(spawn).toHaveBeenCalledWith('/tmp/uno', args, {
      shell: false,
      stdio: 'inherit',
    });
  });

  test('preserves argv with a real child process', () => {
    const directory = mkdtempSync(path.join(tmpdir(), 'uno-launcher-'));
    const outputPath = path.join(directory, 'argv.json');
    const fixturePath = path.join(directory, 'capture-argv.cjs');
    const args = ['value with spaces', '$(not-a-command)', 'semi;colon'];
    writeFileSync(
      fixturePath,
      "require('node:fs').writeFileSync(process.argv[2], JSON.stringify(process.argv.slice(4))); process.exitCode = Number(process.argv[3]);\n",
    );

    expect(runBinary(process.execPath, [fixturePath, outputPath, '17', ...args])).toBe(17);
    expect(JSON.parse(readFileSync(outputPath, 'utf8'))).toEqual(args);
  });
});
