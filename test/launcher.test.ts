import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';

import { describe, expect, test, vi } from 'vite-plus/test';

import { detectLinuxLibc, resolveBinary, runBinary } from '../src/launcher.js';
import { LauncherError } from '../src/platform.js';

describe('resolveBinary', () => {
  test('should throw a LauncherError given a platform binary that does not exist on disk', () => {
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

  test('should return the platform binary path given a bundled binary that exists on disk', () => {
    expect(
      resolveBinary({
        platform: 'linux',
        arch: 'x64',
        linuxLibc: 'glibc',
        packageDirectory: '/package',
        stat: () => ({ isFile: () => true }),
      }),
    ).toBe(path.join('/package', 'native', 'linux-x64-glibc', 'uno'));
  });

  test('should return the musl binary path given a Linux runtime without glibc', () => {
    expect(
      resolveBinary({
        platform: 'linux',
        arch: 'arm64',
        linuxLibc: 'musl',
        packageDirectory: '/package',
        stat: () => ({ isFile: () => true }),
      }),
    ).toBe(path.join('/package', 'native', 'linux-arm64-musl', 'uno'));
  });
});

describe('detectLinuxLibc', () => {
  test('should detect glibc given a runtime glibc version in the Node diagnostic report', () => {
    expect(detectLinuxLibc({ header: { glibcVersionRuntime: '2.28' } })).toBe('glibc');
  });

  test('should detect musl given no runtime glibc version in the Node diagnostic report', () => {
    expect(detectLinuxLibc({ header: {} })).toBe('musl');
  });
});

describe('runBinary', () => {
  test('should spawn without a shell and return the child exit code given arguments containing shell metacharacters', () => {
    const spawn = vi.fn(() => ({ error: undefined, signal: null, status: 23 }));
    const args = ['publish', '--label', 'value with spaces', '$(not-a-command)'];

    expect(runBinary('/tmp/uno', args, { spawn })).toBe(23);
    expect(spawn).toHaveBeenCalledWith('/tmp/uno', args, {
      shell: false,
      stdio: 'inherit',
    });
  });

  test('should preserve argv exactly given arguments with spaces and shell metacharacters when spawned as a real child process', () => {
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

  test('should return 128+signal-number given a child killed by SIGINT when computing the exit code', () => {
    const spawn = vi.fn(() => ({ error: undefined, signal: 'SIGINT' as const, status: null }));

    expect(runBinary('/tmp/uno', [], { spawn })).toBe(130);
  });

  test('should return 128+signal-number given a child killed by SIGTERM when computing the exit code', () => {
    const spawn = vi.fn(() => ({ error: undefined, signal: 'SIGTERM' as const, status: null }));

    expect(runBinary('/tmp/uno', [], { spawn })).toBe(143);
  });

  test('should throw a LauncherError given an unrecognized signal name when computing the exit code', () => {
    const spawn = vi.fn(() => ({
      error: undefined,
      signal: 'SIGNOTREAL' as unknown as NodeJS.Signals,
      status: null,
    }));

    expect(() => runBinary('/tmp/uno', [], { spawn })).toThrowError(
      expect.objectContaining<Partial<LauncherError>>({ code: 'CHILD_SIGNAL' }),
    );
  });
});
