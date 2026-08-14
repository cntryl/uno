import { spawnSync } from 'node:child_process';
import { statSync } from 'node:fs';
import { constants as osConstants } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { LauncherError, type LinuxLibc, selectPlatform } from './platform.js';

interface DiagnosticReport {
  readonly header?: {
    readonly glibcVersionRuntime?: unknown;
  };
}

export interface ResolveBinaryOptions {
  readonly platform?: NodeJS.Platform;
  readonly arch?: string;
  readonly linuxLibc?: LinuxLibc;
  readonly packageDirectory?: string;
  readonly stat?: (path: string) => { isFile(): boolean };
}

export function detectLinuxLibc(report: DiagnosticReport = process.report.getReport()): LinuxLibc {
  return typeof report.header?.glibcVersionRuntime === 'string' ? 'glibc' : 'musl';
}

export function resolveBinary({
  platform = process.platform,
  arch = process.arch,
  linuxLibc,
  packageDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'),
  stat = statSync,
}: ResolveBinaryOptions = {}): string {
  const selected = selectPlatform(
    platform,
    arch,
    platform === 'linux' ? (linuxLibc ?? detectLinuxLibc()) : undefined,
  );
  const binaryPath = path.join(packageDirectory, selected.binaryPath);

  try {
    if (!stat(binaryPath).isFile()) {
      throw new Error('not a file');
    }
  } catch (cause) {
    throw new LauncherError(
      'MISSING_PLATFORM_BINARY',
      `The installed @cntryl/uno package does not contain ${selected.binaryPath}. Reinstall @cntryl/uno.`,
      { cause },
    );
  }

  return binaryPath;
}

export interface RunBinaryOptions {
  readonly spawn?: Spawn;
}

type Spawn = (
  command: string,
  args: string[],
  options: { shell: false; stdio: 'inherit' },
) => {
  readonly error?: Error;
  readonly signal?: NodeJS.Signals | null;
  readonly status?: number | null;
};

export function runBinary(
  binaryPath: string,
  args: readonly string[],
  { spawn = spawnSync }: RunBinaryOptions = {},
): number {
  const result = spawn(binaryPath, [...args], {
    shell: false,
    stdio: 'inherit',
  });

  if (result.error) {
    throw new LauncherError(
      'SPAWN_FAILED',
      `Unable to start the uno binary: ${result.error.message}`,
      { cause: result.error },
    );
  }
  if (result.signal) {
    const signalNumber = (osConstants.signals as Record<string, number>)[result.signal];
    if (typeof signalNumber !== 'number') {
      throw new LauncherError(
        'CHILD_SIGNAL',
        `The uno binary terminated from signal ${result.signal}.`,
      );
    }
    // Follow the POSIX/shell convention (128 + signal number) so callers and
    // CI scripts can distinguish e.g. a user's SIGINT (130) from a SIGKILL
    // (137) instead of seeing the same opaque failure code for both.
    return 128 + signalNumber;
  }
  return result.status ?? 1;
}

export interface MainOptions extends ResolveBinaryOptions, RunBinaryOptions {
  readonly args?: readonly string[];
  readonly stderr?: Pick<NodeJS.WriteStream, 'write'>;
}

export function main({
  args = process.argv.slice(2),
  stderr = process.stderr,
  spawn,
  ...resolveOptions
}: MainOptions = {}): number {
  try {
    return runBinary(resolveBinary(resolveOptions), args, { spawn });
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown launcher failure';
    stderr.write(`uno: ${message}\n`);
    return 1;
  }
}
