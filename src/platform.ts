export type LinuxLibc = 'glibc' | 'musl';

export interface PlatformTarget {
  readonly platform: NodeJS.Platform;
  readonly arch: string;
  readonly libc?: LinuxLibc;
  readonly binaryPath: string;
}

export const platformTargets = Object.freeze({
  'darwin-arm64': target('darwin', 'arm64', 'native/darwin-arm64/uno'),
  'darwin-x64': target('darwin', 'x64', 'native/darwin-x64/uno'),
  'linux-arm64-glibc': target('linux', 'arm64', 'native/linux-arm64-glibc/uno', 'glibc'),
  'linux-arm64-musl': target('linux', 'arm64', 'native/linux-arm64-musl/uno', 'musl'),
  'linux-x64-glibc': target('linux', 'x64', 'native/linux-x64-glibc/uno', 'glibc'),
  'linux-x64-musl': target('linux', 'x64', 'native/linux-x64-musl/uno', 'musl'),
  'win32-arm64': target('win32', 'arm64', 'native/win32-arm64/uno.exe'),
  'win32-x64': target('win32', 'x64', 'native/win32-x64/uno.exe'),
} satisfies Record<string, PlatformTarget>);

function target(
  platform: NodeJS.Platform,
  arch: string,
  binaryPath: string,
  libc?: LinuxLibc,
): Readonly<PlatformTarget> {
  return Object.freeze({ platform, arch, libc, binaryPath });
}

export function selectPlatform(
  platform: NodeJS.Platform,
  arch: string,
  linuxLibc: LinuxLibc = 'glibc',
): PlatformTarget {
  const key = (
    platform === 'linux' ? `${platform}-${arch}-${linuxLibc}` : `${platform}-${arch}`
  ) as keyof typeof platformTargets;
  const selected = platformTargets[key];
  if (!selected) {
    throw new LauncherError('UNSUPPORTED_PLATFORM', `Unsupported platform: ${platform}/${arch}`);
  }
  return selected;
}

export class LauncherError extends Error {
  readonly code: string;

  constructor(code: string, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LauncherError';
    this.code = code;
  }
}
