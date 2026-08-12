import { describe, expect, test } from 'vite-plus/test';

import {
  LauncherError,
  type PlatformTarget,
  platformTargets,
  selectPlatform,
} from '../src/platform.js';

describe('selectPlatform', () => {
  test('maps every supported platform tuple', () => {
    for (const expected of Object.values(platformTargets) as PlatformTarget[]) {
      expect(selectPlatform(expected.platform, expected.arch)).toEqual(expected);
    }
  });

  test('rejects unsupported platform tuples', () => {
    expect(() => selectPlatform('linux', 's390x')).toThrowError(
      expect.objectContaining<Partial<LauncherError>>({
        code: 'UNSUPPORTED_PLATFORM',
        message: 'Unsupported platform: linux/s390x',
      }),
    );
  });
});
