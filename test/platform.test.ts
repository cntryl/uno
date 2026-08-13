import { describe, expect, test } from 'vite-plus/test';

import {
  LauncherError,
  type PlatformTarget,
  platformTargets,
  selectPlatform,
} from '../src/platform.js';

describe('selectPlatform', () => {
  test('should return the matching platform target given every supported platform and arch combination', () => {
    for (const expected of Object.values(platformTargets) as PlatformTarget[]) {
      expect(selectPlatform(expected.platform, expected.arch)).toEqual(expected);
    }
  });

  test('should throw an unsupported platform error given an unsupported platform and arch combination', () => {
    expect(() => selectPlatform('linux', 's390x')).toThrowError(
      expect.objectContaining<Partial<LauncherError>>({
        code: 'UNSUPPORTED_PLATFORM',
        message: 'Unsupported platform: linux/s390x',
      }),
    );
  });
});
