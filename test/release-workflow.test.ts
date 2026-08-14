import { readFileSync } from 'node:fs';

import { describe, expect, test } from 'vite-plus/test';

const darwinWorkflow = readFileSync('.github/workflows/darwin.yml', 'utf8');
const linuxWorkflow = readFileSync('.github/workflows/linux.yml', 'utf8');
const nativeWorkflow = readFileSync('.github/workflows/native.yml', 'utf8');
const publishWorkflow = readFileSync('.github/workflows/publish.yml', 'utf8');
const windowsWorkflow = readFileSync('.github/workflows/windows.yml', 'utf8');

describe('release artifact integrity', () => {
  test('should cancel superseded platform runs only within the same workflow and branch given the workflow files', () => {
    for (const [workflow, group] of [
      [nativeWorkflow, 'group: uno-native-${{ github.workflow }}-${{ github.ref }}'],
      [darwinWorkflow, 'group: uno-darwin-${{ github.workflow }}-${{ github.ref }}'],
      [linuxWorkflow, 'group: uno-linux-${{ github.workflow }}-${{ github.ref }}'],
      [windowsWorkflow, 'group: uno-windows-${{ github.workflow }}-${{ github.ref }}'],
    ]) {
      expect(workflow).toContain(group);
      expect(workflow).toContain('cancel-in-progress: true');
    }
  });

  test('should delegate each platform to a focused reusable workflow given the native workflow file', () => {
    expect(nativeWorkflow).toMatch(/darwin:\n    uses: \.\/\.github\/workflows\/darwin\.yml/);
    expect(nativeWorkflow).toMatch(/linux:\n    uses: \.\/\.github\/workflows\/linux\.yml/);
    expect(nativeWorkflow).toMatch(/windows:\n    uses: \.\/\.github\/workflows\/windows\.yml/);
    expect(nativeWorkflow).not.toContain('runs-on:');
    expect(nativeWorkflow).not.toContain('go build');
    for (const workflow of [darwinWorkflow, linuxWorkflow, windowsWorkflow]) {
      expect(workflow).toMatch(/on:\n  workflow_call:\n  workflow_dispatch:/);
    }
  });

  test('should build native artifacts manually or as a reusable publish job given the workflow files', () => {
    expect(nativeWorkflow).toMatch(/on:\n  workflow_call:\n  workflow_dispatch:/);
    expect(publishWorkflow).toMatch(
      /native:\n    needs: ci\n    uses: \.\/\.github\/workflows\/native\.yml\n    permissions:\n      contents: read/,
    );
    expect(publishWorkflow).not.toMatch(/^  linux:/m);
    for (const workflow of [darwinWorkflow, linuxWorkflow, nativeWorkflow, windowsWorkflow]) {
      expect(workflow).not.toContain('cosign');
      expect(workflow).not.toContain('npm publish');
    }
  });

  test('should use one environment-protected release job with the required permissions given the release workflow file', () => {
    expect(publishWorkflow).toMatch(
      /release:\n    needs: \[ci, native\]\n    runs-on: ubuntu-latest\n    environment: npm\n    permissions:\n      contents: write\n      id-token: write/,
    );
    expect(publishWorkflow).not.toMatch(/^  tag:/m);
    expect(publishWorkflow).not.toMatch(/^  publish:/m);
  });

  test('should build and smoke-test Darwin and Windows binaries natively given the platform workflow files', () => {
    expect(darwinWorkflow).toMatch(/^  darwin:\n/m);
    expect(darwinWorkflow).toContain('runner: macos-15');
    expect(darwinWorkflow).toContain('runner: macos-15-intel');
    expect(windowsWorkflow).toMatch(/^  windows:\n/m);
    expect(windowsWorkflow).toContain('runner: windows-11-arm');
    expect(windowsWorkflow).toContain('runner: windows-2025');
    for (const workflow of [darwinWorkflow, windowsWorkflow]) {
      expect(workflow).toContain('go build -trimpath');
      expect(workflow).not.toMatch(/\bGOOS=/);
      expect(workflow).not.toMatch(/\bGOARCH=/);
      expect(workflow).toContain('actions/upload-artifact@v7.0.1');
    }
    expect(publishWorkflow).toContain('actions/download-artifact@v8.0.1');
  });

  test('should target macOS 13.5 and verify the linked deployment floor given the Darwin workflow file', () => {
    expect(darwinWorkflow).toContain("MACOSX_DEPLOYMENT_TARGET: '13.5'");
    expect(darwinWorkflow).toContain('CGO_CFLAGS: -mmacosx-version-min=13.5');
    expect(darwinWorkflow).toContain('CGO_LDFLAGS: -mmacosx-version-min=13.5');
    expect(darwinWorkflow).toContain('otool -l');
    expect(darwinWorkflow).toContain('= 13.5');
  });

  test('should trust the container checkout and verify the exact VCS revision given the Linux workflow file', () => {
    expect(linuxWorkflow).toContain('git config --global --add safe.directory "$GITHUB_WORKSPACE"');
    expect(linuxWorkflow).toContain('go version -m "$binary"');
    expect(linuxWorkflow).toContain('vcs\\.revision');
    expect(linuxWorkflow.match(/test "\$vcs_revision" = "\$GITHUB_SHA"/g)).toHaveLength(2);
  });

  test('should build glibc 2.28 and static musl Linux binaries on native architectures given the Linux workflow file', () => {
    expect(linuxWorkflow).toMatch(/^  linux:\n/m);
    expect(linuxWorkflow).toContain('quay.io/pypa/manylinux_2_28_aarch64@sha256:');
    expect(linuxWorkflow).toContain('quay.io/pypa/manylinux_2_28_x86_64@sha256:');
    expect(linuxWorkflow).toContain('native/linux-${{ matrix.arch }}-glibc/uno');
    expect(linuxWorkflow).toContain('native/linux-${{ matrix.arch }}-musl/uno');
    expect(linuxWorkflow).toContain('CGO_ENABLED=1 go build');
    expect(linuxWorkflow).toContain('CGO_ENABLED=0 go build');
    expect(linuxWorkflow).toContain('readelf --version-info');
    expect(linuxWorkflow).toContain('readelf --dynamic');
    expect(linuxWorkflow).toContain('2.28');
  });

  test('should sign every native binary and generate a cyclonedx sbom given the release workflow file', () => {
    expect(publishWorkflow).toContain('sigstore/cosign-installer@v4.1.2');
    expect(publishWorkflow).toContain('cyclonedx-gomod@v1.10.0');
    expect(publishWorkflow).toContain('cosign sign-blob --yes --bundle');
    expect(publishWorkflow).toContain(
      'test "$(find release -name \'*.sigstore.json\' -type f | wc -l)" -eq 8',
    );
  });

  test('should verify checksums, sbom format, signer identity, and oidc issuer before publishing given the release workflow file', () => {
    const checksum = publishWorkflow.indexOf('sha256sum --check release/SHA256SUMS');
    const sbom = publishWorkflow.indexOf(`jq -e '.bomFormat == "CycloneDX"'`);
    const signature = publishWorkflow.indexOf('cosign verify-blob');
    const publish = publishWorkflow.indexOf('npm publish ./release/*.tgz');

    expect(checksum).toBeGreaterThan(-1);
    expect(sbom).toBeGreaterThan(checksum);
    expect(signature).toBeGreaterThan(sbom);
    expect(publishWorkflow).toContain('test "${#archives[@]}" -eq 1');
    expect(publishWorkflow).toContain('cmp "$binary" "$package_dir/package/$relative"');
    expect(publishWorkflow).toContain('--certificate-identity "$CERTIFICATE_IDENTITY"');
    expect(publishWorkflow).toContain(
      '--certificate-oidc-issuer https://token.actions.githubusercontent.com',
    );
    expect(publish).toBeGreaterThan(signature);
  });
});
