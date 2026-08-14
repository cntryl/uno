import { readFileSync } from 'node:fs';

import { describe, expect, test } from 'vite-plus/test';

const nativeWorkflow = readFileSync('.github/workflows/native.yml', 'utf8');
const publishWorkflow = readFileSync('.github/workflows/publish.yml', 'utf8');

describe('release artifact integrity', () => {
  test('should build native artifacts manually or as a reusable publish job given the workflow files', () => {
    expect(nativeWorkflow).toMatch(/on:\n  workflow_call:\n  workflow_dispatch:/);
    expect(publishWorkflow).toMatch(
      /native:\n    needs: ci\n    uses: \.\/\.github\/workflows\/native\.yml\n    permissions:\n      contents: read/,
    );
    expect(publishWorkflow).not.toMatch(/^  linux:/m);
    expect(nativeWorkflow).not.toContain('cosign');
    expect(nativeWorkflow).not.toContain('npm publish');
  });

  test('should use one environment-protected release job with the required permissions given the release workflow file', () => {
    expect(publishWorkflow).toMatch(
      /release:\n    needs: \[ci, native\]\n    runs-on: ubuntu-latest\n    environment: npm\n    permissions:\n      contents: write\n      id-token: write/,
    );
    expect(publishWorkflow).not.toMatch(/^  tag:/m);
    expect(publishWorkflow).not.toMatch(/^  publish:/m);
  });

  test('should build and smoke-test macOS and Windows binaries natively given the native workflow file', () => {
    expect(nativeWorkflow).toMatch(/^  native:\n/m);
    expect(nativeWorkflow).toContain('runner: macos-15');
    expect(nativeWorkflow).toContain('runner: macos-15-intel');
    expect(nativeWorkflow).toContain('runner: windows-11-arm');
    expect(nativeWorkflow).toContain('runner: windows-2025');
    expect(nativeWorkflow).toContain('go build -trimpath');
    expect(nativeWorkflow).not.toMatch(/\bGOOS=/);
    expect(nativeWorkflow).not.toMatch(/\bGOARCH=/);
    expect(nativeWorkflow).toContain('actions/upload-artifact@v7.0.1');
    expect(publishWorkflow).toContain('actions/download-artifact@v8.0.1');
  });

  test('should target macOS 13.5 and verify the linked deployment floor given the native workflow file', () => {
    expect(nativeWorkflow).toContain("MACOSX_DEPLOYMENT_TARGET: '13.5'");
    expect(nativeWorkflow).toContain('CGO_CFLAGS: -mmacosx-version-min=13.5');
    expect(nativeWorkflow).toContain('CGO_LDFLAGS: -mmacosx-version-min=13.5');
    expect(nativeWorkflow).toContain('otool -l');
    expect(nativeWorkflow).toContain('= 13.5');
  });

  test('should build glibc 2.28 and static musl Linux binaries on native architectures given the native workflow file', () => {
    expect(nativeWorkflow).toMatch(/^  linux:\n/m);
    expect(nativeWorkflow).toContain('quay.io/pypa/manylinux_2_28_aarch64@sha256:');
    expect(nativeWorkflow).toContain('quay.io/pypa/manylinux_2_28_x86_64@sha256:');
    expect(nativeWorkflow).toContain('native/linux-${{ matrix.arch }}-glibc/uno');
    expect(nativeWorkflow).toContain('native/linux-${{ matrix.arch }}-musl/uno');
    expect(nativeWorkflow).toContain('CGO_ENABLED=1 go build');
    expect(nativeWorkflow).toContain('CGO_ENABLED=0 go build');
    expect(nativeWorkflow).toContain('readelf --version-info');
    expect(nativeWorkflow).toContain('readelf --dynamic');
    expect(nativeWorkflow).toContain('2.28');
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
