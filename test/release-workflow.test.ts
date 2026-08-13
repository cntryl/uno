import { readFileSync } from 'node:fs';

import { describe, expect, test } from 'vite-plus/test';

const workflow = readFileSync('.github/workflows/publish.yml', 'utf8');

describe('release artifact integrity', () => {
  test('should use one environment-protected release job with the required permissions given the release workflow file', () => {
    expect(workflow).toMatch(
      /release:\n    needs: ci\n    runs-on: ubuntu-latest\n    environment: npm\n    permissions:\n      contents: write\n      id-token: write/,
    );
    expect(workflow).not.toMatch(/^  build:/m);
    expect(workflow).not.toMatch(/^  tag:/m);
    expect(workflow).not.toMatch(/^  publish:/m);
  });

  test('should sign every native binary and generate a cyclonedx sbom given the release workflow file', () => {
    expect(workflow).toContain('sigstore/cosign-installer@v4.1.2');
    expect(workflow).toContain('cyclonedx-gomod@v1.10.0');
    expect(workflow).toContain('cosign sign-blob --yes --bundle');
    expect(workflow).toContain(
      'test "$(find release -name \'*.sigstore.json\' -type f | wc -l)" -eq 6',
    );
  });

  test('should verify checksums, sbom format, signer identity, and oidc issuer before publishing given the release workflow file', () => {
    const checksum = workflow.indexOf('sha256sum --check release/SHA256SUMS');
    const sbom = workflow.indexOf(`jq -e '.bomFormat == "CycloneDX"'`);
    const signature = workflow.indexOf('cosign verify-blob');
    const publish = workflow.indexOf('npm publish ./release/*.tgz');

    expect(checksum).toBeGreaterThan(-1);
    expect(sbom).toBeGreaterThan(checksum);
    expect(signature).toBeGreaterThan(sbom);
    expect(workflow).toContain('test "${#archives[@]}" -eq 1');
    expect(workflow).toContain('cmp "$binary" "$package_dir/package/$relative"');
    expect(workflow).toContain('--certificate-identity "$CERTIFICATE_IDENTITY"');
    expect(workflow).toContain(
      '--certificate-oidc-issuer https://token.actions.githubusercontent.com',
    );
    expect(publish).toBeGreaterThan(signature);
  });
});
