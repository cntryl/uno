import { readFileSync } from 'node:fs';

import { describe, expect, test } from 'vite-plus/test';

const workflow = readFileSync('.github/workflows/publish.yml', 'utf8');

describe('release artifact integrity', () => {
  test('grants OIDC only to jobs that need it', () => {
    expect(workflow).toMatch(
      /build:\n[\s\S]*?permissions:\n      contents: read\n      id-token: write/,
    );
    expect(workflow).toMatch(/publish:\n[\s\S]*?permissions:\n      id-token: write/);
  });

  test('signs every native binary and generates a CycloneDX SBOM', () => {
    expect(workflow).toContain(
      'sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6',
    );
    expect(workflow).toContain('cyclonedx-gomod@v1.10.0');
    expect(workflow).toContain('cosign sign-blob --yes --bundle');
    expect(workflow).toContain(
      'test "$(find release -name \'*.sigstore.json\' -type f | wc -l)" -eq 6',
    );
  });

  test('verifies checksums, SBOM format, signer identity, and issuer before publish', () => {
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
