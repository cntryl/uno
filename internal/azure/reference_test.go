package azure

import "testing"

func TestParseAzureKeyVaultReferences(t *testing.T) {
	tests := []struct{ raw, host, secret, key string }{
		{"azure-key-vault://MyVault.vault.azure.net/secret-name", "myvault.vault.azure.net", "secret-name", ""},
		{"azure-key-vault://v.vault.usgovcloudapi.net/secret/key", "v.vault.usgovcloudapi.net", "secret", "key"},
		{"azure-key-vault://v.vault.azure.cn/secret", "v.vault.azure.cn", "secret", ""},
		{"azure-key-vault://v.vault.microsoftazure.de/secret/key", "v.vault.microsoftazure.de", "secret", "key"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			ref, err := Parse(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if ref.Scheme != "azure-key-vault" || ref.Region != tt.host || ref.Container != tt.secret || ref.Key != tt.key || ref.AdapterKey != tt.host {
				t.Fatalf("ref=%+v", ref)
			}
		})
	}
}

func TestRejectInvalidAzureKeyVaultReferences(t *testing.T) {
	invalid := []string{
		"azure-key-vault://", "azure-key-vault://v.vault.azure.net", "azure-key-vault://v.vault.azure.net/",
		"azure-key-vault://v.vault.azure.net/a/b/c", "azure-key-vault://evil.example/a",
		"azure-key-vault://user@v.vault.azure.net/a", "azure-key-vault://v.vault.azure.net:443/a",
		"azure-key-vault://v.vault.azure.net/a?q=x", "azure-key-vault://v.vault.azure.net/a#x",
		"azure-key-vault://v.vault.azure.net/bad_name", "azure-key-vault://v.vault.azure.net/a/",
		"azure-key-vault://v.vault.azure.net/a\x00b",
	}
	for _, raw := range invalid {
		t.Run(raw, func(t *testing.T) {
			if _, err := Parse(raw); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{"azure-key-vault://v.vault.azure.net/MY-SECRET", "azure-key-vault://v.vault.azure.cn/MY-SECRET/MY_API_KEY"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) { _, _ = Parse(raw) })
}
