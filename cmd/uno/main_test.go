package main

import (
	"reflect"
	"testing"
)

// These are the only tests that belong in package main: they exercise the
// production provider registry wiring (registry()) itself, which is a
// cmd/uno concern. Every other CLI behavior is generic dispatch logic that
// lives in, and is tested by, internal/cli — parameterized by any registry,
// not this specific one.

func TestRegistryBindsAzureKeyVaultReference(t *testing.T) {
	ref, err := registry().Parse("azure-key-vault://myvault.vault.azure.net/MY-SECRET/MY_API_KEY")
	if err != nil {
		t.Fatal(err)
	}
	if ref.Region != "myvault.vault.azure.net" || ref.Container != "MY-SECRET" || ref.Key != "MY_API_KEY" {
		t.Fatalf("ref=%+v", ref)
	}
}

func TestRegistryExposesCapabilityPrefixesForEveryProvider(t *testing.T) {
	got := registry().CapabilityPrefixes()
	want := []string{"AWS_", "AZURE_", "GOOGLE_", "OP_", "VAULT_"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prefixes=%v want=%v", got, want)
	}
}
