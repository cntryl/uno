// Package vault adapts explicit HashiCorp Vault KV v2 references.
package vault

import (
	"context"
	"strings"

	"github.com/cntryl/uno/internal/core/provider"
	vaultapi "github.com/hashicorp/vault/api"
)

// adapterKey is constant across every reference: one Vault client (VAULT_ADDR)
// serves every mount, unlike AWS where each region needs its own client.
const adapterKey = "vault"

type Factory struct{}

func (Factory) CapabilityPrefixes() []string { return []string{"VAULT_"} }

func (Factory) Parse(raw string) (provider.Reference, error) { return Parse(raw) }

func (Factory) Adapter(ctx context.Context, ref provider.Reference) (provider.Adapter, error) {
	cfg := vaultapi.DefaultConfig()
	if cfg.Error != nil {
		return nil, &provider.Error{Kind: provider.Authentication}
	}
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return nil, &provider.Error{Kind: provider.Authentication}
	}
	if client.Token() == "" {
		return nil, &provider.Error{Kind: provider.Authentication, Detail: "VAULT_TOKEN is not set"}
	}
	return &Vault{Mount: func(mount string) VaultAPI { return client.KVv2(mount) }}, nil
}

// Parse accepts vault://mount/path/to/secret/key. The mount is the KV v2
// engine's mount point, the last segment is the field name within the
// secret's JSON document, and everything between is the (possibly
// multi-segment) secret path — Vault paths are conventionally hierarchical,
// so unlike AWS Secrets Manager this doesn't restrict path depth or require
// percent-encoding for an internal "/".
func Parse(raw string) (provider.Reference, error) {
	if strings.ContainsRune(raw, 0) {
		return provider.InvalidParse("reference contains NUL")
	}
	if !strings.HasPrefix(raw, "vault://") {
		return provider.InvalidParse("unknown Vault reference scheme")
	}
	rest := strings.TrimPrefix(raw, "vault://")
	parts := strings.Split(rest, "/")
	if len(parts) < 3 {
		return provider.InvalidParse("Vault reference requires mount/path/key")
	}
	mount := parts[0]
	key := parts[len(parts)-1]
	path := strings.Join(parts[1:len(parts)-1], "/")
	if mount == "" || path == "" || key == "" {
		return provider.InvalidParse("Vault reference requires a non-empty mount, path, and key")
	}
	return provider.Reference{Scheme: "vault", Region: mount, Container: path, Key: key, AdapterKey: adapterKey}, nil
}
