// Package gcp adapts explicit Google Cloud Secret Manager references.
package gcp

import (
	"context"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"

	"github.com/cntryl/uno/internal/core/provider"
)

// adapterKey is constant across every reference: one client, authenticated
// via Application Default Credentials, serves every project — the project
// is part of each request's resource name, not baked into the client.
const adapterKey = "gcp-secret-manager"

type Factory struct{}

func (Factory) CapabilityPrefixes() []string { return []string{"GOOGLE_"} }

func (Factory) Parse(raw string) (provider.Reference, error) { return Parse(raw) }

func (Factory) Adapter(ctx context.Context, ref provider.Reference) (provider.Adapter, error) {
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, &provider.Error{Kind: provider.Authentication}
	}
	return &SecretManager{C: client}, nil
}

// Parse accepts gcp-secret-manager://project/secret-name[/key]. GCP secret
// IDs may not contain "/", so unlike AWS Secrets Manager this never needs
// percent-encoding for the container segment.
func Parse(raw string) (provider.Reference, error) {
	if strings.ContainsRune(raw, 0) {
		return provider.InvalidParse("reference contains NUL")
	}
	if !strings.HasPrefix(raw, "gcp-secret-manager://") {
		return provider.InvalidParse("unknown GCP Secret Manager reference scheme")
	}
	rest := strings.TrimPrefix(raw, "gcp-secret-manager://")
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] == "" || parts[1] == "" {
		return provider.InvalidParse("GCP Secret Manager reference requires project/secret-name[/key]")
	}
	key := ""
	if len(parts) == 3 {
		key = parts[2]
		if key == "" {
			return provider.InvalidParse("GCP Secret Manager key must not be empty")
		}
	}
	return provider.Reference{Scheme: "gcp-secret-manager", Region: parts[0], Container: parts[1], Key: key, AdapterKey: adapterKey}, nil
}
