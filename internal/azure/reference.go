// Package azure adapts explicit Azure Key Vault secret references.
package azure

import (
	"context"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/cntryl/uno/internal/core/provider"
)

var (
	secretNamePattern = regexp.MustCompile(`^[0-9A-Za-z-]{1,127}$`)
	vaultNamePattern  = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
)

type Factory struct{}

func (Factory) CapabilityPrefixes() []string                 { return []string{"AZURE_"} }
func (Factory) Parse(raw string) (provider.Reference, error) { return Parse(raw) }
func (Factory) Adapter(ctx context.Context, ref provider.Reference) (provider.Adapter, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, &provider.Error{Kind: provider.Authentication}
	}
	client, err := azsecrets.NewClient("https://"+ref.Region, credential, nil)
	if err != nil {
		return nil, &provider.Error{Kind: provider.Authentication}
	}
	return &KeyVault{C: &sdkClient{client: client}}, nil
}

func Parse(raw string) (provider.Reference, error) {
	if strings.ContainsRune(raw, 0) {
		return invalidReference("reference contains NUL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "azure-key-vault" || u.Opaque != "" {
		return invalidReference("unknown Azure Key Vault reference scheme")
	}
	if u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return invalidReference("Azure Key Vault reference contains unsupported URL data")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || net.ParseIP(host) != nil || !canonicalVaultHost(host) {
		return invalidReference("Azure Key Vault reference requires a canonical vault hostname")
	}
	if u.EscapedPath() != u.Path {
		return invalidReference("Azure Key Vault path must not be escaped")
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" || !secretNamePattern.MatchString(parts[0]) {
		return invalidReference("Azure Key Vault reference requires secret-name[/key]")
	}
	key := ""
	if len(parts) == 2 {
		key = parts[1]
		if key == "" {
			return invalidReference("Azure Key Vault key must not be empty")
		}
	}
	return provider.Reference{Scheme: "azure-key-vault", Region: host, Container: parts[0], Key: key, AdapterKey: host}, nil
}

func canonicalVaultHost(host string) bool {
	for _, suffix := range []string{".vault.azure.net", ".vault.usgovcloudapi.net", ".vault.azure.cn", ".vault.microsoftazure.de"} {
		if strings.HasSuffix(host, suffix) {
			name := strings.TrimSuffix(host, suffix)
			return name != "" && len(name) <= 63 && vaultNamePattern.MatchString(name)
		}
	}
	return false
}

func invalidReference(detail string) (provider.Reference, error) {
	return provider.Reference{}, provider.InvalidReference(detail)
}
