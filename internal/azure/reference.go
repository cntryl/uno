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
		return provider.InvalidParse("reference contains NUL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "azure-key-vault" || u.Opaque != "" {
		return provider.InvalidParse("unknown Azure Key Vault reference scheme")
	}
	if err := validateURL(u); err != nil {
		return provider.Reference{}, err
	}
	host := strings.ToLower(u.Hostname())
	if err := validateHost(host); err != nil {
		return provider.Reference{}, err
	}
	if u.EscapedPath() != u.Path {
		return provider.InvalidParse("Azure Key Vault path must not be escaped")
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	container, key, err := parsePath(parts)
	if err != nil {
		return provider.Reference{}, err
	}
	return provider.Reference{Scheme: "azure-key-vault", Region: host, Container: container, Key: key, AdapterKey: host}, nil
}
func validateURL(u *url.URL) error {
	if u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" {
		return invalid("Azure Key Vault reference contains unsupported URL data")
	}
	return nil
}
func validateHost(host string) error {
	if host == "" || net.ParseIP(host) != nil || !canonicalVaultHost(host) {
		return invalid("Azure Key Vault reference requires a canonical vault hostname")
	}
	return nil
}
func parsePath(parts []string) (string, string, error) {
	if len(parts) < 1 || len(parts) > 2 || parts[0] == "" || !secretNamePattern.MatchString(parts[0]) {
		return "", "", invalid("Azure Key Vault reference requires secret-name[/key]")
	}
	if len(parts) == 1 {
		return parts[0], "", nil
	}
	if parts[1] == "" {
		return "", "", invalid("Azure Key Vault key must not be empty")
	}
	return parts[0], parts[1], nil
}
func invalid(message string) error { _, err := provider.InvalidParse(message); return err }

func canonicalVaultHost(host string) bool {
	for _, suffix := range []string{".vault.azure.net", ".vault.usgovcloudapi.net", ".vault.azure.cn", ".vault.microsoftazure.de"} {
		if strings.HasSuffix(host, suffix) {
			name := strings.TrimSuffix(host, suffix)
			return name != "" && len(name) <= 63 && vaultNamePattern.MatchString(name)
		}
	}
	return false
}
