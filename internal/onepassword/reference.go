package onepassword

import (
	"context"
	"os"
	"strings"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/version"
)

type Factory struct{}

func (Factory) CapabilityPrefixes() []string { return []string{"OP_"} }

func (Factory) Parse(raw string) (provider.Reference, error) { return Parse(raw) }

func (Factory) Adapter(ctx context.Context, _ provider.Reference) (provider.Adapter, error) {
	return New(ctx)
}

func Parse(raw string) (provider.Reference, error) {
	if strings.ContainsRune(raw, 0) {
		return provider.InvalidParse("reference contains NUL")
	}
	if !strings.HasPrefix(raw, "op://") {
		return provider.InvalidParse("1Password reference must start with op://")
	}
	resource, query, hasQuery := strings.Cut(strings.TrimPrefix(raw, "op://"), "?")
	parts := strings.Split(resource, "/")
	if len(parts) < 2 {
		return provider.InvalidParse("1Password reference requires vault/item[/field]")
	}
	for _, part := range parts {
		if part == "" {
			return provider.InvalidParse("1Password vault, item, and field segments must not be empty")
		}
	}
	key, err := parseKey(parts, query, hasQuery)
	if err != nil {
		return provider.Reference{}, err
	}
	return provider.Reference{Scheme: "op", Region: parts[0], Container: parts[1], Key: key, AdapterKey: "op"}, nil
}
func parseKey(parts []string, query string, hasQuery bool) (string, error) {
	if !hasQuery {
		if len(parts) > 2 {
			return strings.Join(parts[2:], "/"), nil
		}
		return "", nil
	}
	if len(parts) != 2 {
		return "", invalidReference("1Password content selectors require an item-only path")
	}
	switch {
	case query == "notes":
		return notesSelector, nil
	case query == "document":
		return documentSelector, nil
	case strings.HasPrefix(query, "file="):
		return parseFileSelector(strings.TrimPrefix(query, "file="))
	default:
		return "", invalidReference("unknown 1Password content selector")
	}
}
func parseFileSelector(selector string) (string, error) {
	for _, segment := range strings.Split(selector, "/") {
		if segment == "" || strings.ContainsRune(segment, '?') {
			return "", invalidReference("1Password file selector requires non-empty path segments")
		}
	}
	return fileSelectorPrefix + selector, nil
}
func invalidReference(message string) error { _, err := provider.InvalidParse(message); return err }

func New(ctx context.Context) (*Adapter, error) {
	options, err := clientOptions(os.Getenv("OP_SERVICE_ACCOUNT_TOKEN"), os.Getenv("OP_ACCOUNT"))
	if err != nil {
		return nil, err
	}
	options = append(options, op.WithIntegrationInfo("uno", version.Current))
	client, err := op.NewClient(ctx, options...)
	if err != nil {
		return nil, &provider.Error{Kind: provider.Authentication}
	}
	api := sdkAPI{client}
	return &Adapter{lookup: api, mutation: api}, nil
}

func clientOptions(token, account string) ([]op.ClientOption, error) {
	if token != "" {
		return []op.ClientOption{op.WithServiceAccountToken(token)}, nil
	}
	if account != "" {
		return []op.ClientOption{op.WithDesktopAppIntegration(account)}, nil
	}
	return nil, &provider.Error{Kind: provider.Authentication}
}
