// Package onepassword adapts explicit 1Password Secure Note references.
package onepassword

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

type Factory struct{}

func (Factory) Parse(raw string) (provider.Reference, error) { return Parse(raw) }
func (Factory) Adapter(ctx context.Context, ref provider.Reference) (provider.Adapter, error) {
	return New(ctx, ref)
}

func Parse(raw string) (provider.Reference, error) {
	if !strings.HasPrefix(raw, "op://") || strings.ContainsRune(raw, 0) {
		return invalid()
	}
	parts := strings.Split(strings.TrimPrefix(raw, "op://"), "/")
	if len(parts) < 2 {
		return invalid()
	}
	for _, part := range parts {
		if part == "" {
			return invalid()
		}
	}
	key := ""
	if len(parts) > 2 {
		key = strings.Join(parts[2:], "/")
	}
	return provider.Reference{Scheme: "op", Region: parts[0], Container: parts[1], Key: key}, nil
}

type API interface {
	ListVaults(context.Context) ([]op.VaultOverview, error)
	ListItems(context.Context, string) ([]op.ItemOverview, error)
	GetItem(context.Context, string, string) (op.Item, error)
	PutItem(context.Context, op.Item) (op.Item, error)
}
type sdkAPI struct{ c *op.Client }

func (s sdkAPI) ListVaults(c context.Context) ([]op.VaultOverview, error) {
	return s.c.Vaults().List(c)
}
func (s sdkAPI) ListItems(c context.Context, v string) ([]op.ItemOverview, error) {
	return s.c.Items().List(c, v)
}
func (s sdkAPI) GetItem(c context.Context, v, i string) (op.Item, error) {
	return s.c.Items().Get(c, v, i)
}
func (s sdkAPI) PutItem(c context.Context, i op.Item) (op.Item, error) { return s.c.Items().Put(c, i) }

func New(ctx context.Context, _ provider.Reference) (*Adapter, error) {
	token, account := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN"), os.Getenv("OP_ACCOUNT")
	var options []op.ClientOption
	switch selectAuthentication(token, account) {
	case authServiceAccount:
		options = append(options, op.WithServiceAccountToken(token))
	case authDesktop:
		options = append(options, op.WithDesktopAppIntegration(account))
	case authMissing:
		return nil, &provider.Error{Kind: provider.Authentication}
	}
	options = append(options, op.WithIntegrationInfo("uno", "0.1.0"))
	client, err := op.NewClient(ctx, options...)
	if err != nil {
		return nil, &provider.Error{Kind: provider.Authentication}
	}
	return &Adapter{api: sdkAPI{client}}, nil
}

type authentication int

const (
	authMissing authentication = iota
	authDesktop
	authServiceAccount
)

func selectAuthentication(token, account string) authentication {
	if token != "" {
		return authServiceAccount
	}
	if account != "" {
		return authDesktop
	}
	return authMissing
}

type Adapter struct{ api API }

func NewWithAPI(api API) *Adapter { return &Adapter{api: api} }
func (a *Adapter) Read(ctx context.Context, ref provider.Reference) (secret.Value, error) {
	values, err := a.ReadMany(ctx, []provider.Reference{ref})
	if err != nil {
		return secret.Value{}, err
	}
	return values[0], nil
}
func (a *Adapter) Write(ctx context.Context, w []provider.Write) (provider.Receipt, error) {
	return a.WriteMany(ctx, w)
}
func (a *Adapter) resolveVault(ctx context.Context, name string) (string, error) {
	vaults, err := a.api.ListVaults(ctx)
	if err != nil {
		return "", remote()
	}
	ids := []string{}
	for _, vault := range vaults {
		if vault.ID == name || vault.Title == name {
			ids = append(ids, vault.ID)
		}
	}
	if len(ids) == 0 {
		return "", &provider.Error{Kind: provider.InvalidBinding}
	}
	if len(ids) > 1 {
		return "", &provider.Error{Kind: provider.Ambiguous}
	}
	return ids[0], nil
}
func (a *Adapter) load(ctx context.Context, ref provider.Reference) (*op.Item, error) {
	vault, err := a.resolveVault(ctx, ref.Region)
	if err != nil {
		return nil, err
	}
	items, err := a.api.ListItems(ctx, vault)
	if err != nil {
		return nil, remote()
	}
	ids := []string{}
	for _, item := range items {
		if item.ID == ref.Container || item.Title == ref.Container {
			ids = append(ids, item.ID)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	if len(ids) > 1 {
		return nil, &provider.Error{Kind: provider.Ambiguous}
	}
	item, err := a.api.GetItem(ctx, vault, ids[0])
	if err != nil {
		return nil, remote()
	}
	return &item, nil
}
func (a *Adapter) ReadMany(ctx context.Context, refs []provider.Reference) ([]secret.Value, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	item, err := a.load(ctx, refs[0])
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, &provider.Error{Kind: provider.InvalidBinding}
	}
	if item.Category != op.ItemCategorySecureNote {
		return nil, &provider.Error{Kind: provider.InvalidState}
	}
	values := make([]secret.Value, 0, len(refs))
	fail := func(err error) ([]secret.Value, error) {
		for i := range values {
			values[i].Destroy()
		}
		return nil, err
	}
	for _, ref := range refs {
		if ref.Container != refs[0].Container {
			return fail(&provider.Error{Kind: provider.InvalidBinding})
		}
		if ref.Blob() {
			values = append(values, secret.New(item.Notes))
			continue
		}
		section, field := splitKey(ref.Key)
		sectionID, err := findSection(item, section)
		if err != nil {
			return fail(err)
		}
		matches := []op.ItemField{}
		for _, candidate := range item.Fields {
			if (candidate.ID == field || candidate.Title == field) && candidate.FieldType == op.ItemFieldTypeConcealed && sameSection(candidate.SectionID, sectionID) {
				matches = append(matches, candidate)
			}
		}
		if len(matches) == 0 {
			return fail(&provider.Error{Kind: provider.InvalidBinding})
		}
		if len(matches) > 1 {
			return fail(&provider.Error{Kind: provider.Ambiguous})
		}
		values = append(values, secret.New(matches[0].Value))
	}
	return values, nil
}
func (a *Adapter) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	if len(writes) == 0 {
		return provider.Receipt{}, nil
	}
	provider.SortedWrites(writes)
	for range 3 {
		item, err := a.load(ctx, writes[0].Reference)
		if err != nil {
			return provider.Receipt{}, err
		}
		if item == nil {
			return provider.Receipt{}, &provider.Error{Kind: provider.InvalidBinding}
		}
		if item.Category != op.ItemCategorySecureNote {
			return provider.Receipt{}, &provider.Error{Kind: provider.InvalidState}
		}
		if writes[0].Reference.Blob() {
			item.Notes = writes[0].Value.Reveal()
		} else if err := updateFields(item, writes); err != nil {
			return provider.Receipt{}, err
		}
		if _, err := a.api.PutItem(ctx, *item); err == nil {
			return provider.Receipt{Completed: environments(writes)}, nil
		}
	}
	return provider.Receipt{}, remote()
}
func updateFields(item *op.Item, writes []provider.Write) error {
	for _, write := range writes {
		section, field := splitKey(write.Reference.Key)
		sectionID, err := ensureSection(item, section)
		if err != nil {
			return err
		}
		matches := []int{}
		for i, candidate := range item.Fields {
			if (candidate.ID == field || candidate.Title == field) && candidate.FieldType == op.ItemFieldTypeConcealed && sameSection(candidate.SectionID, sectionID) {
				matches = append(matches, i)
			}
		}
		if len(matches) > 1 {
			return &provider.Error{Kind: provider.Ambiguous}
		}
		if len(matches) == 1 {
			item.Fields[matches[0]].Value = write.Value.Reveal()
		} else {
			item.Fields = append(item.Fields, op.ItemField{ID: field, Title: field, SectionID: sectionID, FieldType: op.ItemFieldTypeConcealed, Value: write.Value.Reveal()})
		}
	}
	return nil
}
func splitKey(key string) (string, string) {
	i := strings.LastIndexByte(key, '/')
	if i < 0 {
		return "", key
	}
	return key[:i], key[i+1:]
}
func findSection(item *op.Item, title string) (*string, error) {
	if title == "" {
		return nil, nil
	}
	ids := []string{}
	for _, section := range item.Sections {
		if section.ID == title || section.Title == title {
			ids = append(ids, section.ID)
		}
	}
	if len(ids) == 0 {
		return nil, &provider.Error{Kind: provider.InvalidBinding}
	}
	if len(ids) > 1 {
		return nil, &provider.Error{Kind: provider.Ambiguous}
	}
	return &ids[0], nil
}
func ensureSection(item *op.Item, title string) (*string, error) {
	if title == "" {
		return nil, nil
	}
	id, err := findSection(item, title)
	var typed *provider.Error
	if err == nil {
		return id, nil
	}
	if !errors.As(err, &typed) || typed.Kind != provider.InvalidBinding {
		return nil, err
	}
	item.Sections = append(item.Sections, op.ItemSection{ID: sectionID(len(item.Sections)), Title: title})
	return &item.Sections[len(item.Sections)-1].ID, nil
}
func sectionID(index int) string { return fmt.Sprintf("uno-%d", index) }
func sameSection(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
func environments(w []provider.Write) []string {
	out := make([]string, 0, len(w))
	for _, x := range w {
		out = append(out, x.Environment)
	}
	sort.Strings(out)
	return out
}
func invalid() (provider.Reference, error) {
	return provider.Reference{}, &provider.Error{Kind: provider.InvalidBinding}
}
func remote() error { return &provider.Error{Kind: provider.Indeterminate} }
