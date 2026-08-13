// Package onepassword adapts explicit 1Password Secure Note references.
package onepassword

import (
	"context"
	"strings"
	"sync"
	"time"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

type API interface {
	LookupAPI
	MutationAPI
}
type LookupAPI interface {
	ListVaults(context.Context) ([]op.VaultOverview, error)
	ListItems(context.Context, string) ([]op.ItemOverview, error)
	GetItem(context.Context, string, string) (op.Item, error)
}
type MutationAPI interface {
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

type Adapter struct {
	lookup       LookupAPI
	mutation     MutationAPI
	wait         func(context.Context, time.Duration) error
	jitter       func(time.Duration) time.Duration
	cacheMu      sync.Mutex
	vaults       []op.VaultOverview
	vaultsLoaded bool
	items        map[string][]op.ItemOverview
}

func NewWithAPI(api API) *Adapter { return &Adapter{lookup: api, mutation: api} }

func (a *Adapter) waitBeforeRetry(ctx context.Context, attempt int) error {
	return provider.WaitBeforeRetry(ctx, attempt, a.wait, a.jitter)
}
func (a *Adapter) resolveVault(ctx context.Context, name string) (string, error) {
	vaults, err := a.listVaults(ctx)
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

func (a *Adapter) listVaults(ctx context.Context) ([]op.VaultOverview, error) {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	if a.vaultsLoaded {
		return a.vaults, nil
	}
	vaults, err := a.lookup.ListVaults(ctx)
	if err == nil {
		a.vaults = vaults
		a.vaultsLoaded = true
	}
	return vaults, err
}

func (a *Adapter) listItems(ctx context.Context, vault string) ([]op.ItemOverview, error) {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	if items, ok := a.items[vault]; ok {
		return items, nil
	}
	items, err := a.lookup.ListItems(ctx, vault)
	if err == nil {
		if a.items == nil {
			a.items = make(map[string][]op.ItemOverview)
		}
		a.items[vault] = items
	}
	return items, err
}
func (a *Adapter) load(ctx context.Context, ref provider.Reference) (*op.Item, error) {
	vault, err := a.resolveVault(ctx, ref.Region)
	if err != nil {
		return nil, err
	}
	items, err := a.listItems(ctx, vault)
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
	item, err := a.lookup.GetItem(ctx, vault, ids[0])
	if err != nil {
		return nil, remote()
	}
	return &item, nil
}
func (a *Adapter) ReadMany(ctx context.Context, refs []provider.Reference) (map[string]secret.Value, error) {
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
	values := make(map[string]secret.Value, len(refs))
	fail := func(err error) (map[string]secret.Value, error) {
		secret.DestroyMap(values)
		return nil, err
	}
	for _, ref := range refs {
		if ref.Container != refs[0].Container {
			return fail(&provider.Error{Kind: provider.InvalidBinding})
		}
		if ref.Blob() {
			values[ref.Binding()] = secret.New(item.Notes)
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
		values[ref.Binding()] = secret.New(matches[0].Value)
	}
	return values, nil
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
func sameSection(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
func remote() error { return &provider.Error{Kind: provider.Indeterminate} }
