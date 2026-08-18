// Package onepassword adapts 1Password item sources and Secure Note destinations.
package onepassword

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

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
	ReadFile(context.Context, string, string, op.FileAttributes) ([]byte, error)
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
func (s sdkAPI) ReadFile(c context.Context, vault, item string, attributes op.FileAttributes) ([]byte, error) {
	return s.c.Items().Files().Read(c, vault, item, attributes)
}
func (s sdkAPI) PutItem(c context.Context, i op.Item) (op.Item, error) { return s.c.Items().Put(c, i) }

const (
	notesSelector      = "?notes"
	documentSelector   = "?document"
	fileSelectorPrefix = "?file="
)

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
		return "", remote(err)
	}
	ids := []string{}
	for _, vault := range vaults {
		if vault.ID == name || vault.Title == name {
			if vault.ID == "" {
				return "", &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.InvalidResponse}
			}
			ids = append(ids, vault.ID)
		}
	}
	if len(ids) == 0 {
		return "", &provider.Error{Kind: provider.InvalidBinding, Diagnostic: provider.SecretNotFound}
	}
	if len(ids) > 1 {
		return "", &provider.Error{Kind: provider.Ambiguous, Diagnostic: provider.AmbiguousContainer}
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
		return nil, remote(err)
	}
	ids, err := matchingItemIDs(items, ref.Container)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	if len(ids) > 1 {
		return nil, &provider.Error{Kind: provider.Ambiguous, Diagnostic: provider.AmbiguousContainer}
	}
	item, err := a.lookup.GetItem(ctx, vault, ids[0])
	if err != nil {
		return nil, remote(err)
	}
	if item.ID == "" || item.VaultID == "" {
		return nil, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.InvalidResponse}
	}
	return &item, nil
}

func matchingItemIDs(items []op.ItemOverview, name string) ([]string, error) {
	ids := []string{}
	for _, item := range items {
		if item.ID != name && item.Title != name {
			continue
		}
		if item.ID == "" {
			return nil, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.InvalidResponse}
		}
		ids = append(ids, item.ID)
	}
	return ids, nil
}
func (a *Adapter) ReadMany(ctx context.Context, refs []provider.Reference) (map[string]provider.ReadResult, error) {
	return a.readMany(ctx, refs, false)
}

func (a *Adapter) ReadDestinations(ctx context.Context, refs []provider.Reference) (map[string]provider.ReadResult, error) {
	return a.readMany(ctx, refs, true)
}

func (a *Adapter) readMany(ctx context.Context, refs []provider.Reference, destination bool) (map[string]provider.ReadResult, error) {
	if err := provider.ValidateReadGroup(refs); err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, nil
	}
	if err := validateReadMode(refs, destination); err != nil {
		return nil, err
	}
	item, err := a.load(ctx, refs[0])
	if err != nil {
		return nil, err
	}
	if item == nil {
		return provider.MissingResultsWithDiagnostic(refs, provider.SecretNotFound), nil
	}
	if destination && item.Category != op.ItemCategorySecureNote {
		return nil, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.UnsupportedContent}
	}
	values := make(map[string]provider.ReadResult, len(refs))
	fail := func(err error) (map[string]provider.ReadResult, error) {
		provider.DestroyReadResults(values)
		return nil, err
	}
	for index, ref := range refs {
		result, err := a.readReference(ctx, item, ref, destination)
		if err != nil {
			return fail(provider.ReadFailure(index, err))
		}
		values[ref.Binding()] = result
	}
	return values, nil
}
func validateReadMode(refs []provider.Reference, destination bool) error {
	if !destination {
		return nil
	}
	for _, ref := range refs {
		if sourceOnly(ref) {
			return &provider.Error{Kind: provider.InvalidBinding}
		}
	}
	return nil
}
func (a *Adapter) readReference(ctx context.Context, item *op.Item, ref provider.Reference, destination bool) (provider.ReadResult, error) {
	if ref.Key == notesSelector {
		return provider.ReadResult{Value: secret.New(item.Notes), Found: true}, nil
	}
	if ref.Key == documentSelector {
		return a.readDocument(ctx, item)
	}
	if selector, ok := strings.CutPrefix(ref.Key, fileSelectorPrefix); ok {
		return a.readAttachment(ctx, item, selector)
	}
	if ref.Blob() {
		if item.Category != op.ItemCategorySecureNote {
			return provider.ReadResult{}, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.UnsupportedContent}
		}
		return provider.ReadResult{Value: secret.New(item.Notes), Found: true}, nil
	}
	return readField(item, ref.Key, destination)
}
func readField(item *op.Item, key string, destination bool) (provider.ReadResult, error) {
	section, field := splitKey(key)
	sectionID, err := findSection(item, section)
	if err != nil {
		return provider.ReadResult{}, err
	}
	matches := []op.ItemField{}
	for _, candidate := range item.Fields {
		if (candidate.ID == field || candidate.Title == field) && sameSection(candidate.SectionID, sectionID) && (!destination || candidate.FieldType == op.ItemFieldTypeConcealed) {
			matches = append(matches, candidate)
		}
	}
	if len(matches) == 0 {
		return provider.ReadResult{Diagnostic: provider.FieldNotFound}, nil
	}
	if len(matches) > 1 {
		return provider.ReadResult{}, &provider.Error{Kind: provider.Ambiguous, Diagnostic: provider.AmbiguousField}
	}
	return provider.ReadResult{Value: secret.New(matches[0].Value), Found: true}, nil
}

func (a *Adapter) readDocument(ctx context.Context, item *op.Item) (provider.ReadResult, error) {
	if item.Category != op.ItemCategoryDocument {
		return provider.ReadResult{}, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.UnsupportedContent}
	}
	if item.Document == nil {
		return provider.ReadResult{Diagnostic: provider.FileNotFound}, nil
	}
	return a.readFile(ctx, item, *item.Document)
}

func (a *Adapter) readAttachment(ctx context.Context, item *op.Item, selector string) (provider.ReadResult, error) {
	section, file := splitKey(selector)
	sectionID, err := findSection(item, section)
	if err != nil {
		return provider.ReadResult{}, err
	}
	matches := make([]op.FileAttributes, 0, 1)
	for _, candidate := range item.Files {
		candidateSection := &candidate.SectionID
		if sameSection(candidateSection, sectionID) && (candidate.FieldID == file || candidate.Attributes.ID == file || candidate.Attributes.Name == file) {
			matches = append(matches, candidate.Attributes)
		}
	}
	if len(matches) == 0 {
		return provider.ReadResult{Diagnostic: provider.FileNotFound}, nil
	}
	if len(matches) > 1 {
		return provider.ReadResult{}, &provider.Error{Kind: provider.Ambiguous, Diagnostic: provider.AmbiguousFile}
	}
	return a.readFile(ctx, item, matches[0])
}

func (a *Adapter) readFile(ctx context.Context, item *op.Item, attributes op.FileAttributes) (provider.ReadResult, error) {
	content, err := a.lookup.ReadFile(ctx, item.VaultID, item.ID, attributes)
	defer secret.DestroyBytes(content)
	if err != nil {
		return provider.ReadResult{}, remote(err)
	}
	if bytes.IndexByte(content, 0) >= 0 || !utf8.Valid(content) {
		return provider.ReadResult{}, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.UnsupportedContent}
	}
	return provider.ReadResult{Value: secret.NewBytes(content), Found: true}, nil
}

func sourceOnly(ref provider.Reference) bool {
	return ref.Key == notesSelector || ref.Key == documentSelector || strings.HasPrefix(ref.Key, fileSelectorPrefix)
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
		return nil, &provider.Error{Kind: provider.InvalidBinding, Diagnostic: provider.SectionNotFound}
	}
	if len(ids) > 1 {
		return nil, &provider.Error{Kind: provider.Ambiguous, Diagnostic: provider.AmbiguousSection}
	}
	return &ids[0], nil
}
func sameSection(a, b *string) bool {
	section := func(value *string) string {
		if value == nil {
			return ""
		}
		return *value
	}
	return section(a) == section(b)
}
func remote(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return &provider.Error{Kind: provider.Indeterminate}
}
