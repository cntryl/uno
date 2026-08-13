package onepassword

import (
	"context"
	"errors"
	"testing"
	"time"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

type fakeAPI struct {
	vaults         []op.VaultOverview
	items          []op.ItemOverview
	item           op.Item
	created        op.ItemCreateParams
	puts           int
	putFailures    int
	putVersions    []uint32
	typedConflicts bool
	vaultLists     int
	itemLists      int
}

type fakeVersionConflictError struct{}

func (fakeVersionConflictError) Error() string         { return "conflict" }
func (fakeVersionConflictError) VersionConflict() bool { return true }

func (f *fakeAPI) ListVaults(context.Context) ([]op.VaultOverview, error) {
	f.vaultLists++
	return f.vaults, nil
}
func (f *fakeAPI) ListItems(context.Context, string) ([]op.ItemOverview, error) {
	f.itemLists++
	return f.items, nil
}
func (f *fakeAPI) GetItem(context.Context, string, string) (op.Item, error) { return f.item, nil }
func (f *fakeAPI) CreateItem(_ context.Context, p op.ItemCreateParams) (op.Item, error) {
	f.created = p
	return op.Item{ID: "new"}, nil
}
func (f *fakeAPI) PutItem(_ context.Context, item op.Item) (op.Item, error) {
	f.puts++
	f.putVersions = append(f.putVersions, item.Version)
	if f.puts <= f.putFailures {
		f.item.Version++
		if f.typedConflicts {
			return op.Item{}, fakeVersionConflictError{}
		}
		return op.Item{}, errors.New("version conflict")
	}
	f.item = item
	return item, nil
}

func TestWriteReloadsCurrentVersionAfterConflict(t *testing.T) {
	fake := baseFake()
	fake.item.Version = 7
	fake.putFailures = 1
	fake.typedConflicts = true
	writes := []provider.Write{{Environment: "MY_API_KEY", Reference: provider.Reference{Region: "Production", Container: "service", Key: "path1/path2/FIELD"}, Value: secret.New("new")}}
	a := NewWithAPI(fake)
	a.jitter = func(time.Duration) time.Duration { return 0 }
	a.wait = func(context.Context, time.Duration) error { return nil }
	if _, err := a.WriteMany(context.Background(), writes); err != nil {
		t.Fatal(err)
	}
	if got := fake.putVersions; len(got) != 2 || got[0] != 7 || got[1] != 8 {
		t.Fatalf("put versions=%v", got)
	}
}

func TestGenericWriteFailureIsNotRetried(t *testing.T) {
	fake := baseFake()
	fake.putFailures = 4
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Region: "Production", Container: "service"}, Value: secret.New("new")}
	if _, err := NewWithAPI(fake).WriteMany(context.Background(), []provider.Write{write}); err == nil || fake.puts != 1 {
		t.Fatalf("puts=%d err=%v", fake.puts, err)
	}
}

func TestTypedConflictAllowsThreeRetries(t *testing.T) {
	fake := baseFake()
	fake.putFailures = 4
	fake.typedConflicts = true
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Region: "Production", Container: "service"}, Value: secret.New("new")}
	a := NewWithAPI(fake)
	a.jitter = func(time.Duration) time.Duration { return 0 }
	a.wait = func(context.Context, time.Duration) error { return nil }
	if _, err := a.WriteMany(context.Background(), []provider.Write{write}); err == nil || fake.puts != 4 {
		t.Fatalf("puts=%d err=%v", fake.puts, err)
	}
}

func TestTypedConflictBackoffIsBoundedAndHasNoFinalWait(t *testing.T) {
	fake := baseFake()
	fake.putFailures = 4
	fake.typedConflicts = true
	a := NewWithAPI(fake)
	var caps []time.Duration
	a.jitter = func(ceiling time.Duration) time.Duration { caps = append(caps, ceiling); return ceiling }
	a.wait = func(context.Context, time.Duration) error { return nil }
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Region: "Production", Container: "service"}, Value: secret.New("new")}
	_, err := a.WriteMany(context.Background(), []provider.Write{write})
	if err == nil || fake.puts != 4 || len(caps) != 3 || caps[0] != 200*time.Millisecond || caps[1] != 400*time.Millisecond || caps[2] != 800*time.Millisecond {
		t.Fatalf("puts=%d caps=%v err=%v", fake.puts, caps, err)
	}
}

func TestTypedConflictCancellationDuringBackoffIsIndeterminate(t *testing.T) {
	fake := baseFake()
	fake.putFailures = 4
	fake.typedConflicts = true
	a := NewWithAPI(fake)
	a.jitter = func(time.Duration) time.Duration { return 0 }
	a.wait = func(context.Context, time.Duration) error { return context.Canceled }
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Region: "Production", Container: "service"}, Value: secret.New("new")}
	_, err := a.WriteMany(context.Background(), []provider.Write{write})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.Indeterminate || fake.puts != 1 {
		t.Fatalf("puts=%d err=%v", fake.puts, err)
	}
}
func baseFake() *fakeAPI {
	return &fakeAPI{
		vaults: []op.VaultOverview{{ID: "v1", Title: "Production"}},
		items:  []op.ItemOverview{{ID: "i1", Title: "service"}},
		item: op.Item{ID: "i1", VaultID: "v1", Title: "service", Category: op.ItemCategorySecureNote, Notes: "note",
			Sections: []op.ItemSection{{ID: "section", Title: "path1/path2"}},
			Fields: []op.ItemField{
				{ID: "KEEP", Title: "KEEP", FieldType: op.ItemFieldTypeText, Value: "untouched"},
				{ID: "FIELD", Title: "FIELD", SectionID: stringPtr("section"), FieldType: op.ItemFieldTypeConcealed, Value: "old"},
			},
		},
	}
}
func stringPtr(s string) *string { return &s }

func TestParseNoteFieldAndDeepPath(t *testing.T) {
	for _, raw := range []string{"op://vault/item", "op://vault/item/field", "op://vault/item/path1/path2/field"} {
		if _, err := Parse(raw); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}

func FuzzParseReference(f *testing.F) {
	for _, seed := range []string{
		"op://vault/item",
		"op://vault/item/field",
		"op://vault/item/path1/path2/field",
		"op://",
		"op://vault//field",
		"op://vault/item\x00/field",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ref, err := Parse(raw)
		if err == nil && (ref.Scheme != "op" || ref.Region == "" || ref.Container == "") {
			t.Fatalf("successful parse returned incomplete reference")
		}
	})
}

func TestReadsNoteAndDeepConcealedField(t *testing.T) {
	fake := baseFake()
	a := NewWithAPI(fake)
	noteRef := provider.Reference{Region: "Production", Container: "service"}
	notes, err := a.ReadMany(context.Background(), []provider.Reference{noteRef})
	if err != nil || notes[noteRef.Binding()].Reveal() != "note" {
		t.Fatalf("note=%q err=%v", notes[noteRef.Binding()].Reveal(), err)
	}
	fieldRef := provider.Reference{Region: "Production", Container: "service", Key: "path1/path2/FIELD"}
	values, err := a.ReadMany(context.Background(), []provider.Reference{fieldRef})
	if err != nil || values[fieldRef.Binding()].Reveal() != "old" {
		t.Fatalf("value=%q err=%v", values[fieldRef.Binding()].Reveal(), err)
	}
}
func TestGroupedUpdatePreservesFieldsAndSections(t *testing.T) {
	fake := baseFake()
	a := NewWithAPI(fake)
	writes := []provider.Write{{Environment: "A", Reference: provider.Reference{Region: "Production", Container: "service", Key: "path1/path2/FIELD"}, Value: secret.New("new")}, {Environment: "B", Reference: provider.Reference{Region: "Production", Container: "service", Key: "new/path/SECOND"}, Value: secret.New("two")}}
	receipt, err := a.WriteMany(context.Background(), writes)
	if err != nil || fake.puts != 1 || len(receipt.Completed) != 2 || fake.item.Fields[0].Value != "untouched" || fake.item.Fields[1].Value != "new" || len(fake.item.Sections) != 2 {
		t.Fatalf("item=%#v receipt=%#v err=%v", fake.item, receipt, err)
	}
}

func TestWriteIgnoresNonConcealedFieldCollisionLikeRead(t *testing.T) {
	fake := baseFake()
	fake.item.Fields[1] = op.ItemField{
		ID:        "MY_API_KEY",
		Title:     "MY_API_KEY",
		SectionID: stringPtr("section"),
		FieldType: op.ItemFieldTypeText,
		Value:     "plaintext",
	}
	writes := []provider.Write{{
		Environment: "MY_API_KEY",
		Reference:   provider.Reference{Region: "Production", Container: "service", Key: "path1/path2/MY_API_KEY"},
		Value:       secret.New("replacement"),
	}}

	_, err := NewWithAPI(fake).WriteMany(context.Background(), writes)
	if err != nil || fake.puts != 1 || len(fake.item.Fields) != 3 || fake.item.Fields[2].FieldType != op.ItemFieldTypeConcealed {
		t.Fatalf("fields=%#v", fake.item.Fields)
	}
}

func TestNewSectionIDDoesNotCollideWithExistingIDs(t *testing.T) {
	fake := baseFake()
	fake.item.Sections = []op.ItemSection{{ID: "uno-1", Title: "existing"}}
	write := provider.Write{Environment: "KEY", Reference: provider.Reference{Region: "Production", Container: "service", Key: "new/KEY"}, Value: secret.New("new")}
	if _, err := NewWithAPI(fake).WriteMany(context.Background(), []provider.Write{write}); err != nil {
		t.Fatal(err)
	}
	if got := fake.item.Sections[1].ID; got == "uno-1" {
		t.Fatalf("colliding section ID %q", got)
	}
}

func TestAdapterCachesVaultAndItemListings(t *testing.T) {
	fake := baseFake()
	a := NewWithAPI(fake)
	refs := []provider.Reference{{Region: "Production", Container: "service"}}
	if _, err := a.ReadMany(context.Background(), refs); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadMany(context.Background(), refs); err != nil {
		t.Fatal(err)
	}
	if fake.vaultLists != 1 || fake.itemLists != 1 {
		t.Fatalf("vault lists=%d item lists=%d", fake.vaultLists, fake.itemLists)
	}
}

func TestMissingItemIsNotCreated(t *testing.T) {
	fake := baseFake()
	fake.items = nil
	a := NewWithAPI(fake)
	_, err := a.WriteMany(context.Background(), []provider.Write{{Environment: "K", Reference: provider.Reference{Region: "Production", Container: "new"}, Value: secret.New("body")}})
	if err == nil || fake.created.Notes != nil {
		t.Fatalf("created=%#v err=%v", fake.created, err)
	}
}
func TestAmbiguityAndAuthenticationPrecedence(t *testing.T) {
	fake := baseFake()
	fake.vaults = append(fake.vaults, op.VaultOverview{ID: "v2", Title: "Production"})
	_, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{{Region: "Production", Container: "service"}})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.Ambiguous {
		t.Fatalf("err=%v", err)
	}
	if options, optionErr := clientOptions("token", "account"); optionErr != nil || len(options) != 1 {
		t.Fatal("service-account authentication precedence")
	}
	if options, optionErr := clientOptions("", "account"); optionErr != nil || len(options) != 1 {
		t.Fatal("desktop authentication")
	}
	if _, optionErr := clientOptions("", ""); optionErr == nil {
		t.Fatal("missing authentication")
	}
}
