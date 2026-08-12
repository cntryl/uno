package onepassword

import (
	"context"
	"errors"
	"testing"

	op "github.com/1password/onepassword-sdk-go"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

type fakeAPI struct {
	vaults  []op.VaultOverview
	items   []op.ItemOverview
	item    op.Item
	created op.ItemCreateParams
	puts    int
}

func (f *fakeAPI) ListVaults(context.Context) ([]op.VaultOverview, error)       { return f.vaults, nil }
func (f *fakeAPI) ListItems(context.Context, string) ([]op.ItemOverview, error) { return f.items, nil }
func (f *fakeAPI) GetItem(context.Context, string, string) (op.Item, error)     { return f.item, nil }
func (f *fakeAPI) CreateItem(_ context.Context, p op.ItemCreateParams) (op.Item, error) {
	f.created = p
	return op.Item{ID: "new"}, nil
}
func (f *fakeAPI) PutItem(_ context.Context, item op.Item) (op.Item, error) {
	f.puts++
	f.item = item
	return item, nil
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
func TestReadsNoteAndDeepConcealedField(t *testing.T) {
	fake := baseFake()
	a := NewWithAPI(fake)
	note, err := a.Read(context.Background(), provider.Reference{Region: "Production", Container: "service"})
	if err != nil || note.Reveal() != "note" {
		t.Fatalf("note=%q err=%v", note.Reveal(), err)
	}
	value, err := a.Read(context.Background(), provider.Reference{Region: "Production", Container: "service", Key: "path1/path2/FIELD"})
	if err != nil || value.Reveal() != "old" {
		t.Fatalf("value=%q err=%v", value.Reveal(), err)
	}
}
func TestGroupedUpdatePreservesFieldsAndSections(t *testing.T) {
	fake := baseFake()
	a := NewWithAPI(fake)
	writes := []provider.Write{{Environment: "A", Reference: provider.Reference{Region: "Production", Container: "service", Key: "path1/path2/FIELD"}, Value: secret.New("new")}, {Environment: "B", Reference: provider.Reference{Region: "Production", Container: "service", Key: "new/path/SECOND"}, Value: secret.New("two")}}
	receipt, err := a.Write(context.Background(), writes)
	if err != nil || fake.puts != 1 || len(receipt.Completed) != 2 || fake.item.Fields[0].Value != "untouched" || fake.item.Fields[1].Value != "new" || len(fake.item.Sections) != 2 {
		t.Fatalf("item=%#v receipt=%#v err=%v", fake.item, receipt, err)
	}
}
func TestMissingItemIsNotCreated(t *testing.T) {
	fake := baseFake()
	fake.items = nil
	a := NewWithAPI(fake)
	_, err := a.Write(context.Background(), []provider.Write{{Environment: "K", Reference: provider.Reference{Region: "Production", Container: "new"}, Value: secret.New("body")}})
	if err == nil || fake.created.Notes != nil {
		t.Fatalf("created=%#v err=%v", fake.created, err)
	}
}
func TestAmbiguityAndAuthenticationPrecedence(t *testing.T) {
	fake := baseFake()
	fake.vaults = append(fake.vaults, op.VaultOverview{ID: "v2", Title: "Production"})
	_, err := NewWithAPI(fake).Read(context.Background(), provider.Reference{Region: "Production", Container: "service"})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.Ambiguous {
		t.Fatalf("err=%v", err)
	}
	if selectAuthentication("token", "account") != authServiceAccount || selectAuthentication("", "account") != authDesktop {
		t.Fatal("authentication precedence")
	}
}
