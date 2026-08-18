package onepassword

import (
	"bytes"
	"context"
	"errors"
	"strings"
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
	itemGets       int
	fileContents   map[string][]byte
	fileReads      []string
	fileErr        error
	vaultErr       error
	itemListErr    error
	itemGetErr     error
}

type fakeVersionConflictError struct{}

func (fakeVersionConflictError) Error() string         { return "conflict" }
func (fakeVersionConflictError) VersionConflict() bool { return true }

func (f *fakeAPI) ListVaults(context.Context) ([]op.VaultOverview, error) {
	f.vaultLists++
	return f.vaults, f.vaultErr
}
func (f *fakeAPI) ListItems(context.Context, string) ([]op.ItemOverview, error) {
	f.itemLists++
	return f.items, f.itemListErr
}
func (f *fakeAPI) GetItem(context.Context, string, string) (op.Item, error) {
	f.itemGets++
	return f.item, f.itemGetErr
}
func (f *fakeAPI) ReadFile(_ context.Context, _, _ string, attributes op.FileAttributes) ([]byte, error) {
	f.fileReads = append(f.fileReads, attributes.ID)
	return f.fileContents[attributes.ID], f.fileErr
}
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

func TestShouldRetryWriteWithReloadedVersionGivenTypedVersionConflict(t *testing.T) {
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

func TestShouldNotRetryGivenGenericPutError(t *testing.T) {
	fake := baseFake()
	fake.putFailures = 4
	write := provider.Write{Environment: "MY_API_KEY", Reference: provider.Reference{Region: "Production", Container: "service"}, Value: secret.New("new")}
	if _, err := NewWithAPI(fake).WriteMany(context.Background(), []provider.Write{write}); err == nil || fake.puts != 1 {
		t.Fatalf("puts=%d err=%v", fake.puts, err)
	}
}

func TestShouldRetryUpToThreeTimesGivenTypedVersionConflicts(t *testing.T) {
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

func TestShouldBoundBackoffWithoutFinalWaitGivenRepeatedTypedConflicts(t *testing.T) {
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

func TestShouldReturnIndeterminateErrorGivenCancellationDuringBackoff(t *testing.T) {
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

func TestShouldParseSuccessfullyGivenValidOpReferenceVariants(t *testing.T) {
	for _, raw := range []string{"op://vault/item", "op://vault/item/field", "op://vault/item/path1/path2/field"} {
		if _, err := Parse(raw); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
	}
}

func TestShouldParseSourceOnlyContentSelectors(t *testing.T) {
	for raw, key := range map[string]string{
		"op://vault/item?notes":                    "?notes",
		"op://vault/item?document":                 "?document",
		"op://vault/item?file=certificate.pem":     "?file=certificate.pem",
		"op://vault/item?file=path/to/config.json": "?file=path/to/config.json",
	} {
		ref, err := Parse(raw)
		if err != nil || ref.Scheme != "op" || ref.Region != "vault" || ref.Container != "item" || ref.Key != key {
			t.Fatalf("%s: ref=%#v err=%v", raw, ref, err)
		}
	}

	for _, raw := range []string{
		"op://vault/item?",
		"op://vault/item?unknown",
		"op://vault/item?file=",
		"op://vault/item?file=path//file",
		"op://vault/item/field?document",
	} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("%s: expected parse failure", raw)
		}
	}
}

func FuzzParseReference(f *testing.F) {
	for _, seed := range []string{
		"op://vault/item",
		"op://vault/item/field",
		"op://vault/item/path1/path2/field",
		"op://vault/item?notes",
		"op://vault/item?document",
		"op://vault/item?file=path/to/file",
		"op://",
		"op://vault//field",
		"op://vault/item?file=",
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

func TestShouldReadNoteAndDeepConcealedFieldGivenValidReferences(t *testing.T) {
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

func TestShouldReadConcealedFieldGivenAPICredentialItem(t *testing.T) {
	fake := baseFake()
	fake.item.Category = op.ItemCategoryAPICredentials
	ref := provider.Reference{Region: "Production", Container: "service", Key: "path1/path2/FIELD"}

	values, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
	if err != nil || values[ref.Binding()].Reveal() != "old" {
		t.Fatalf("value=%q err=%v", values[ref.Binding()].Reveal(), err)
	}
}

func TestShouldClassifyVaultAndItemLookupDiagnostics(t *testing.T) {
	ref := provider.Reference{Scheme: "op", Region: "Production", Container: "service", Key: "FIELD"}

	missingVault := baseFake()
	missingVault.vaults = nil
	_, err := NewWithAPI(missingVault).ReadMany(context.Background(), []provider.Reference{ref})
	assertDiagnostic(t, err, provider.InvalidBinding, provider.SecretNotFound, -1)

	ambiguousVault := baseFake()
	ambiguousVault.vaults = append(ambiguousVault.vaults, op.VaultOverview{ID: "v2", Title: "Production"})
	_, err = NewWithAPI(ambiguousVault).ReadMany(context.Background(), []provider.Reference{ref})
	assertDiagnostic(t, err, provider.Ambiguous, provider.AmbiguousContainer, -1)

	missingItem := baseFake()
	missingItem.items = nil
	values, err := NewWithAPI(missingItem).ReadMany(context.Background(), []provider.Reference{ref})
	if err != nil || values[ref.Binding()].Found || values[ref.Binding()].Diagnostic != provider.SecretNotFound {
		t.Fatalf("missing item values=%v err=%v", values, err)
	}

	ambiguousItem := baseFake()
	ambiguousItem.items = append(ambiguousItem.items, op.ItemOverview{ID: "i2", Title: "service"})
	_, err = NewWithAPI(ambiguousItem).ReadMany(context.Background(), []provider.Reference{ref})
	assertDiagnostic(t, err, provider.Ambiguous, provider.AmbiguousContainer, -1)

	incompleteItem := baseFake()
	incompleteItem.item.ID = ""
	_, err = NewWithAPI(incompleteItem).ReadMany(context.Background(), []provider.Reference{ref})
	assertDiagnostic(t, err, provider.InvalidState, provider.InvalidResponse, -1)
}

func TestShouldClassifySectionAndFieldDiagnostics(t *testing.T) {
	missingSection := baseFake()
	missingSection.item.Sections = nil
	ref := provider.Reference{Scheme: "op", Region: "Production", Container: "service", Key: "path1/path2/FIELD"}
	_, err := NewWithAPI(missingSection).ReadMany(context.Background(), []provider.Reference{ref})
	assertDiagnostic(t, err, provider.InvalidBinding, provider.SectionNotFound, 0)

	ambiguousSection := baseFake()
	ambiguousSection.item.Sections = append(ambiguousSection.item.Sections, op.ItemSection{ID: "section-2", Title: "path1/path2"})
	_, err = NewWithAPI(ambiguousSection).ReadMany(context.Background(), []provider.Reference{ref})
	assertDiagnostic(t, err, provider.Ambiguous, provider.AmbiguousSection, 0)

	missingField := baseFake()
	missingField.item.Fields = nil
	values, err := NewWithAPI(missingField).ReadMany(context.Background(), []provider.Reference{ref})
	if err != nil || values[ref.Binding()].Found || values[ref.Binding()].Diagnostic != provider.FieldNotFound {
		t.Fatalf("missing field values=%v err=%v", values, err)
	}

	ambiguousField := baseFake()
	ambiguousField.item.Fields = append(ambiguousField.item.Fields, ambiguousField.item.Fields[1])
	_, err = NewWithAPI(ambiguousField).ReadMany(context.Background(), []provider.Reference{ref})
	assertDiagnostic(t, err, provider.Ambiguous, provider.AmbiguousField, 0)
}

func assertDiagnostic(t *testing.T, err error, kind provider.ErrorKind, diagnostic provider.Diagnostic, readIndex int) {
	t.Helper()
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != kind || typed.Diagnostic != diagnostic {
		t.Fatalf("err=%v kind=%v diagnostic=%v", err, kind, diagnostic)
	}
	var indexed *provider.ReadError
	if readIndex < 0 {
		if errors.As(err, &indexed) {
			t.Fatalf("unexpected read index=%d err=%v", indexed.Index, err)
		}
		return
	}
	if !errors.As(err, &indexed) || indexed.Index != readIndex {
		t.Fatalf("read index=%v want=%d err=%v", indexed, readIndex, err)
	}
}

func TestShouldReadTextFieldGivenAPICredentialItem(t *testing.T) {
	fake := baseFake()
	fake.item.Category = op.ItemCategoryAPICredentials
	ref := provider.Reference{Region: "Production", Container: "service", Key: "KEEP"}

	values, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
	if err != nil || values[ref.Binding()].Reveal() != "untouched" {
		t.Fatalf("value=%q err=%v", values[ref.Binding()].Reveal(), err)
	}
}

func TestShouldReadNotesGivenNonSecureNoteItem(t *testing.T) {
	fake := baseFake()
	fake.item.Category = op.ItemCategoryAPICredentials
	fake.item.Notes = "ITEM_NOTES"
	ref := provider.Reference{Scheme: "op", Region: "Production", Container: "service", Key: "?notes"}

	values, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
	defer provider.DestroyReadResults(values)
	if err != nil || values[ref.Binding()].Reveal() != "ITEM_NOTES" {
		t.Fatalf("value=%q err=%v", values[ref.Binding()].Reveal(), err)
	}
}

func TestShouldReadDocumentAndAttachmentFromOneItemSnapshot(t *testing.T) {
	fake := baseFake()
	fake.item.Category = op.ItemCategoryDocument
	fake.item.Document = &op.FileAttributes{ID: "document", Name: "config.env"}
	fake.item.Files = []op.ItemFile{{
		Attributes: op.FileAttributes{ID: "attachment", Name: "certificate.pem"},
		SectionID:  "section",
		FieldID:    "certificate",
	}}
	fake.fileContents = map[string][]byte{
		"document":   []byte("DOCUMENT_VALUE"),
		"attachment": []byte("ATTACHMENT_VALUE"),
	}
	document, err := Parse("op://Production/service?document")
	if err != nil {
		t.Fatal(err)
	}
	attachment, err := Parse("op://Production/service?file=path1/path2/certificate.pem")
	if err != nil {
		t.Fatal(err)
	}

	values, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{document, attachment})
	defer provider.DestroyReadResults(values)
	if err != nil || values[document.Binding()].Reveal() != "DOCUMENT_VALUE" || values[attachment.Binding()].Reveal() != "ATTACHMENT_VALUE" {
		t.Fatalf("document=%q attachment=%q err=%v", values[document.Binding()].Reveal(), values[attachment.Binding()].Reveal(), err)
	}
	if fake.itemGets != 1 || len(fake.fileReads) != 2 {
		t.Fatalf("item gets=%d file reads=%v", fake.itemGets, fake.fileReads)
	}
	for id, content := range fake.fileContents {
		if !bytes.Equal(content, make([]byte, len(content))) {
			t.Fatalf("%s content buffer was not destroyed", id)
		}
	}
}

func TestShouldResolveAttachmentByFieldIDFileIDOrFilename(t *testing.T) {
	for _, selector := range []string{"certificate", "attachment", "certificate.pem"} {
		t.Run(selector, func(t *testing.T) {
			fake := baseFake()
			fake.item.Files = []op.ItemFile{{
				Attributes: op.FileAttributes{ID: "attachment", Name: "certificate.pem"},
				FieldID:    "certificate",
			}}
			fake.fileContents = map[string][]byte{"attachment": []byte("ATTACHMENT_VALUE")}
			ref := provider.Reference{Scheme: "op", Region: "Production", Container: "service", Key: fileSelectorPrefix + selector}

			values, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
			defer provider.DestroyReadResults(values)
			if err != nil || values[ref.Binding()].Reveal() != "ATTACHMENT_VALUE" {
				t.Fatalf("value=%q err=%v", values[ref.Binding()].Reveal(), err)
			}
		})
	}
}

func TestShouldRejectAndDestroyNonTextDocumentContent(t *testing.T) {
	for name, content := range map[string][]byte{
		"invalid UTF-8": {0xff},
		"NUL":           {'a', 0, 'b'},
	} {
		t.Run(name, func(t *testing.T) {
			fake := baseFake()
			fake.item.Category = op.ItemCategoryDocument
			fake.item.Document = &op.FileAttributes{ID: "document"}
			fake.fileContents = map[string][]byte{"document": content}
			ref := provider.Reference{Scheme: "op", Region: "Production", Container: "service", Key: "?document"}

			_, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
			var typed *provider.Error
			var indexed *provider.ReadError
			if !errors.As(err, &typed) || typed.Kind != provider.InvalidState || typed.Diagnostic != provider.UnsupportedContent || !errors.As(err, &indexed) || indexed.Index != 0 {
				t.Fatalf("err=%v", err)
			}
			if !bytes.Equal(content, make([]byte, len(content))) {
				t.Fatal("rejected content buffer was not destroyed")
			}
		})
	}
}

func TestShouldRedactFileReadFailure(t *testing.T) {
	fake := baseFake()
	fake.item.Category = op.ItemCategoryDocument
	fake.item.Document = &op.FileAttributes{ID: "document"}
	fake.fileErr = errors.New("remote leaked document detail")
	ref := provider.Reference{Scheme: "op", Region: "Production", Container: "service", Key: "?document"}

	_, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.Indeterminate || strings.Contains(err.Error(), "leaked") {
		t.Fatalf("err=%v", err)
	}
}

func TestShouldFailClosedGivenAmbiguousAttachment(t *testing.T) {
	fake := baseFake()
	fake.item.Files = []op.ItemFile{
		{Attributes: op.FileAttributes{ID: "first", Name: "config.env"}, SectionID: "section", FieldID: "first-file"},
		{Attributes: op.FileAttributes{ID: "second", Name: "config.env"}, SectionID: "section", FieldID: "second-file"},
	}
	ref := provider.Reference{Scheme: "op", Region: "Production", Container: "service", Key: "?file=path1/path2/config.env"}

	_, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.Ambiguous || typed.Diagnostic != provider.AmbiguousFile || len(fake.fileReads) != 0 {
		t.Fatalf("file reads=%v err=%v", fake.fileReads, err)
	}
}

func TestShouldReportMissingGivenUnknownAttachment(t *testing.T) {
	fake := baseFake()
	ref := provider.Reference{Scheme: "op", Region: "Production", Container: "service", Key: "?file=missing.txt"}

	values, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
	defer provider.DestroyReadResults(values)
	if err != nil || values[ref.Binding()].Found || values[ref.Binding()].Diagnostic != provider.FileNotFound || len(fake.fileReads) != 0 {
		t.Fatalf("result=%v file reads=%v err=%v", values[ref.Binding()].Found, fake.fileReads, err)
	}
}

func TestShouldRejectDocumentSelectorGivenNonDocumentItem(t *testing.T) {
	fake := baseFake()
	ref := provider.Reference{Scheme: "op", Region: "Production", Container: "service", Key: "?document"}

	_, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.InvalidState || typed.Diagnostic != provider.UnsupportedContent || len(fake.fileReads) != 0 {
		t.Fatalf("file reads=%v err=%v", fake.fileReads, err)
	}
}

func TestShouldReportMissingDocumentGivenDocumentItemWithoutContent(t *testing.T) {
	fake := baseFake()
	fake.item.Category = op.ItemCategoryDocument
	fake.item.Document = nil
	ref := provider.Reference{Scheme: "op", Region: "Production", Container: "service", Key: "?document"}

	values, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
	if err != nil || values[ref.Binding()].Found || values[ref.Binding()].Diagnostic != provider.FileNotFound || len(fake.fileReads) != 0 {
		t.Fatalf("values=%v file reads=%v err=%v", values, fake.fileReads, err)
	}
}

func TestShouldRejectSourceOnlyContentSelectorsAsDestinations(t *testing.T) {
	for _, key := range []string{"?notes", "?document", "?file=certificate.pem"} {
		fake := baseFake()
		ref := provider.Reference{Scheme: "op", Region: "Production", Container: "service", Key: key}
		adapter := NewWithAPI(fake)

		_, readErr := adapter.ReadDestinations(context.Background(), []provider.Reference{ref})
		_, writeErr := adapter.WriteMany(context.Background(), []provider.Write{{Environment: "VALUE", Reference: ref, Value: secret.New("replacement")}})
		var readTyped, writeTyped *provider.Error
		if !errors.As(readErr, &readTyped) || readTyped.Kind != provider.InvalidBinding || !errors.As(writeErr, &writeTyped) || writeTyped.Kind != provider.InvalidBinding {
			t.Fatalf("key=%s readErr=%v writeErr=%v", key, readErr, writeErr)
		}
		if fake.itemGets != 0 || fake.puts != 0 {
			t.Fatalf("key=%s item gets=%d puts=%d", key, fake.itemGets, fake.puts)
		}
	}
}

func TestShouldIgnorePlainFieldWhenReadingDestination(t *testing.T) {
	fake := baseFake()
	fake.item.Fields[1] = op.ItemField{
		ID:        "MY_API_KEY",
		Title:     "MY_API_KEY",
		SectionID: stringPtr("section"),
		FieldType: op.ItemFieldTypeText,
		Value:     "same",
	}
	ref := provider.Reference{Region: "Production", Container: "service", Key: "path1/path2/MY_API_KEY"}
	reader, ok := any(NewWithAPI(fake)).(interface {
		ReadDestinations(context.Context, []provider.Reference) (map[string]provider.ReadResult, error)
	})
	if !ok {
		t.Fatal("1Password adapter does not distinguish destination reads")
	}

	values, err := reader.ReadDestinations(context.Background(), []provider.Reference{ref})
	defer provider.DestroyReadResults(values)
	if err != nil || values[ref.Binding()].Found {
		t.Fatalf("result=%v err=%v", values[ref.Binding()].Found, err)
	}
}

func TestShouldReadConcealedDestinationWhenPlainFieldAlsoMatches(t *testing.T) {
	fake := baseFake()
	fake.item.Fields[1] = op.ItemField{
		ID:        "MY_API_KEY",
		Title:     "MY_API_KEY",
		SectionID: stringPtr("section"),
		FieldType: op.ItemFieldTypeText,
		Value:     "plain",
	}
	fake.item.Fields = append(fake.item.Fields, op.ItemField{
		ID:        "MY_API_KEY",
		Title:     "MY_API_KEY",
		SectionID: stringPtr("section"),
		FieldType: op.ItemFieldTypeConcealed,
		Value:     "concealed",
	})
	ref := provider.Reference{Region: "Production", Container: "service", Key: "path1/path2/MY_API_KEY"}

	values, err := NewWithAPI(fake).ReadDestinations(context.Background(), []provider.Reference{ref})
	defer provider.DestroyReadResults(values)
	if err != nil || !values[ref.Binding()].Found || values[ref.Binding()].Reveal() != "concealed" {
		t.Fatalf("found=%v value=%q err=%v", values[ref.Binding()].Found, values[ref.Binding()].Reveal(), err)
	}
}

func TestShouldReadRootFieldGivenEmptySDKSectionID(t *testing.T) {
	fake := baseFake()
	fake.item.Fields[0].SectionID = stringPtr("")
	ref := provider.Reference{Region: "Production", Container: "service", Key: "KEEP"}

	values, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
	if err != nil || values[ref.Binding()].Reveal() != "untouched" {
		t.Fatalf("value=%q err=%v", values[ref.Binding()].Reveal(), err)
	}
}

func TestShouldRejectBodyReadGivenNonSecureNoteItem(t *testing.T) {
	fake := baseFake()
	fake.item.Category = op.ItemCategoryAPICredentials
	ref := provider.Reference{Region: "Production", Container: "service"}

	_, err := NewWithAPI(fake).ReadMany(context.Background(), []provider.Reference{ref})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.InvalidState || typed.Diagnostic != provider.UnsupportedContent {
		t.Fatalf("err=%v", err)
	}
}

func TestShouldPreserveFieldsAndSectionsGivenGroupedWrites(t *testing.T) {
	fake := baseFake()
	a := NewWithAPI(fake)
	writes := []provider.Write{{Environment: "A", Reference: provider.Reference{Region: "Production", Container: "service", Key: "path1/path2/FIELD"}, Value: secret.New("new")}, {Environment: "B", Reference: provider.Reference{Region: "Production", Container: "service", Key: "new/path/SECOND"}, Value: secret.New("two")}}
	receipt, err := a.WriteMany(context.Background(), writes)
	if err != nil || fake.puts != 1 || len(receipt.Completed) != 2 || fake.item.Fields[0].Value != "untouched" || fake.item.Fields[1].Value != "new" || len(fake.item.Sections) != 2 {
		t.Fatalf("item=%#v receipt=%#v err=%v", fake.item, receipt, err)
	}
}

func TestShouldCreateNewConcealedFieldGivenNonConcealedFieldNameCollision(t *testing.T) {
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

func TestShouldGenerateNonCollidingSectionIDGivenExistingSectionID(t *testing.T) {
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

func TestShouldCacheVaultAndItemListingsGivenRepeatedReads(t *testing.T) {
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

func TestShouldNotCreateItemGivenMissingItem(t *testing.T) {
	fake := baseFake()
	fake.items = nil
	a := NewWithAPI(fake)
	_, err := a.WriteMany(context.Background(), []provider.Write{{Environment: "K", Reference: provider.Reference{Region: "Production", Container: "new"}, Value: secret.New("body")}})
	if err == nil || fake.created.Notes != nil {
		t.Fatalf("created=%#v err=%v", fake.created, err)
	}
}
func TestShouldSurfaceVaultAmbiguityAndAuthPrecedenceGivenDuplicateVaultsAndCredentials(t *testing.T) {
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
