package vault

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

func TestShouldParseOrRejectGivenWellFormedAndMalformedURIs(t *testing.T) {
	cases := map[string]provider.Reference{
		"vault://secret/team/service/API_KEY": {Scheme: "vault", Region: "secret", Container: "team/service", Key: "API_KEY", AdapterKey: adapterKey},
		"vault://secret/app/KEY":              {Scheme: "vault", Region: "secret", Container: "app", Key: "KEY", AdapterKey: adapterKey},
	}
	for raw, want := range cases {
		got, err := Parse(raw)
		if err != nil || got != want {
			t.Fatalf("%s: got=%#v want=%#v err=%v", raw, got, want, err)
		}
	}
	for _, raw := range []string{"vault://mount/key", "vault://mount//key", "vault://mount/path/", "vault:///path/key", "aws-ssm://x/y", "vault://mount/path\x00/key"} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func FuzzParseReference(f *testing.F) {
	for _, seed := range []string{
		"vault://secret/team/service/API_KEY",
		"vault://secret/app/KEY",
		"vault://",
		"vault://mount/key",
		"vault://mount//key",
		"vault://mount/path\x00/key",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ref, err := Parse(raw)
		if err == nil && (ref.Scheme != "vault" || ref.Region == "" || ref.Container == "" || ref.Key == "") {
			t.Fatalf("successful parse returned incomplete reference")
		}
	})
}

type fakeVaultAPI struct {
	get         func(ctx context.Context, path string) (*vaultapi.KVSecret, error)
	put         func(ctx context.Context, path string, data map[string]interface{}, opts ...vaultapi.KVOption) (*vaultapi.KVSecret, error)
	rollback    func(ctx context.Context, path string, toVersion int) (*vaultapi.KVSecret, error)
	getMetadata func(ctx context.Context, path string) (*vaultapi.KVMetadata, error)
}

func (f *fakeVaultAPI) Get(ctx context.Context, path string) (*vaultapi.KVSecret, error) {
	return f.get(ctx, path)
}
func (f *fakeVaultAPI) Put(ctx context.Context, path string, data map[string]interface{}, opts ...vaultapi.KVOption) (*vaultapi.KVSecret, error) {
	return f.put(ctx, path, data, opts...)
}
func (f *fakeVaultAPI) Rollback(ctx context.Context, path string, toVersion int) (*vaultapi.KVSecret, error) {
	return f.rollback(ctx, path, toVersion)
}
func (f *fakeVaultAPI) GetMetadata(ctx context.Context, path string) (*vaultapi.KVMetadata, error) {
	return f.getMetadata(ctx, path)
}

func mounting(api VaultAPI) func(string) VaultAPI {
	return func(string) VaultAPI { return api }
}

func TestShouldReadEveryKeyFromOneSharedDocumentGivenMultipleReferences(t *testing.T) {
	fake := &fakeVaultAPI{get: func(context.Context, string) (*vaultapi.KVSecret, error) {
		return &vaultapi.KVSecret{Data: map[string]interface{}{"a": "one", "b": "two", "c": 5}}, nil
	}}
	v := &Vault{Mount: mounting(fake)}
	refs := []provider.Reference{
		{Scheme: "vault", Region: "secret", Container: "app", Key: "a"},
		{Scheme: "vault", Region: "secret", Container: "app", Key: "b"},
	}
	values, err := v.ReadMany(context.Background(), refs)
	if err != nil || values[refs[0].Binding()].Reveal() != "one" || values[refs[1].Binding()].Reveal() != "two" {
		t.Fatalf("values=%v err=%v", values, err)
	}
}

func TestShouldClassifyMissingKeyAndNonStringValue(t *testing.T) {
	fake := &fakeVaultAPI{get: func(context.Context, string) (*vaultapi.KVSecret, error) {
		return &vaultapi.KVSecret{Data: map[string]interface{}{"a": "one", "c": 5}}, nil
	}}
	v := &Vault{Mount: mounting(fake)}
	missingRef := provider.Reference{Scheme: "vault", Region: "secret", Container: "app", Key: "missing"}
	values, err := v.ReadMany(context.Background(), []provider.Reference{missingRef})
	if err != nil || values[missingRef.Binding()].Found || values[missingRef.Binding()].Diagnostic != provider.BindingNotFound {
		t.Fatalf("missing=%v err=%v", values, err)
	}

	unsupportedRef := provider.Reference{Scheme: "vault", Region: "secret", Container: "app", Key: "c"}
	_, err = v.ReadMany(context.Background(), []provider.Reference{unsupportedRef})
	var indexed *provider.ReadError
	var typed *provider.Error
	if !errors.As(err, &indexed) || indexed.Index != 0 || !errors.As(err, &typed) || typed.Kind != provider.InvalidState || typed.Diagnostic != provider.UnsupportedContent {
		t.Fatalf("unsupported err=%v", err)
	}
}

func TestShouldFailReadGivenSecretNotFound(t *testing.T) {
	fake := &fakeVaultAPI{get: func(context.Context, string) (*vaultapi.KVSecret, error) {
		return nil, vaultapi.ErrSecretNotFound
	}}
	v := &Vault{Mount: mounting(fake)}
	ref := provider.Reference{Scheme: "vault", Region: "secret", Container: "app", Key: "a"}
	values, err := v.ReadMany(context.Background(), []provider.Reference{ref})
	if err != nil || values[ref.Binding()].Found || values[ref.Binding()].Diagnostic != provider.SecretNotFound {
		t.Fatalf("values=%v err=%v", values, err)
	}
}

func TestShouldClassifyNilVaultResponseAsIncomplete(t *testing.T) {
	fake := &fakeVaultAPI{get: func(context.Context, string) (*vaultapi.KVSecret, error) { return nil, nil }}
	ref := provider.Reference{Scheme: "vault", Region: "secret", Container: "app", Key: "a"}
	_, err := (&Vault{Mount: mounting(fake)}).ReadMany(context.Background(), []provider.Reference{ref})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.InvalidState || typed.Diagnostic != provider.InvalidResponse {
		t.Fatalf("err=%v", err)
	}
}

func TestShouldClassifyNilVaultDataAsMalformedContainer(t *testing.T) {
	fake := &fakeVaultAPI{get: func(context.Context, string) (*vaultapi.KVSecret, error) { return &vaultapi.KVSecret{}, nil }}
	ref := provider.Reference{Scheme: "vault", Region: "secret", Container: "app", Key: "a"}
	_, err := (&Vault{Mount: mounting(fake)}).ReadMany(context.Background(), []provider.Reference{ref})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.InvalidState || typed.Diagnostic != provider.MalformedContainer {
		t.Fatalf("err=%v", err)
	}
}

func TestShouldMergeAndWriteOnceGivenExistingDocument(t *testing.T) {
	var putData map[string]interface{}
	var putCAS int
	fake := &fakeVaultAPI{
		get: func(context.Context, string) (*vaultapi.KVSecret, error) {
			return &vaultapi.KVSecret{Data: map[string]interface{}{"keep": "yes"}, VersionMetadata: &vaultapi.KVVersionMetadata{Version: 3}}, nil
		},
		put: func(_ context.Context, _ string, data map[string]interface{}, opts ...vaultapi.KVOption) (*vaultapi.KVSecret, error) {
			putData = data
			for _, opt := range opts {
				key, value := opt()
				if key == vaultapi.KVOptionCheckAndSet {
					if cas, ok := value.(int); ok {
						putCAS = cas
					}
				}
			}
			return &vaultapi.KVSecret{}, nil
		},
	}
	v := &Vault{Mount: mounting(fake)}
	writes := []provider.Write{{Environment: "A", Reference: provider.Reference{Region: "secret", Container: "app", Key: "new"}, Value: secret.New("value")}}
	receipt, err := v.WriteMany(context.Background(), writes)
	if err != nil || len(receipt.Completed) != 1 || putCAS != 3 || !reflect.DeepEqual(putData, map[string]interface{}{"keep": "yes", "new": "value"}) {
		t.Fatalf("receipt=%v putData=%v putCAS=%d err=%v", receipt, putData, putCAS, err)
	}
}

func TestShouldCreateGivenSecretNotFound(t *testing.T) {
	var putCAS int
	fake := &fakeVaultAPI{
		get: func(context.Context, string) (*vaultapi.KVSecret, error) { return nil, vaultapi.ErrSecretNotFound },
		put: func(_ context.Context, _ string, _ map[string]interface{}, opts ...vaultapi.KVOption) (*vaultapi.KVSecret, error) {
			for _, opt := range opts {
				key, value := opt()
				if key == vaultapi.KVOptionCheckAndSet {
					if cas, ok := value.(int); ok {
						putCAS = cas
					}
				}
			}
			return &vaultapi.KVSecret{}, nil
		},
	}
	v := &Vault{Mount: mounting(fake)}
	writes := []provider.Write{{Environment: "A", Reference: provider.Reference{Region: "secret", Container: "app", Key: "new"}, Value: secret.New("value")}}
	receipt, err := v.WriteMany(context.Background(), writes)
	if err != nil || len(receipt.Completed) != 1 || putCAS != 0 {
		t.Fatalf("receipt=%v putCAS=%d err=%v", receipt, putCAS, err)
	}
}

func casConflictError() error {
	return &vaultapi.ResponseError{StatusCode: http.StatusBadRequest, Errors: []string{"check-and-set parameter did not match the current version"}}
}

func TestShouldRetryGivenCASConflictThenSucceed(t *testing.T) {
	attempts := 0
	fake := &fakeVaultAPI{
		get: func(context.Context, string) (*vaultapi.KVSecret, error) {
			return &vaultapi.KVSecret{VersionMetadata: &vaultapi.KVVersionMetadata{Version: 1}}, nil
		},
		put: func(context.Context, string, map[string]interface{}, ...vaultapi.KVOption) (*vaultapi.KVSecret, error) {
			attempts++
			if attempts < 2 {
				return nil, casConflictError()
			}
			return &vaultapi.KVSecret{}, nil
		},
	}
	v := &Vault{Mount: mounting(fake), wait: func(context.Context, time.Duration) error { return nil }}
	writes := []provider.Write{{Environment: "A", Reference: provider.Reference{Region: "secret", Container: "app", Key: "new"}, Value: secret.New("value")}}
	receipt, err := v.WriteMany(context.Background(), writes)
	if err != nil || len(receipt.Completed) != 1 || attempts != 2 {
		t.Fatalf("receipt=%v attempts=%d err=%v", receipt, attempts, err)
	}
}

func TestShouldNotRetryGivenNonConflictWriteError(t *testing.T) {
	attempts := 0
	fake := &fakeVaultAPI{
		get: func(context.Context, string) (*vaultapi.KVSecret, error) { return nil, vaultapi.ErrSecretNotFound },
		put: func(context.Context, string, map[string]interface{}, ...vaultapi.KVOption) (*vaultapi.KVSecret, error) {
			attempts++
			return nil, &vaultapi.ResponseError{StatusCode: http.StatusForbidden}
		},
	}
	v := &Vault{Mount: mounting(fake), wait: func(context.Context, time.Duration) error { return nil }}
	writes := []provider.Write{{Environment: "A", Reference: provider.Reference{Region: "secret", Container: "app", Key: "new"}, Value: secret.New("value")}}
	_, err := v.WriteMany(context.Background(), writes)
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.AccessDenied || attempts != 1 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
}

func TestShouldRollbackToPreviousVersionGivenCurrentVersionAtLeastTwo(t *testing.T) {
	var rolledBackTo int
	fake := &fakeVaultAPI{
		getMetadata: func(context.Context, string) (*vaultapi.KVMetadata, error) {
			return &vaultapi.KVMetadata{CurrentVersion: 4}, nil
		},
		rollback: func(_ context.Context, _ string, toVersion int) (*vaultapi.KVSecret, error) {
			rolledBackTo = toVersion
			return &vaultapi.KVSecret{}, nil
		},
	}
	v := &Vault{Mount: mounting(fake)}
	err := v.Rollback(context.Background(), provider.Reference{Region: "secret", Container: "app"})
	if err != nil || rolledBackTo != 3 {
		t.Fatalf("rolledBackTo=%d err=%v", rolledBackTo, err)
	}
}

func TestShouldFailRollbackGivenOnlyOneVersionExists(t *testing.T) {
	fake := &fakeVaultAPI{getMetadata: func(context.Context, string) (*vaultapi.KVMetadata, error) {
		return &vaultapi.KVMetadata{CurrentVersion: 1}, nil
	}}
	v := &Vault{Mount: mounting(fake)}
	err := v.Rollback(context.Background(), provider.Reference{Region: "secret", Container: "app"})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.InvalidState {
		t.Fatalf("err=%v", err)
	}
}
