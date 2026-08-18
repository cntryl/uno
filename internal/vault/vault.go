package vault

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
	vaultapi "github.com/hashicorp/vault/api"
)

// VaultAPI is the subset of *vaultapi.KVv2's method set this adapter needs.
// *vaultapi.KVv2 satisfies it structurally, so production code needs no
// wrapper; tests substitute a fake.
type VaultAPI interface {
	Get(ctx context.Context, secretPath string) (*vaultapi.KVSecret, error)
	Put(ctx context.Context, secretPath string, data map[string]interface{}, opts ...vaultapi.KVOption) (*vaultapi.KVSecret, error)
	Rollback(ctx context.Context, secretPath string, toVersion int) (*vaultapi.KVSecret, error)
	GetMetadata(ctx context.Context, secretPath string) (*vaultapi.KVMetadata, error)
}

const maxWriteAttempts = 4

type Vault struct {
	// Mount returns the KV v2 handle for a given engine mount. Indirected
	// through a function (rather than embedding *vaultapi.Client directly)
	// because one Vault client serves every mount, but each reference names
	// its own — and because a function field is trivially fakeable in tests.
	Mount  func(mount string) VaultAPI
	wait   func(context.Context, time.Duration) error
	jitter func(time.Duration) time.Duration
}

func (v *Vault) ReadMany(ctx context.Context, refs []provider.Reference) (map[string]provider.ReadResult, error) {
	if err := provider.ValidateReadGroup(refs); err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, nil
	}
	got, missing, err := readContainer(ctx, v.Mount(refs[0].Region), refs[0].Container)
	if err != nil {
		return nil, err
	}
	if missing {
		return provider.MissingResultsWithDiagnostic(refs, provider.SecretNotFound), nil
	}
	values := make(map[string]provider.ReadResult, len(refs))
	fail := func(err error) (map[string]provider.ReadResult, error) {
		provider.DestroyReadResults(values)
		return nil, err
	}
	for index, ref := range refs {
		if ref.Region != refs[0].Region || ref.Container != refs[0].Container {
			return fail(&provider.Error{Kind: provider.InvalidBinding})
		}
		result, err := decodeResult(got, ref.Key)
		if err != nil {
			return fail(provider.ReadFailure(index, err))
		}
		values[ref.Binding()] = result
	}
	return values, nil
}

func readContainer(ctx context.Context, kv VaultAPI, path string) (*vaultapi.KVSecret, bool, error) {
	got, err := kv.Get(ctx, path)
	if errors.Is(err, vaultapi.ErrSecretNotFound) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, remoteError(err)
	}
	if got == nil {
		return nil, false, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.InvalidResponse}
	}
	if got.Data == nil {
		return nil, false, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.MalformedContainer}
	}
	return got, false, nil
}

// WriteMany merges every write into the secret's current document (like
// AWS Secrets Manager) and writes it once with a KV v2 check-and-set option
// pinned to the version just read, retrying on a CAS conflict up to
// maxWriteAttempts times with jittered exponential backoff.
func (v *Vault) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	if err := provider.ValidateWriteGroup(writes); err != nil {
		return provider.Receipt{}, err
	}
	if len(writes) == 0 {
		return provider.Receipt{}, nil
	}
	mount, path := writes[0].Reference.Region, writes[0].Reference.Container
	kv := v.Mount(mount)
	for attempt := range maxWriteAttempts {
		putErr := writeAttempt(ctx, kv, path, writes)
		if putErr == nil {
			return provider.Receipt{Completed: provider.Environments(writes)}, nil
		}
		if !isCASConflict(putErr) {
			return provider.Receipt{}, remoteError(putErr)
		}
		if attempt == maxWriteAttempts-1 {
			return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
		}
		if err := v.waitBeforeRetry(ctx, attempt); err != nil {
			return provider.Receipt{}, err
		}
	}
	return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
}
func decodeResult(got *vaultapi.KVSecret, key string) (provider.ReadResult, error) {
	raw, ok := got.Data[key]
	if !ok {
		return provider.ReadResult{Diagnostic: provider.BindingNotFound}, nil
	}
	str, ok := raw.(string)
	if !ok || raw == nil {
		return provider.ReadResult{}, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.UnsupportedContent}
	}
	return provider.ReadResult{Value: secret.New(str), Found: true}, nil
}
func writeAttempt(ctx context.Context, kv VaultAPI, path string, writes []provider.Write) error {
	existing, err := kv.Get(ctx, path)
	if err != nil && !errors.Is(err, vaultapi.ErrSecretNotFound) {
		return err
	}
	cas := 0
	data := map[string]interface{}{}
	if existing != nil {
		for key, value := range existing.Data {
			data[key] = value
		}
		if existing.VersionMetadata != nil {
			cas = existing.VersionMetadata.Version
		}
	}
	for _, write := range writes {
		data[write.Reference.Key] = write.Value.Reveal()
	}
	_, err = kv.Put(ctx, path, data, vaultapi.WithCheckAndSet(cas))
	return err
}

// Rollback uses Vault's own KV v2 rollback operation (a server-side copy of
// an older version's data back to a new version), targeting the version
// immediately before the current one.
func (v *Vault) Rollback(ctx context.Context, ref provider.Reference) error {
	kv := v.Mount(ref.Region)
	meta, err := kv.GetMetadata(ctx, ref.Container)
	if err != nil {
		return remoteError(err)
	}
	if meta == nil || meta.CurrentVersion < 2 {
		return &provider.Error{Kind: provider.InvalidState, Detail: "no previous version to roll back to"}
	}
	if _, err := kv.Rollback(ctx, ref.Container, meta.CurrentVersion-1); err != nil {
		return remoteError(err)
	}
	return nil
}

func (v *Vault) waitBeforeRetry(ctx context.Context, attempt int) error {
	return provider.WaitBeforeRetry(ctx, attempt, v.wait, v.jitter)
}

// isCASConflict reports whether err is Vault's documented check-and-set
// mismatch response. The SDK doesn't expose a typed error for this the way
// AWS's ResourceExistsException does, so this matches on the response
// shape Vault's KV v2 API is documented to return: HTTP 400 with an error
// message mentioning "check-and-set".
func isCASConflict(err error) bool {
	var respErr *vaultapi.ResponseError
	if !errors.As(err, &respErr) || respErr.StatusCode != http.StatusBadRequest {
		return false
	}
	for _, msg := range respErr.Errors {
		if strings.Contains(msg, "check-and-set") {
			return true
		}
	}
	return false
}

func remoteError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, vaultapi.ErrSecretNotFound) {
		return &provider.Error{Kind: provider.InvalidBinding}
	}
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		switch respErr.StatusCode {
		case http.StatusNotFound:
			return &provider.Error{Kind: provider.InvalidBinding}
		case http.StatusForbidden, http.StatusUnauthorized:
			return &provider.Error{Kind: provider.AccessDenied}
		}
	}
	return &provider.Error{Kind: provider.Indeterminate}
}
