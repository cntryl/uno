package azure

import (
	"context"
	"errors"
	"net/http"
	"sort"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/cntryl/uno/internal/core/provider"
)

type Client interface {
	GetSecret(context.Context, string, string) (azsecrets.GetSecretResponse, error)
	SetSecret(context.Context, string, azsecrets.SetSecretParameters) (azsecrets.SetSecretResponse, error)
	ListSecretVersions(context.Context, string) ([]azsecrets.SecretProperties, error)
}

type sdkClient struct{ client *azsecrets.Client }

func (s *sdkClient) GetSecret(ctx context.Context, name, version string) (azsecrets.GetSecretResponse, error) {
	return s.client.GetSecret(ctx, name, version, nil)
}
func (s *sdkClient) SetSecret(ctx context.Context, name string, params azsecrets.SetSecretParameters) (azsecrets.SetSecretResponse, error) {
	return s.client.SetSecret(ctx, name, params, nil)
}
func (s *sdkClient) ListSecretVersions(ctx context.Context, name string) ([]azsecrets.SecretProperties, error) {
	pager := s.client.NewListSecretPropertiesVersionsPager(name, nil)
	var out []azsecrets.SecretProperties
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, properties := range page.Value {
			if properties != nil {
				out = append(out, *properties)
			}
		}
	}
	return out, nil
}

type KeyVault struct{ C Client }

func (a *KeyVault) ReadMany(ctx context.Context, refs []provider.Reference) (map[string]provider.ReadResult, error) {
	if err := provider.ValidateReadGroup(refs); err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, nil
	}
	response, err := a.C.GetSecret(ctx, refs[0].Container, "")
	if err != nil {
		var responseError *azcore.ResponseError
		if errors.As(err, &responseError) && responseError.StatusCode == http.StatusNotFound {
			return provider.MissingResultsWithDiagnostic(refs, provider.SecretNotFound), nil
		}
		return nil, remoteError(err)
	}
	if response.Value == nil {
		return nil, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.InvalidResponse}
	}
	return provider.ReadJSONDocument(refs, []byte(*response.Value))
}

func (a *KeyVault) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	if err := provider.ValidateWriteGroup(writes); err != nil {
		return provider.Receipt{}, err
	}
	if len(writes) == 0 {
		return provider.Receipt{}, nil
	}
	ref := writes[0].Reference
	params := azsecrets.SetSecretParameters{}
	var existing []byte
	if !ref.Blob() {
		current, err := a.C.GetSecret(ctx, ref.Container, "")
		switch {
		case err == nil:
			if current.Value == nil {
				return provider.Receipt{}, &provider.Error{Kind: provider.InvalidState}
			}
			existing = []byte(*current.Value)
			params.ContentType = current.ContentType
			params.Tags = current.Tags
			params.SecretAttributes = current.Attributes
		case !statusCode(err, 404):
			return provider.Receipt{}, remoteError(err)
		}
	}
	payload, err := provider.MergeJSONDocument(existing, writes)
	if err != nil {
		return provider.Receipt{}, err
	}
	value := string(payload)
	params.Value = &value
	if _, err := a.C.SetSecret(ctx, ref.Container, params); err != nil {
		return provider.Receipt{}, remoteError(err)
	}
	return provider.Receipt{Completed: provider.Environments(writes)}, nil
}

func (a *KeyVault) Rollback(ctx context.Context, ref provider.Reference) error {
	versions, err := a.C.ListSecretVersions(ctx, ref.Container)
	if err != nil {
		return remoteError(err)
	}
	previous, err := previousVersion(versions)
	if err != nil {
		return err
	}
	response, err := a.C.GetSecret(ctx, ref.Container, previous.ID.Version())
	if err != nil {
		return remoteError(err)
	}
	if response.Value == nil {
		return &provider.Error{Kind: provider.InvalidState}
	}
	params := azsecrets.SetSecretParameters{Value: response.Value, ContentType: response.ContentType, Tags: response.Tags, SecretAttributes: response.Attributes}
	if _, err := a.C.SetSecret(ctx, ref.Container, params); err != nil {
		return remoteError(err)
	}
	return nil
}
func previousVersion(versions []azsecrets.SecretProperties) (azsecrets.SecretProperties, error) {
	for _, version := range versions {
		if version.ID == nil || version.ID.Version() == "" || version.Attributes == nil || version.Attributes.Created == nil {
			return azsecrets.SecretProperties{}, &provider.Error{Kind: provider.InvalidState}
		}
	}
	if len(versions) < 2 {
		return azsecrets.SecretProperties{}, &provider.Error{Kind: provider.InvalidState, Detail: "no previous version to roll back to"}
	}
	sort.Slice(versions, func(i, j int) bool {
		a, b := versions[i], versions[j]
		if !a.Attributes.Created.Equal(*b.Attributes.Created) {
			return a.Attributes.Created.Before(*b.Attributes.Created)
		}
		return a.ID.Version() < b.ID.Version()
	})
	return versions[len(versions)-2], nil
}

func statusCode(err error, code int) bool {
	var response *azcore.ResponseError
	return errors.As(err, &response) && response.StatusCode == code
}
func remoteError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var response *azcore.ResponseError
	if !errors.As(err, &response) {
		return &provider.Error{Kind: provider.Indeterminate}
	}
	switch response.StatusCode {
	case http.StatusUnauthorized:
		return &provider.Error{Kind: provider.Authentication}
	case http.StatusForbidden:
		return &provider.Error{Kind: provider.AccessDenied}
	case http.StatusNotFound:
		return &provider.Error{Kind: provider.InvalidBinding}
	case http.StatusBadRequest, http.StatusConflict, http.StatusGone, http.StatusPreconditionFailed, http.StatusUnprocessableEntity:
		return &provider.Error{Kind: provider.InvalidState}
	default:
		return &provider.Error{Kind: provider.Indeterminate}
	}
}
