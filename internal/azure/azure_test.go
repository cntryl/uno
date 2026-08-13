package azure

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

type fakeClient struct {
	get  func(context.Context, string, string) (azsecrets.GetSecretResponse, error)
	set  func(context.Context, string, azsecrets.SetSecretParameters) (azsecrets.SetSecretResponse, error)
	list func(context.Context, string) ([]azsecrets.SecretProperties, error)
}

func (f *fakeClient) GetSecret(c context.Context, n, v string) (azsecrets.GetSecretResponse, error) {
	return f.get(c, n, v)
}
func (f *fakeClient) SetSecret(c context.Context, n string, p azsecrets.SetSecretParameters) (azsecrets.SetSecretResponse, error) {
	return f.set(c, n, p)
}
func (f *fakeClient) ListSecretVersions(c context.Context, n string) ([]azsecrets.SecretProperties, error) {
	return f.list(c, n)
}
func ptr[T any](v T) *T { return &v }
func ref(key string) provider.Reference {
	return provider.Reference{Scheme: "azure-key-vault", Region: "v.vault.azure.net", Container: "secret", Key: key, AdapterKey: "v.vault.azure.net"}
}

func TestReadManyUsesOneSnapshotForBlobAndKeys(t *testing.T) {
	calls := 0
	f := &fakeClient{get: func(context.Context, string, string) (azsecrets.GetSecretResponse, error) {
		calls++
		return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: ptr(`{"a":"one","b":"two"}`)}}, nil
	}}
	a := &KeyVault{C: f}
	refs := []provider.Reference{ref("a"), ref("b")}
	values, err := a.ReadMany(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	defer secret.DestroyMap(values)
	if calls != 1 || values[refs[0].Binding()].Reveal() != "one" || values[refs[1].Binding()].Reveal() != "two" {
		t.Fatalf("calls=%d values=%v", calls, values)
	}
}

func TestReadManyRejectsUnsafeValuesAndMixedContainers(t *testing.T) {
	for _, value := range []*string{nil, ptr("null"), ptr(`{"a":null}`), ptr(`{"a":1}`), ptr(`{"b":"x"}`)} {
		f := &fakeClient{get: func(context.Context, string, string) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: value}}, nil
		}}
		if _, err := (&KeyVault{C: f}).ReadMany(context.Background(), []provider.Reference{ref("a")}); err == nil {
			t.Fatalf("value=%v", value)
		}
	}
	f := &fakeClient{get: func(context.Context, string, string) (azsecrets.GetSecretResponse, error) {
		return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: ptr("x")}}, nil
	}}
	r2 := ref("")
	r2.Container = "other"
	if _, err := (&KeyVault{C: f}).ReadMany(context.Background(), []provider.Reference{ref(""), r2}); err == nil {
		t.Fatal("expected mixed container error")
	}
}

func TestKeyedWriteMergesOnceAndPreservesMetadata(t *testing.T) {
	now := time.Now()
	enabled := true
	calls := 0
	attrs := &azsecrets.SecretAttributes{Enabled: &enabled, NotBefore: &now, Expires: ptr(now.Add(time.Hour))}
	f := &fakeClient{
		get: func(context.Context, string, string) (azsecrets.GetSecretResponse, error) {
			return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: ptr(`{"sibling":true,"a":"old"}`), ContentType: ptr("application/json"), Tags: map[string]*string{"x": ptr("y")}, Attributes: attrs}}, nil
		},
		set: func(_ context.Context, _ string, p azsecrets.SetSecretParameters) (azsecrets.SetSecretResponse, error) {
			calls++
			if *p.Value != `{"a":"new","b":"second","sibling":true}` || p.ContentType == nil || p.SecretAttributes != attrs || *p.Tags["x"] != "y" {
				t.Fatalf("params=%+v value=%s", p, *p.Value)
			}
			return azsecrets.SetSecretResponse{}, nil
		},
	}
	writes := []provider.Write{{Environment: "B", Reference: ref("b"), Value: secret.New("second")}, {Environment: "A", Reference: ref("a"), Value: secret.New("new")}}
	receipt, err := (&KeyVault{C: f}).WriteMany(context.Background(), writes)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(receipt.Completed) != 2 || receipt.Completed[0] != "A" {
		t.Fatalf("calls=%d receipt=%v", calls, receipt)
	}
}

func TestMissingKeyedSecretStartsObjectAndBlobDoesNotRead(t *testing.T) {
	getCalls := 0
	f := &fakeClient{get: func(context.Context, string, string) (azsecrets.GetSecretResponse, error) {
		getCalls++
		return azsecrets.GetSecretResponse{}, &azcore.ResponseError{StatusCode: 404}
	}, set: func(_ context.Context, _ string, p azsecrets.SetSecretParameters) (azsecrets.SetSecretResponse, error) {
		if getCalls > 0 && *p.Value != "{\"a\":\"x\"}" {
			t.Fatalf("value=%s", *p.Value)
		}
		return azsecrets.SetSecretResponse{}, nil
	}}
	if _, err := (&KeyVault{C: f}).WriteMany(context.Background(), []provider.Write{{Environment: "A", Reference: ref("a"), Value: secret.New("x")}}); err != nil {
		t.Fatal(err)
	}
	if getCalls != 1 {
		t.Fatal(getCalls)
	}
	getCalls = 0
	if _, err := (&KeyVault{C: f}).WriteMany(context.Background(), []provider.Write{{Environment: "A", Reference: ref(""), Value: secret.New("blob")}}); err != nil {
		t.Fatal(err)
	}
	if getCalls != 0 {
		t.Fatal("blob write read existing secret")
	}
}

func TestRollbackChoosesImmediatelyPriorVersionAndMetadata(t *testing.T) {
	t0 := time.Unix(1, 0)
	t1 := time.Unix(2, 0)
	t2 := time.Unix(3, 0)
	id0 := azsecrets.ID("https://v.vault.azure.net/secrets/secret/a")
	id1 := azsecrets.ID("https://v.vault.azure.net/secrets/secret/b")
	id2 := azsecrets.ID("https://v.vault.azure.net/secrets/secret/c")
	props := []azsecrets.SecretProperties{{ID: &id2, Attributes: &azsecrets.SecretAttributes{Created: &t2}}, {ID: &id0, Attributes: &azsecrets.SecretAttributes{Created: &t0}}, {ID: &id1, Attributes: &azsecrets.SecretAttributes{Created: &t1}}}
	f := &fakeClient{list: func(context.Context, string) ([]azsecrets.SecretProperties, error) { return props, nil }, get: func(_ context.Context, _ string, v string) (azsecrets.GetSecretResponse, error) {
		if v != "b" {
			t.Fatalf("version=%s", v)
		}
		return azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: ptr("old"), ContentType: ptr("text/plain")}}, nil
	}, set: func(_ context.Context, _ string, p azsecrets.SetSecretParameters) (azsecrets.SetSecretResponse, error) {
		if *p.Value != "old" || *p.ContentType != "text/plain" {
			t.Fatalf("params=%+v", p)
		}
		return azsecrets.SetSecretResponse{}, nil
	}}
	if err := (&KeyVault{C: f}).Rollback(context.Background(), ref("")); err != nil {
		t.Fatal(err)
	}
}

func TestRollbackDoesNotSkipUnusableVersion(t *testing.T) {
	now := time.Now()
	id := azsecrets.ID("https://v.vault.azure.net/secrets/secret/current")
	f := &fakeClient{list: func(context.Context, string) ([]azsecrets.SecretProperties, error) {
		return []azsecrets.SecretProperties{{ID: &id, Attributes: &azsecrets.SecretAttributes{Created: &now}}, {}}, nil
	}}
	err := (&KeyVault{C: f}).Rollback(context.Background(), ref(""))
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.InvalidState {
		t.Fatalf("err=%v", err)
	}
}

func TestRemoteErrorsAreClassifiedWithoutSDKText(t *testing.T) {
	for status, want := range map[int]provider.ErrorKind{401: provider.Authentication, 403: provider.AccessDenied, 404: provider.InvalidBinding, 409: provider.InvalidState, 429: provider.Indeterminate, 500: provider.Indeterminate} {
		err := remoteError(&azcore.ResponseError{StatusCode: status, ErrorCode: "REMOTE", RawResponse: &http.Response{StatusCode: status}})
		var typed *provider.Error
		if !errors.As(err, &typed) || typed.Kind != want || typed.Detail != "" || errors.Is(err, context.Canceled) {
			t.Fatalf("status=%d err=%v", status, err)
		}
	}
	if !errors.Is(remoteError(context.Canceled), context.Canceled) {
		t.Fatal("cancellation not preserved")
	}
}
