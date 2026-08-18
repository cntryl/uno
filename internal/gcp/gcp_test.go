package gcp

import (
	"context"
	"errors"
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

func TestShouldParseOrRejectGivenWellFormedAndMalformedURIs(t *testing.T) {
	cases := map[string]provider.Reference{
		"gcp-secret-manager://my-project/my-secret":     {Scheme: "gcp-secret-manager", Region: "my-project", Container: "my-secret", AdapterKey: adapterKey},
		"gcp-secret-manager://my-project/my-secret/KEY": {Scheme: "gcp-secret-manager", Region: "my-project", Container: "my-secret", Key: "KEY", AdapterKey: adapterKey},
	}
	for raw, want := range cases {
		got, err := Parse(raw)
		if err != nil || got != want {
			t.Fatalf("%s: got=%#v want=%#v err=%v", raw, got, want, err)
		}
	}
	for _, raw := range []string{"gcp-secret-manager://", "gcp-secret-manager://project", "gcp-secret-manager://project/name/extra/key", "gcp-secret-manager://project//key", "vault://x/y/z"} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}

func FuzzParseReference(f *testing.F) {
	for _, seed := range []string{
		"gcp-secret-manager://my-project/my-secret",
		"gcp-secret-manager://my-project/my-secret/KEY",
		"gcp-secret-manager://",
		"gcp-secret-manager://project",
		"gcp-secret-manager://project/name/extra\x00/key",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		ref, err := Parse(raw)
		if err == nil && (ref.Scheme != "gcp-secret-manager" || ref.Region == "" || ref.Container == "") {
			t.Fatalf("successful parse returned incomplete reference")
		}
	})
}

type fakeSecretManagerAPI struct {
	access func(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error)
	add    func(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error)
	create func(ctx context.Context, req *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error)
}

func (f *fakeSecretManagerAPI) AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error) {
	return f.access(ctx, req)
}
func (f *fakeSecretManagerAPI) AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, _ ...gax.CallOption) (*secretmanagerpb.SecretVersion, error) {
	return f.add(ctx, req)
}
func (f *fakeSecretManagerAPI) CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, _ ...gax.CallOption) (*secretmanagerpb.Secret, error) {
	return f.create(ctx, req)
}

func notFound() error { return status.Error(codes.NotFound, "not found") }

func TestShouldReadBlobAndKeyedValuesGivenSharedPayload(t *testing.T) {
	fake := &fakeSecretManagerAPI{access: func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
		return &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: []byte(`{"a":"one","b":"two"}`)}}, nil
	}}
	s := &SecretManager{C: fake}
	refs := []provider.Reference{
		{Region: "p", Container: "s", Key: "a"},
		{Region: "p", Container: "s", Key: "b"},
	}
	values, err := s.ReadMany(context.Background(), refs)
	if err != nil || values[refs[0].Binding()].Reveal() != "one" || values[refs[1].Binding()].Reveal() != "two" {
		t.Fatalf("values=%v err=%v", values, err)
	}
}

func TestShouldReadRawPayloadGivenBlobReference(t *testing.T) {
	fake := &fakeSecretManagerAPI{access: func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
		return &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: []byte("raw-value")}}, nil
	}}
	s := &SecretManager{C: fake}
	ref := provider.Reference{Region: "p", Container: "s"}
	values, err := s.ReadMany(context.Background(), []provider.Reference{ref})
	if err != nil || values[ref.Binding()].Reveal() != "raw-value" {
		t.Fatalf("values=%v err=%v", values, err)
	}
}

func TestShouldFailReadGivenSecretNotFound(t *testing.T) {
	fake := &fakeSecretManagerAPI{access: func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
		return nil, notFound()
	}}
	s := &SecretManager{C: fake}
	ref := provider.Reference{Region: "p", Container: "s", Key: "a"}
	values, err := s.ReadMany(context.Background(), []provider.Reference{ref})
	if err != nil || values[ref.Binding()].Found || values[ref.Binding()].Diagnostic != provider.SecretNotFound {
		t.Fatalf("values=%v err=%v", values, err)
	}
}

func TestShouldMergeIntoExistingPayloadGivenSecretExists(t *testing.T) {
	var addedPayload []byte
	fake := &fakeSecretManagerAPI{
		access: func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: []byte(`{"keep":"yes"}`)}}, nil
		},
		add: func(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
			addedPayload = req.GetPayload().GetData()
			return &secretmanagerpb.SecretVersion{}, nil
		},
	}
	s := &SecretManager{C: fake}
	writes := []provider.Write{{Environment: "A", Reference: provider.Reference{Region: "p", Container: "s", Key: "new"}, Value: secret.New("value")}}
	receipt, err := s.WriteMany(context.Background(), writes)
	if err != nil || len(receipt.Completed) != 1 || string(addedPayload) != `{"keep":"yes","new":"value"}` {
		t.Fatalf("receipt=%v payload=%s err=%v", receipt, addedPayload, err)
	}
}

func TestShouldCreateSecretGivenNotFoundThenAddVersion(t *testing.T) {
	created := false
	fake := &fakeSecretManagerAPI{
		access: func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, notFound()
		},
		create: func(_ context.Context, req *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error) {
			created = true
			if req.GetParent() != "projects/p" || req.GetSecretId() != "s" {
				t.Fatalf("unexpected create request: %#v", req)
			}
			return &secretmanagerpb.Secret{}, nil
		},
		add: func(context.Context, *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
			return &secretmanagerpb.SecretVersion{}, nil
		},
	}
	s := &SecretManager{C: fake}
	writes := []provider.Write{{Environment: "A", Reference: provider.Reference{Region: "p", Container: "s"}, Value: secret.New("value")}}
	receipt, err := s.WriteMany(context.Background(), writes)
	if err != nil || len(receipt.Completed) != 1 || !created {
		t.Fatalf("receipt=%v created=%v err=%v", receipt, created, err)
	}
}

func TestShouldRereadAndPreserveSiblingsGivenCreateRace(t *testing.T) {
	reads := 0
	var added []byte
	fake := &fakeSecretManagerAPI{
		access: func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			reads++
			if reads == 1 {
				return nil, notFound()
			}
			return &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: []byte(`{"sibling":"preserved"}`)}}, nil
		},
		create: func(context.Context, *secretmanagerpb.CreateSecretRequest) (*secretmanagerpb.Secret, error) {
			return nil, status.Error(codes.AlreadyExists, "raced")
		},
		add: func(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
			added = req.GetPayload().GetData()
			return &secretmanagerpb.SecretVersion{}, nil
		},
	}
	writes := []provider.Write{{Environment: "A", Reference: provider.Reference{Region: "p", Container: "s", Key: "new"}, Value: secret.New("value")}}
	if _, err := (&SecretManager{C: fake}).WriteMany(context.Background(), writes); err != nil || reads != 2 || string(added) != `{"new":"value","sibling":"preserved"}` {
		t.Fatalf("reads=%d added=%s err=%v", reads, added, err)
	}
}

func TestShouldRejectNilSDKResponses(t *testing.T) {
	readFake := &fakeSecretManagerAPI{
		access: func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return nil, nil
		},
	}
	writeFake := &fakeSecretManagerAPI{
		access: func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			return &secretmanagerpb.AccessSecretVersionResponse{Payload: &secretmanagerpb.SecretPayload{Data: []byte("old")}}, nil
		},
		add: func(context.Context, *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
			return nil, nil
		},
	}
	ref := provider.Reference{Region: "p", Container: "s"}
	if _, err := (&SecretManager{C: readFake}).ReadMany(context.Background(), []provider.Reference{ref}); err == nil {
		t.Fatal("expected nil read response to fail")
	} else {
		var typed *provider.Error
		if !errors.As(err, &typed) || typed.Kind != provider.InvalidState || typed.Diagnostic != provider.InvalidResponse {
			t.Fatalf("read err=%v", err)
		}
	}
	if _, err := (&SecretManager{C: writeFake}).WriteMany(context.Background(), []provider.Write{{Environment: "A", Reference: ref, Value: secret.New("value")}}); err == nil {
		t.Fatal("expected nil write response to fail")
	}
}

func TestShouldRollbackToPreviousVersionGivenLatestVersionAtLeastTwo(t *testing.T) {
	var addedPayload []byte
	fake := &fakeSecretManagerAPI{
		access: func(_ context.Context, req *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
			if req.GetName() == "projects/p/secrets/s/versions/latest" {
				return &secretmanagerpb.AccessSecretVersionResponse{Name: "projects/p/secrets/s/versions/4", Payload: &secretmanagerpb.SecretPayload{Data: []byte("new")}}, nil
			}
			if req.GetName() == "projects/p/secrets/s/versions/3" {
				return &secretmanagerpb.AccessSecretVersionResponse{Name: req.GetName(), Payload: &secretmanagerpb.SecretPayload{Data: []byte("old")}}, nil
			}
			return nil, notFound()
		},
		add: func(_ context.Context, req *secretmanagerpb.AddSecretVersionRequest) (*secretmanagerpb.SecretVersion, error) {
			addedPayload = req.GetPayload().GetData()
			return &secretmanagerpb.SecretVersion{}, nil
		},
	}
	s := &SecretManager{C: fake}
	err := s.Rollback(context.Background(), provider.Reference{Region: "p", Container: "s"})
	if err != nil || string(addedPayload) != "old" {
		t.Fatalf("payload=%s err=%v", addedPayload, err)
	}
}

func TestShouldFailRollbackGivenOnlyOneVersionExists(t *testing.T) {
	fake := &fakeSecretManagerAPI{access: func(context.Context, *secretmanagerpb.AccessSecretVersionRequest) (*secretmanagerpb.AccessSecretVersionResponse, error) {
		return &secretmanagerpb.AccessSecretVersionResponse{Name: "projects/p/secrets/s/versions/1", Payload: &secretmanagerpb.SecretPayload{Data: []byte("only")}}, nil
	}}
	s := &SecretManager{C: fake}
	err := s.Rollback(context.Background(), provider.Reference{Region: "p", Container: "s"})
	var typed *provider.Error
	if !errors.As(err, &typed) || typed.Kind != provider.InvalidState {
		t.Fatalf("err=%v", err)
	}
}
