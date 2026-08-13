package gcp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	gax "github.com/googleapis/gax-go/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/cntryl/uno/internal/core/provider"
)

// SecretManagerAPI is the subset of *secretmanager.Client's method set this
// adapter needs. The real client satisfies it structurally; tests substitute
// a fake.
type SecretManagerAPI interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	AddSecretVersion(ctx context.Context, req *secretmanagerpb.AddSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.SecretVersion, error)
	CreateSecret(ctx context.Context, req *secretmanagerpb.CreateSecretRequest, opts ...gax.CallOption) (*secretmanagerpb.Secret, error)
}

type SecretManager struct{ C SecretManagerAPI }

func secretName(ref provider.Reference) string {
	return fmt.Sprintf("projects/%s/secrets/%s", ref.Region, ref.Container)
}

func (s *SecretManager) ReadMany(ctx context.Context, refs []provider.Reference) (map[string]provider.ReadResult, error) {
	if err := provider.ValidateReadGroup(refs); err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, nil
	}
	out, err := s.C.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: secretName(refs[0]) + "/versions/latest"})
	if err != nil {
		if isNotFound(err) {
			return provider.MissingResults(refs), nil
		}
		return nil, remoteError(err)
	}
	if out.GetPayload() == nil {
		return nil, &provider.Error{Kind: provider.InvalidState}
	}
	return provider.ReadJSONDocument(refs, out.GetPayload().GetData())
}

// WriteMany merges every write into the secret's latest payload (like AWS
// Secrets Manager) and adds it as a new version, creating the secret first
// if it doesn't exist yet.
//
// Unlike AWS Secrets Manager and Vault, this has no compare-and-swap
// protection: the stable Secret Manager API has no conditional-write
// primitive for AddSecretVersion, so a concurrent writer's read-modify-write
// can race and the later AddSecretVersion call wins outright, silently
// dropping the earlier one's sibling keys.
func (s *SecretManager) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	if err := provider.ValidateWriteGroup(writes); err != nil {
		return provider.Receipt{}, err
	}
	if len(writes) == 0 {
		return provider.Receipt{}, nil
	}
	ref := writes[0].Reference
	name := secretName(ref)
	existing, err := s.C.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: name + "/versions/latest"})
	var existingData []byte
	switch {
	case err == nil:
		if existing == nil || existing.GetPayload() == nil {
			return provider.Receipt{}, &provider.Error{Kind: provider.InvalidState}
		}
		existingData = existing.GetPayload().GetData()
	case isNotFound(err):
		created, createErr := s.C.CreateSecret(ctx, &secretmanagerpb.CreateSecretRequest{
			Parent:   "projects/" + ref.Region,
			SecretId: ref.Container,
			Secret: &secretmanagerpb.Secret{
				Replication: &secretmanagerpb.Replication{Replication: &secretmanagerpb.Replication_Automatic_{Automatic: &secretmanagerpb.Replication_Automatic{}}},
			},
		})
		if createErr != nil {
			if !isAlreadyExists(createErr) {
				return provider.Receipt{}, remoteError(createErr)
			}
			existing, err = s.C.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: name + "/versions/latest"})
			if err != nil {
				return provider.Receipt{}, remoteError(err)
			}
			if existing == nil || existing.GetPayload() == nil {
				return provider.Receipt{}, &provider.Error{Kind: provider.InvalidState}
			}
			existingData = existing.GetPayload().GetData()
		} else if created == nil {
			return provider.Receipt{}, &provider.Error{Kind: provider.InvalidState}
		}
	default:
		return provider.Receipt{}, remoteError(err)
	}
	payload, err := provider.MergeJSONDocument(existingData, writes)
	if err != nil {
		return provider.Receipt{}, err
	}
	added, err := s.C.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{Parent: name, Payload: &secretmanagerpb.SecretPayload{Data: payload}})
	if err != nil {
		return provider.Receipt{}, remoteError(err)
	}
	if added == nil {
		return provider.Receipt{}, &provider.Error{Kind: provider.InvalidState}
	}
	return provider.Receipt{Completed: provider.Environments(writes)}, nil
}

// Rollback fetches the value one version behind the secret's latest version
// and adds it again as a new version. Like SSM (and for the same reason —
// no movable "current" pointer in this API), this is best-effort: rolling
// back twice in a row does not return to the value from three writes ago.
func (s *SecretManager) Rollback(ctx context.Context, ref provider.Reference) error {
	name := secretName(ref)
	latest, err := s.C.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: name + "/versions/latest"})
	if err != nil {
		return remoteError(err)
	}
	version, err := versionNumber(latest.GetName())
	if err != nil || version < 2 {
		return &provider.Error{Kind: provider.InvalidState, Detail: "no previous version to roll back to"}
	}
	previous, err := s.C.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: fmt.Sprintf("%s/versions/%d", name, version-1)})
	if err != nil {
		return remoteError(err)
	}
	if previous.GetPayload() == nil {
		return &provider.Error{Kind: provider.InvalidState}
	}
	if _, err := s.C.AddSecretVersion(ctx, &secretmanagerpb.AddSecretVersionRequest{Parent: name, Payload: previous.GetPayload()}); err != nil {
		return remoteError(err)
	}
	return nil
}

func versionNumber(resourceName string) (int, error) {
	const marker = "/versions/"
	idx := strings.LastIndex(resourceName, marker)
	if idx < 0 {
		return 0, fmt.Errorf("unexpected version resource name")
	}
	return strconv.Atoi(resourceName[idx+len(marker):])
}

func isNotFound(err error) bool {
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.NotFound
}

func isAlreadyExists(err error) bool {
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.AlreadyExists
}

// remoteError classifies a gRPC status the way the AWS and Vault adapters
// classify their own SDK errors. This is deliberately an if-chain rather
// than a switch over codes.Code — that enum has ~17 members and only a
// handful matter here, so exhaustively listing the rest would only add
// noise every time the API adds a new code.
func remoteError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	st, ok := status.FromError(err)
	if !ok {
		return &provider.Error{Kind: provider.Indeterminate}
	}
	if st.Code() == codes.NotFound {
		return &provider.Error{Kind: provider.InvalidBinding}
	}
	if st.Code() == codes.Unauthenticated {
		return &provider.Error{Kind: provider.Authentication}
	}
	if st.Code() == codes.PermissionDenied {
		return &provider.Error{Kind: provider.AccessDenied}
	}
	if st.Code() == codes.FailedPrecondition {
		return &provider.Error{Kind: provider.InvalidState}
	}
	return &provider.Error{Kind: provider.Indeterminate}
}
