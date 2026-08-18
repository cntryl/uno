// Package aws adapts explicit AWS Secrets Manager and SSM references.
package aws

import (
	"context"
	"errors"
	"time"

	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/smithy-go"
	"github.com/cntryl/uno/internal/core/provider"
)

type SecretsAPI interface {
	GetSecretValue(context.Context, *sm.GetSecretValueInput, ...func(*sm.Options)) (*sm.GetSecretValueOutput, error)
	CreateSecret(context.Context, *sm.CreateSecretInput, ...func(*sm.Options)) (*sm.CreateSecretOutput, error)
	PutSecretValue(context.Context, *sm.PutSecretValueInput, ...func(*sm.Options)) (*sm.PutSecretValueOutput, error)
	UpdateSecretVersionStage(context.Context, *sm.UpdateSecretVersionStageInput, ...func(*sm.Options)) (*sm.UpdateSecretVersionStageOutput, error)
}
type Secrets struct {
	C      SecretsAPI
	wait   func(context.Context, time.Duration) error
	jitter func(time.Duration) time.Duration
}

func (s *Secrets) ReadMany(ctx context.Context, refs []provider.Reference) (map[string]provider.ReadResult, error) {
	if err := provider.ValidateReadGroup(refs); err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return nil, nil
	}
	out, err := s.C.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: &refs[0].Container})
	if err != nil {
		if isMissing(err) {
			return provider.MissingResultsWithDiagnostic(refs, provider.SecretNotFound), nil
		}
		return nil, remoteError(err)
	}
	if out == nil {
		return nil, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.InvalidResponse}
	}
	if out.SecretString == nil {
		if out.SecretBinary != nil {
			return nil, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.UnsupportedContent}
		}
		return nil, &provider.Error{Kind: provider.InvalidState, Diagnostic: provider.InvalidResponse}
	}
	return provider.ReadJSONDocument(refs, []byte(*out.SecretString))
}

// Rollback moves AWSCURRENT back to whatever AWSPREVIOUS currently points
// at — the exact inverse of the promotion WriteMany performs, so it's a
// single compare-and-swap-free stage move rather than a new write. It fails
// with InvalidState if there is no distinct previous version (e.g. the
// secret has only ever been written once).
func (s *Secrets) Rollback(ctx context.Context, ref provider.Reference) error {
	id := ref.Container
	current, err := s.C.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: &id, VersionStage: stringPtr("AWSCURRENT")})
	if err != nil {
		return remoteError(err)
	}
	previous, err := s.C.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: &id, VersionStage: stringPtr("AWSPREVIOUS")})
	if err != nil {
		return remoteError(err)
	}
	if current.VersionId == nil || previous.VersionId == nil {
		return &provider.Error{Kind: provider.InvalidState, Detail: "no previous version to roll back to"}
	}
	if *current.VersionId == *previous.VersionId {
		return &provider.Error{Kind: provider.InvalidState, Detail: "no distinct previous version to roll back to"}
	}
	_, err = s.C.UpdateSecretVersionStage(ctx, &sm.UpdateSecretVersionStageInput{
		SecretId: &id, VersionStage: stringPtr("AWSCURRENT"),
		MoveToVersionId: previous.VersionId, RemoveFromVersionId: current.VersionId,
	})
	if err != nil {
		return remoteError(err)
	}
	return nil
}

func stringPtr(s string) *string { return &s }

func isMissing(err error) bool {
	var missingSM *smtypes.ResourceNotFoundException
	var missingSSM *ssmtypes.ParameterNotFound
	return errors.As(err, &missingSM) || errors.As(err, &missingSSM)
}
func remoteError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var missingSM *smtypes.ResourceNotFoundException
	var missingSSM *ssmtypes.ParameterNotFound
	if errors.As(err, &missingSM) || errors.As(err, &missingSSM) {
		return &provider.Error{Kind: provider.InvalidBinding}
	}
	var api smithy.APIError
	if errors.As(err, &api) {
		switch api.ErrorCode() {
		case "UnrecognizedClientException", "InvalidSignatureException", "ExpiredTokenException", "InvalidClientTokenId":
			return &provider.Error{Kind: provider.Authentication}
		case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
			return &provider.Error{Kind: provider.AccessDenied}
		case "InvalidParameterException", "InvalidRequestException", "ParameterAlreadyExists":
			return &provider.Error{Kind: provider.InvalidState}
		}
	}
	return &provider.Error{Kind: provider.Indeterminate}
}
