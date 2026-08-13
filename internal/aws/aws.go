// Package aws adapts explicit AWS Secrets Manager and SSM references.
package aws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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

const maxWriteAttempts = 4

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
			return provider.MissingResults(refs), nil
		}
		return nil, remoteError(err)
	}
	if out.SecretString == nil {
		return nil, &provider.Error{Kind: provider.InvalidState}
	}
	return provider.ReadJSONDocument(refs, []byte(*out.SecretString))
}

func (s *Secrets) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	if err := provider.ValidateWriteGroup(writes); err != nil {
		return provider.Receipt{}, err
	}
	if len(writes) == 0 {
		return provider.Receipt{}, nil
	}
	id := writes[0].Reference.Container
	for attempt := range maxWriteAttempts {
		out, getErr := s.C.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: &id})
		if isMissing(getErr) {
			payload, err := provider.MergeJSONDocument(nil, writes)
			if err != nil {
				return provider.Receipt{}, err
			}
			payloadString := string(payload)
			if _, err = s.C.CreateSecret(ctx, &sm.CreateSecretInput{Name: &id, SecretString: &payloadString}); err == nil {
				return provider.Receipt{Completed: provider.Environments(writes)}, nil
			}
			var exists *smtypes.ResourceExistsException
			if !errors.As(err, &exists) {
				return provider.Receipt{}, remoteError(err)
			}
			if attempt == maxWriteAttempts-1 {
				return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
			}
			if err := s.waitBeforeRetry(ctx, attempt); err != nil {
				return provider.Receipt{}, err
			}
			continue
		}
		if getErr != nil {
			return provider.Receipt{}, remoteError(getErr)
		}
		if out.VersionId == nil {
			return provider.Receipt{}, &provider.Error{Kind: provider.InvalidState}
		}
		var existing []byte
		if out.SecretString != nil {
			existing = []byte(*out.SecretString)
		}
		payload, err := provider.MergeJSONDocument(existing, writes)
		if err != nil {
			return provider.Receipt{}, err
		}
		payloadString := string(payload)
		token, err := randomToken()
		if err != nil {
			return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
		}
		stage := "UNO-PENDING-" + token
		put, err := s.C.PutSecretValue(ctx, &sm.PutSecretValueInput{SecretId: &id, SecretString: &payloadString, ClientRequestToken: &token, VersionStages: []string{stage}})
		if err != nil {
			return provider.Receipt{}, remoteError(err)
		}
		version := token
		if put.VersionId != nil {
			version = *put.VersionId
		}
		_, promoteErr := s.C.UpdateSecretVersionStage(ctx, &sm.UpdateSecretVersionStageInput{SecretId: &id, VersionStage: stringPtr("AWSCURRENT"), MoveToVersionId: &version, RemoveFromVersionId: out.VersionId})
		if promoteErr == nil {
			if err := s.removePending(ctx, id, stage, version); err != nil {
				return provider.Receipt{Completed: provider.Environments(writes)}, err
			}
			return provider.Receipt{Completed: provider.Environments(writes)}, nil
		}
		current, observeErr := s.C.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: &id})
		if observeErr != nil || current == nil || current.VersionId == nil {
			if err := s.removePending(ctx, id, stage, version); err != nil {
				return provider.Receipt{}, err
			}
			return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
		}
		cleanupErr := s.removePending(ctx, id, stage, version)
		switch *current.VersionId {
		case version:
			if cleanupErr != nil {
				return provider.Receipt{Completed: provider.Environments(writes)}, cleanupErr
			}
			return provider.Receipt{Completed: provider.Environments(writes)}, nil
		case *out.VersionId:
			if cleanupErr != nil {
				return provider.Receipt{}, cleanupErr
			}
			if attempt == maxWriteAttempts-1 {
				return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
			}
			if err := s.waitBeforeRetry(ctx, attempt); err != nil {
				return provider.Receipt{}, err
			}
			continue
		default:
			if cleanupErr != nil {
				return provider.Receipt{}, cleanupErr
			}
			if attempt == maxWriteAttempts-1 {
				return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
			}
			if err := s.waitBeforeRetry(ctx, attempt); err != nil {
				return provider.Receipt{}, err
			}
			continue
		}
	}
	return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
}

// removePendingCleanupTimeout bounds the detached context used to strip a
// pending version stage after the caller's context has already expired, so a
// cleanup attempt following a timeout still gets a chance to run instead of
// failing immediately and leaking the stage forever.
const removePendingCleanupTimeout = 10 * time.Second

func (s *Secrets) removePending(ctx context.Context, id, stage, version string) error {
	if ctx.Err() != nil {
		// The caller's context is already done (e.g. deadline exceeded during
		// promotion). Detach from it so this cleanup call isn't doomed to fail
		// before it even starts, which would otherwise leave the UNO-PENDING-*
		// stage attached to the secret version forever.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), removePendingCleanupTimeout)
		defer cancel()
	}
	_, err := s.C.UpdateSecretVersionStage(ctx, &sm.UpdateSecretVersionStageInput{SecretId: &id, VersionStage: &stage, RemoveFromVersionId: &version})
	if err != nil {
		return &provider.Error{Kind: provider.PendingCleanupFailed}
	}
	return nil
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

func (s *Secrets) waitBeforeRetry(ctx context.Context, attempt int) error {
	return provider.WaitBeforeRetry(ctx, attempt, s.wait, s.jitter)
}
func randomToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
func stringPtr(s string) *string { return &s }

func isMissing(err error) bool {
	var missing *smtypes.ResourceNotFoundException
	return errors.As(err, &missing)
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
