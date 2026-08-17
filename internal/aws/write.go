package aws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	sm "github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/cntryl/uno/internal/core/provider"
)

const maxWriteAttempts = 4

// removePendingCleanupTimeout bounds the detached context used to strip a
// pending version stage after the caller's context has already expired.
const removePendingCleanupTimeout = 10 * time.Second

type secretsDescriber interface {
	DescribeSecret(context.Context, *sm.DescribeSecretInput, ...func(*sm.Options)) (*sm.DescribeSecretOutput, error)
}

type writeAttemptResult struct {
	receipt provider.Receipt
	err     error
	retry   bool
}

func (s *Secrets) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	if err := provider.ValidateWriteGroup(writes); err != nil {
		return provider.Receipt{}, err
	}
	if len(writes) == 0 {
		return provider.Receipt{}, nil
	}

	secretID := writes[0].Reference.Container
	for attempt := range maxWriteAttempts {
		result := s.writeAttempt(ctx, secretID, writes)
		if !result.retry {
			return result.receipt, result.err
		}
		if attempt == maxWriteAttempts-1 {
			return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
		}
		if err := s.waitBeforeRetry(ctx, attempt); err != nil {
			return provider.Receipt{}, err
		}
	}
	return provider.Receipt{}, &provider.Error{Kind: provider.Indeterminate}
}

func (s *Secrets) writeAttempt(ctx context.Context, secretID string, writes []provider.Write) writeAttemptResult {
	currentSecret, err := s.C.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: &secretID})
	if isMissing(err) {
		return s.initializeMissingSecret(ctx, secretID, writes)
	}
	if err != nil {
		return failedWrite(remoteError(err))
	}
	return s.mergeStageAndPromote(ctx, secretID, currentSecret, writes)
}

func (s *Secrets) initializeMissingSecret(ctx context.Context, secretID string, writes []provider.Write) writeAttemptResult {
	payload, err := provider.MergeJSONDocument(nil, writes)
	if err != nil {
		return failedWrite(err)
	}
	payloadString := string(payload)

	if describer, ok := s.C.(secretsDescriber); ok {
		_, describeErr := describer.DescribeSecret(ctx, &sm.DescribeSecretInput{SecretId: &secretID})
		switch {
		case describeErr == nil:
			return s.initializeExistingSecret(ctx, secretID, payloadString, writes)
		case !isMissing(describeErr):
			return failedWrite(remoteError(describeErr))
		}
	}

	_, err = s.C.CreateSecret(ctx, &sm.CreateSecretInput{Name: &secretID, SecretString: &payloadString})
	if err == nil {
		return completedWrite(writes)
	}
	var alreadyExists *smtypes.ResourceExistsException
	if errors.As(err, &alreadyExists) {
		return retryWrite()
	}
	return failedWrite(remoteError(err))
}

func (s *Secrets) initializeExistingSecret(ctx context.Context, secretID, payload string, writes []provider.Write) writeAttemptResult {
	token, err := randomToken()
	if err != nil {
		return failedWrite(&provider.Error{Kind: provider.Indeterminate})
	}
	_, err = s.C.PutSecretValue(ctx, &sm.PutSecretValueInput{
		SecretId: &secretID, SecretString: &payload, ClientRequestToken: &token,
	})
	if err != nil {
		return failedWrite(remoteError(err))
	}
	return completedWrite(writes)
}

func (s *Secrets) mergeStageAndPromote(ctx context.Context, secretID string, currentSecret *sm.GetSecretValueOutput, writes []provider.Write) writeAttemptResult {
	if currentSecret.VersionId == nil {
		return failedWrite(&provider.Error{Kind: provider.InvalidState})
	}

	var currentPayload []byte
	if currentSecret.SecretString != nil {
		currentPayload = []byte(*currentSecret.SecretString)
	}
	mergedPayload, err := provider.MergeJSONDocument(currentPayload, writes)
	if err != nil {
		return failedWrite(err)
	}

	token, err := randomToken()
	if err != nil {
		return failedWrite(&provider.Error{Kind: provider.Indeterminate})
	}
	pendingStage := "UNO-PENDING-" + token
	payloadString := string(mergedPayload)
	stagedSecret, err := s.C.PutSecretValue(ctx, &sm.PutSecretValueInput{
		SecretId: &secretID, SecretString: &payloadString,
		ClientRequestToken: &token, VersionStages: []string{pendingStage},
	})
	if err != nil {
		return failedWrite(remoteError(err))
	}

	stagedVersion := token
	if stagedSecret.VersionId != nil {
		stagedVersion = *stagedSecret.VersionId
	}
	_, promotionErr := s.C.UpdateSecretVersionStage(ctx, &sm.UpdateSecretVersionStageInput{
		SecretId: &secretID, VersionStage: stringPtr("AWSCURRENT"),
		MoveToVersionId: &stagedVersion, RemoveFromVersionId: currentSecret.VersionId,
	})
	if promotionErr == nil {
		return s.finishPromotedWrite(ctx, secretID, pendingStage, stagedVersion, writes)
	}
	return s.observeAmbiguousPromotion(ctx, secretID, pendingStage, stagedVersion, *currentSecret.VersionId, writes)
}

func (s *Secrets) finishPromotedWrite(ctx context.Context, secretID, pendingStage, stagedVersion string, writes []provider.Write) writeAttemptResult {
	if err := s.removePending(ctx, secretID, pendingStage, stagedVersion); err != nil {
		return writeAttemptResult{receipt: completedReceipt(writes), err: err}
	}
	return completedWrite(writes)
}

func (s *Secrets) observeAmbiguousPromotion(ctx context.Context, secretID, pendingStage, stagedVersion, previousVersion string, writes []provider.Write) writeAttemptResult {
	observedSecret, observeErr := s.C.GetSecretValue(ctx, &sm.GetSecretValueInput{SecretId: &secretID})
	if observeErr != nil || observedSecret == nil || observedSecret.VersionId == nil {
		if cleanupErr := s.removePending(ctx, secretID, pendingStage, stagedVersion); cleanupErr != nil {
			return failedWrite(cleanupErr)
		}
		return failedWrite(&provider.Error{Kind: provider.Indeterminate})
	}

	cleanupErr := s.removePending(ctx, secretID, pendingStage, stagedVersion)
	if *observedSecret.VersionId == stagedVersion {
		if cleanupErr != nil {
			return writeAttemptResult{receipt: completedReceipt(writes), err: cleanupErr}
		}
		return completedWrite(writes)
	}
	if cleanupErr != nil {
		return failedWrite(cleanupErr)
	}

	if *observedSecret.VersionId == previousVersion {
		return retryWrite()
	}
	// A third-party version won the race. Re-read and re-merge on the next
	// attempt so its sibling updates are preserved.
	return retryWrite()
}

func completedReceipt(writes []provider.Write) provider.Receipt {
	return provider.Receipt{Completed: provider.Environments(writes)}
}

func completedWrite(writes []provider.Write) writeAttemptResult {
	return writeAttemptResult{receipt: completedReceipt(writes)}
}

func failedWrite(err error) writeAttemptResult {
	return writeAttemptResult{err: err}
}

func retryWrite() writeAttemptResult {
	return writeAttemptResult{retry: true}
}

func (s *Secrets) removePending(ctx context.Context, secretID, pendingStage, stagedVersion string) error {
	if ctx.Err() != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), removePendingCleanupTimeout)
		defer cancel()
	}
	_, err := s.C.UpdateSecretVersionStage(ctx, &sm.UpdateSecretVersionStageInput{
		SecretId: &secretID, VersionStage: &pendingStage, RemoveFromVersionId: &stagedVersion,
	})
	if err != nil {
		return &provider.Error{Kind: provider.PendingCleanupFailed}
	}
	return nil
}

func (s *Secrets) waitBeforeRetry(ctx context.Context, attempt int) error {
	return provider.WaitBeforeRetry(ctx, attempt, s.wait, s.jitter)
}

func randomToken() (string, error) {
	var tokenBytes [16]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(tokenBytes[:]), nil
}
