package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/cntryl/uno/internal/core/provider"
	"github.com/cntryl/uno/internal/core/secret"
)

type SSMAPI interface {
	GetParameter(context.Context, *ssm.GetParameterInput, ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
	PutParameter(context.Context, *ssm.PutParameterInput, ...func(*ssm.Options)) (*ssm.PutParameterOutput, error)
}

const maxSSMWriteAttempts = 4

type SSM struct {
	C      SSMAPI
	wait   func(context.Context, time.Duration) error
	jitter func(time.Duration) time.Duration
}

func (s *SSM) ReadMany(ctx context.Context, refs []provider.Reference) (map[string]secret.Value, error) {
	values := make(map[string]secret.Value, len(refs))
	for _, ref := range refs {
		value, err := s.read(ctx, ref)
		if err != nil {
			secret.DestroyMap(values)
			return nil, err
		}
		values[ref.Binding()] = value
	}
	return values, nil
}

func (s *SSM) read(ctx context.Context, ref provider.Reference) (secret.Value, error) {
	decrypt := true
	out, err := s.C.GetParameter(ctx, &ssm.GetParameterInput{Name: &ref.Container, WithDecryption: &decrypt})
	if err != nil {
		return secret.Value{}, remoteError(err)
	}
	if out.Parameter == nil || out.Parameter.Value == nil || out.Parameter.Type != ssmtypes.ParameterTypeSecureString {
		return secret.Value{}, &provider.Error{Kind: provider.InvalidState}
	}
	return secret.New(*out.Parameter.Value), nil
}

func (s *SSM) WriteMany(ctx context.Context, writes []provider.Write) (provider.Receipt, error) {
	provider.SortedWrites(writes)
	// retry.NewStandard reuses the AWS SDK's own retryable-error
	// classification (throttling, 5xx, timeouts, connection resets) instead
	// of retrying every non-"not found" error. Built once per batch and
	// shared across every write attempt in it — its classifiers are
	// read-only lookup tables, safe to reuse across calls.
	classifier := retry.NewStandard()
	completed := make([]provider.Write, 0, len(writes))
	for _, write := range writes {
		if err := s.write(ctx, write, classifier); err != nil {
			return provider.Receipt{Completed: provider.Environments(completed)}, err
		}
		completed = append(completed, write)
	}
	return provider.Receipt{Completed: provider.Environments(completed)}, nil
}

// Rollback fetches the value one version behind the parameter's current
// version and writes it again as a new version. Unlike Secrets.Rollback,
// SSM Parameter Store has no movable "current" pointer to swap — every
// PutParameter call always creates a new, incrementing version — so this is
// a best-effort "write the previous value back" rather than a true revert:
// rolling back twice in a row does not return to the value from three
// writes ago, it just re-applies whatever was one version behind at the
// time each rollback ran.
func (s *SSM) Rollback(ctx context.Context, ref provider.Reference) error {
	name := ref.Container
	decrypt := true
	current, err := s.C.GetParameter(ctx, &ssm.GetParameterInput{Name: &name, WithDecryption: &decrypt})
	if err != nil {
		return remoteError(err)
	}
	if current.Parameter == nil || current.Parameter.Version < 2 {
		return &provider.Error{Kind: provider.InvalidState, Detail: "no previous version to roll back to"}
	}
	previousName := fmt.Sprintf("%s:%d", name, current.Parameter.Version-1)
	previous, err := s.C.GetParameter(ctx, &ssm.GetParameterInput{Name: &previousName, WithDecryption: &decrypt})
	if err != nil {
		return remoteError(err)
	}
	if previous.Parameter == nil || previous.Parameter.Value == nil {
		return &provider.Error{Kind: provider.InvalidState}
	}
	overwrite := true
	_, err = s.C.PutParameter(ctx, &ssm.PutParameterInput{
		Name: &name, Value: previous.Parameter.Value, Type: ssmtypes.ParameterTypeSecureString, Overwrite: &overwrite,
	})
	if err != nil {
		return remoteError(err)
	}
	return nil
}

func (s *SSM) write(ctx context.Context, write provider.Write, classifier *retry.Standard) error {
	value := write.Value.Reveal()
	name := write.Reference.Container
	overwrite := true
	var lastErr error
	for attempt := range maxSSMWriteAttempts {
		_, err := s.C.PutParameter(ctx, &ssm.PutParameterInput{
			Name: &name, Value: &value, Type: ssmtypes.ParameterTypeSecureString, Overwrite: &overwrite,
		})
		if err == nil {
			return nil
		}
		wrapped := remoteError(err)
		if !classifier.IsErrorRetryable(err) {
			// Permanent failure (e.g. AccessDenied, validation error, or the
			// parameter path is invalid); retrying wastes latency and repeats
			// the write for no benefit.
			return wrapped
		}
		lastErr = wrapped
		if attempt == maxSSMWriteAttempts-1 {
			break
		}
		if waitErr := provider.WaitBeforeRetry(ctx, attempt, s.wait, s.jitter); waitErr != nil {
			return waitErr
		}
	}
	return lastErr
}
