package provider

import (
	"context"
	"crypto/rand"
	"math/big"
	"time"
)

func WaitBeforeRetry(ctx context.Context, attempt int, wait func(context.Context, time.Duration) error, jitter func(time.Duration) time.Duration) error {
	ceiling := 200 * time.Millisecond * time.Duration(1<<attempt)
	if ceiling > 2*time.Second {
		ceiling = 2 * time.Second
	}
	delay := randomDelay(ceiling)
	if jitter != nil {
		delay = jitter(ceiling)
	}
	if wait != nil {
		if err := wait(ctx, delay); err != nil {
			return &Error{Kind: Indeterminate}
		}
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return &Error{Kind: Indeterminate}
	case <-timer.C:
		return nil
	}
}

func randomDelay(ceiling time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(ceiling)+1))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}
