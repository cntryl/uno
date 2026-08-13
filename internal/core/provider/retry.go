package provider

import (
	"context"
	"crypto/rand"
	"math/big"
	"time"
)

func WaitBeforeRetry(ctx context.Context, attempt int, wait func(context.Context, time.Duration) error, jitter func(time.Duration) time.Duration) error {
	ceiling := backoffCeiling(attempt)
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

const (
	backoffBase = 200 * time.Millisecond
	backoffCap  = 2 * time.Second
	// maxBackoffShift bounds the exponent so 1<<attempt can never overflow
	// int64 (or the Duration arithmetic that follows); once the exponential
	// term would already dwarf backoffCap, there's no need to compute it.
	maxBackoffShift = 32
)

func backoffCeiling(attempt int) time.Duration {
	if attempt < 0 || attempt > maxBackoffShift {
		return backoffCap
	}
	ceiling := backoffBase * time.Duration(1<<uint(attempt))
	if ceiling <= 0 || ceiling > backoffCap {
		return backoffCap
	}
	return ceiling
}

func randomDelay(ceiling time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(ceiling)+1))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}
