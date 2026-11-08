package dispatcher

import (
	"math"
	"math/rand/v2"
	"time"
)

// CalculateBackoffCeiling returns min(maxDelay, baseDelay * 2^attempt) with 64-bit overflow protection.
func CalculateBackoffCeiling(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	if baseDelay <= 0 {
		return 0
	}
	if maxDelay <= 0 {
		maxDelay = baseDelay
	}
	if attempt <= 0 {
		if baseDelay > maxDelay {
			return maxDelay
		}
		return baseDelay
	}
	if attempt >= 62 {
		return maxDelay
	}

	multiplier := int64(1) << uint(attempt)
	if int64(baseDelay) > math.MaxInt64/multiplier {
		return maxDelay
	}

	calculated := time.Duration(multiplier) * baseDelay
	if calculated <= 0 || calculated > maxDelay {
		return maxDelay
	}
	return calculated
}

func CalculateBackoffDeterministic(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	return CalculateBackoffCeiling(attempt, baseDelay, maxDelay)
}

// CalculateBackoff computes an exponential backoff duration with Full Jitter in [0, ceiling).
func CalculateBackoff(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	if baseDelay <= 0 {
		return 0
	}
	if maxDelay <= 0 {
		maxDelay = baseDelay
	}
	if attempt <= 0 {
		if baseDelay > maxDelay {
			return maxDelay
		}
		return baseDelay
	}

	ceiling := CalculateBackoffCeiling(attempt, baseDelay, maxDelay)
	if ceiling <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(ceiling)))
}
