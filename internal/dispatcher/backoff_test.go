package dispatcher

import (
	"math"
	"testing"
	"time"
)

func TestCalculateBackoff_ZeroAndNegativeInputs(t *testing.T) {
	base := 100 * time.Millisecond
	max := 5 * time.Second

	for _, attempt := range []int{0, -1, -100, math.MinInt} {
		got := CalculateBackoff(attempt, base, max)
		if got != base {
			t.Fatalf("attempt=%d: expected %v, got %v", attempt, base, got)
		}
		ceil := CalculateBackoffDeterministic(attempt, base, max)
		if ceil != base {
			t.Fatalf("attempt=%d ceiling: expected %v, got %v", attempt, base, ceil)
		}
	}

	// When baseDelay > maxDelay and attempt <= 0, clamps to maxDelay.
	if got := CalculateBackoff(0, 10*time.Second, 2*time.Second); got != 2*time.Second {
		t.Fatalf("expected clamp to maxDelay 2s, got %v", got)
	}
	if got := CalculateBackoffCeiling(0, 10*time.Second, 2*time.Second); got != 2*time.Second {
		t.Fatalf("expected ceiling clamp to maxDelay 2s, got %v", got)
	}

	// Non-positive baseDelay returns 0 without panicking.
	for _, b := range []time.Duration{0, -1 * time.Millisecond, -10 * time.Second} {
		if got := CalculateBackoff(3, b, max); got != 0 {
			t.Fatalf("base=%v: expected 0, got %v", b, got)
		}
		if got := CalculateBackoffCeiling(3, b, max); got != 0 {
			t.Fatalf("base=%v ceiling: expected 0, got %v", b, got)
		}
	}

	// Non-positive maxDelay falls back to baseDelay.
	for _, m := range []time.Duration{0, -1 * time.Second} {
		got := CalculateBackoff(3, base, m)
		if got < 0 || got >= base {
			t.Fatalf("max=%v: expected in [0, %v), got %v", m, base, got)
		}
	}
}

func TestCalculateBackoff_OverflowProtection(t *testing.T) {
	base := 100 * time.Millisecond
	max := 10 * time.Second

	attempts := []int{1, 2, 5, 10, 30, 50, 61, 62, 63, 64, 65, 100, 1000, math.MaxInt}
	for _, att := range attempts {
		for i := 0; i < 20; i++ {
			d := CalculateBackoff(att, base, max)
			if d < 0 || d > max {
				t.Fatalf("attempt=%d: backoff %v out of bounds [0, %v]", att, d, max)
			}
		}
		ceil := CalculateBackoffCeiling(att, base, max)
		if ceil <= 0 || ceil > max {
			t.Fatalf("attempt=%d: ceiling %v out of bounds (0, %v]", att, ceil, max)
		}
	}

	// Large baseDelay that would overflow int64 when multiplied by 2^40.
	hugeBase := 365 * 24 * time.Hour
	hugeMax := 2 * hugeBase
	ceil := CalculateBackoffCeiling(40, hugeBase, hugeMax)
	if ceil != hugeMax {
		t.Fatalf("expected overflow clamp to %v, got %v", hugeMax, ceil)
	}
}

func TestCalculateBackoff_FullJitterAndCeilingProgression(t *testing.T) {
	base := 10 * time.Millisecond
	max := 100 * time.Millisecond

	expectedCeilings := map[int]time.Duration{
		0: 10 * time.Millisecond,
		1: 20 * time.Millisecond,
		2: 40 * time.Millisecond,
		3: 80 * time.Millisecond,
		4: 100 * time.Millisecond,
		5: 100 * time.Millisecond,
	}
	for att, want := range expectedCeilings {
		if got := CalculateBackoffCeiling(att, base, max); got != want {
			t.Fatalf("attempt %d: expected ceiling %v, got %v", att, want, got)
		}
	}

	distinct := make(map[time.Duration]struct{})
	ceiling := 80 * time.Millisecond
	for i := 0; i < 200; i++ {
		d := CalculateBackoff(3, base, max)
		if d < 0 || d >= ceiling {
			t.Fatalf("sample %v outside [0, %v)", d, ceiling)
		}
		distinct[d] = struct{}{}
	}
	if len(distinct) < 10 {
		t.Fatalf("expected Full Jitter to produce varied samples, got only %d distinct values", len(distinct))
	}
}
