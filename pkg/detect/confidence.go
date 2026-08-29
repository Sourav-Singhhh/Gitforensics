package detect

// ConfidenceTier represents the confidence classification of a finding (§10).
type ConfidenceTier string

const (
	TierLow      ConfidenceTier = "LOW"
	TierMedium   ConfidenceTier = "MEDIUM"
	TierHigh     ConfidenceTier = "HIGH"
	TierCritical ConfidenceTier = "CRITICAL"
)

// ConfidenceScore computes the total clamped score and tier from components (§10).
//
// Invariants:
// 1. Clamped to [0, 100].
// 2. Tiers:
//   - 0–39   -> LOW
//   - 40–69  -> MEDIUM
//   - 70–89  -> HIGH
//   - 90–100 -> CRITICAL
func ConfidenceScore(basePatternScore, entropyScore, contextScore, pathScore int) (int, ConfidenceTier) {
	total := basePatternScore + entropyScore + contextScore + pathScore
	if total < 0 {
		total = 0
	}
	if total > 100 {
		total = 100
	}

	var tier ConfidenceTier
	switch {
	case total >= 90:
		tier = TierCritical
	case total >= 70:
		tier = TierHigh
	case total >= 40:
		tier = TierMedium
	default:
		tier = TierLow
	}

	return total, tier
}

// ParseConfidenceTier parses a string into ConfidenceTier, returning (tier, ok).
func ParseConfidenceTier(s string) (ConfidenceTier, bool) {
	switch s {
	case "low", "LOW":
		return TierLow, true
	case "medium", "MEDIUM":
		return TierMedium, true
	case "high", "HIGH":
		return TierHigh, true
	case "critical", "CRITICAL":
		return TierCritical, true
	default:
		return "", false
	}
}

// TierRank returns numeric priority of a tier for filtering comparisons (Low=1, Medium=2, High=3, Critical=4).
func TierRank(tier ConfidenceTier) int {
	switch tier {
	case TierCritical:
		return 4
	case TierHigh:
		return 3
	case TierMedium:
		return 2
	case TierLow:
		return 1
	default:
		return 0
	}
}
