package detect

import (
	"math"
)

// CalculateShannonEntropy computes the Shannon entropy in bits per byte over a slice of bytes (§10).
// Returns 0.0 if the slice is empty.
func CalculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	length := float64(len(data))
	var entropy float64

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// EntropyContribution evaluates the Shannon entropy and returns the provisional tiered score contribution (§10).
//
// Tiered contributions:
// - Entropy >= 4.5 -> +25
// - Entropy >= 3.8 -> +18
// - Entropy >= 3.0 -> +10
// - Otherwise      -> 0
func EntropyContribution(entropy float64) int {
	switch {
	case entropy >= 4.5:
		return 25
	case entropy >= 3.8:
		return 18
	case entropy >= 3.0:
		return 10
	default:
		return 0
	}
}
