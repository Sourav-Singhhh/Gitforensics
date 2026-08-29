package detect

import (
	"math"
	"testing"
)

func TestShannonEntropy(t *testing.T) {
	// Empty data
	if h := CalculateShannonEntropy(nil); h != 0.0 {
		t.Errorf("expected 0.0 for nil data, got %f", h)
	}

	// Single repeated character -> 0 bits of entropy
	repeated := []byte("AAAAAAAAAAAAAAAAAAAA")
	if h := CalculateShannonEntropy(repeated); h != 0.0 {
		t.Errorf("expected 0.0 for single repeated byte, got %f", h)
	}

	// Two equally probable bytes -> 1 bit of entropy
	twoBytes := []byte("ABABABABABABABAB")
	if h := CalculateShannonEntropy(twoBytes); math.Abs(h-1.0) > 0.001 {
		t.Errorf("expected 1.0 bit for 2 uniform bytes, got %f", h)
	}

	// High entropy random-like string
	highEntropy := []byte("4Kz9#mQv!8xL@2wP$7yN%1vR^6tB&0s")
	hHigh := CalculateShannonEntropy(highEntropy)
	if hHigh < 4.0 {
		t.Errorf("expected high entropy > 4.0, got %f", hHigh)
	}

	// Test tiered contributions
	if c := EntropyContribution(4.6); c != 25 {
		t.Errorf("expected +25 for entropy >= 4.5, got %d", c)
	}
	if c := EntropyContribution(4.0); c != 18 {
		t.Errorf("expected +18 for entropy >= 3.8, got %d", c)
	}
	if c := EntropyContribution(3.2); c != 10 {
		t.Errorf("expected +10 for entropy >= 3.0, got %d", c)
	}
	if c := EntropyContribution(2.5); c != 0 {
		t.Errorf("expected 0 for entropy < 3.0, got %d", c)
	}
}
