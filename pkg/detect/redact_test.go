package detect

import (
	"strings"
	"testing"
)

func TestRedactSecret(t *testing.T) {
	// Normal token redaction (e.g. AWS access key)
	awsToken := []byte("AKIAIOSFODNN7EXAMPLE")
	redactedAWS := RedactSecret(awsToken, false)
	if redactedAWS != "AKIA...MPLE" {
		t.Errorf("expected AKIA...MPLE, got %s", redactedAWS)
	}
	if strings.Contains(redactedAWS, "IOSFODNN7EXA") {
		t.Errorf("leaked inner secret material in normal token redaction: %s", redactedAWS)
	}

	// GitHub token
	ghToken := []byte("ghp_123456789012345678901234567890123456")
	redactedGH := RedactSecret(ghToken, false)
	if !strings.HasPrefix(redactedGH, "ghp_") || !strings.HasSuffix(redactedGH, "3456") {
		t.Errorf("expected ghp_...3456, got %s", redactedGH)
	}

	// Private Key Header - MUST be strict zero-reveal
	privKey := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----")
	redactedKey := RedactSecret(privKey, true)
	if redactedKey != RedactedPrivateKeyString {
		t.Errorf("expected exact %q, got %s", RedactedPrivateKeyString, redactedKey)
	}

	// Assert zero characters of the original key material are present in the output
	for _, rawLine := range strings.Split(string(privKey), "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if len(trimmed) > 5 && strings.Contains(redactedKey, trimmed) {
			t.Fatalf("CRITICAL SECURITY DEFECT: leaked private key material %q in redacted output %q", trimmed, redactedKey)
		}
	}
}

func TestDetectorBlobScenarios(t *testing.T) {
	// 1. Text blob with line numbers and offsets
	textPayload := []byte("line 1\nline 2\nconst key = 'AKIAIOSFODNN7EXAMPLE';\nline 4\n")
	candidates, isOversize, isBinary := ScanBlob(textPayload)
	if isOversize || isBinary {
		t.Fatalf("expected text blob, got oversize=%v, binary=%v", isOversize, isBinary)
	}
	if len(candidates) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(candidates))
	}
	if candidates[0].LineNumber != 3 {
		t.Errorf("expected line number 3, got %d", candidates[0].LineNumber)
	}
	if candidates[0].ByteOffset != 27 {
		t.Errorf("expected byte offset 27, got %d", candidates[0].ByteOffset)
	}

	// 2. Binary blob containing a strong secret pattern
	binaryPayload := []byte{0x00, 0x01, 0x02, 'A', 'K', 'I', 'A', 'I', 'O', 'S', 'F', 'O', 'D', 'N', 'N', '7', 'E', 'X', 'A', 'M', 'P', 'L', 'E', 0xFF}
	binCandidates, isBinOversize, isBin := ScanBlob(binaryPayload)
	if isBinOversize || !isBin {
		t.Fatalf("expected binary blob detection, got oversize=%v, isBin=%v", isBinOversize, isBin)
	}
	if len(binCandidates) != 1 {
		t.Fatalf("expected strong pattern to be detected even inside binary blob, got %d", len(binCandidates))
	}

	// 3. Oversize blob (>10MB)
	hugePayload := make([]byte, 10*1024*1024+1)
	_, isHugeOversize, _ := ScanBlob(hugePayload)
	if !isHugeOversize {
		t.Errorf("expected oversize flag for >10MB payload")
	}
}
