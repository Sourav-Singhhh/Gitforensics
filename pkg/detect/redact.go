package detect

import (
	"bytes"
)

const (
	// RedactedPrivateKeyString is the strict zero-reveal redaction format for private keys (§11).
	RedactedPrivateKeyString = "[REDACTED PRIVATE KEY]"
)

// RedactSecret centralizes secret redaction across the entire application (§11).
// Invariant 1: Private keys / PEM blocks always return exactly "[REDACTED PRIVATE KEY]" with zero characters revealed.
// Invariant 2: Normal tokens preserve up to 4 characters of prefix and 4 characters of suffix with middle replaced by "...".
// Invariant 3: Short tokens (<= 8 characters) are masked entirely to prevent secret leakage.
func RedactSecret(match []byte, isPrivateKey bool) string {
	if isPrivateKey || bytes.Contains(match, []byte("PRIVATE KEY")) {
		return RedactedPrivateKeyString
	}

	str := string(match)
	length := len(str)
	if length <= 8 {
		return "..."
	}

	prefixLen := 4
	suffixLen := 4

	prefix := str[:prefixLen]
	suffix := str[length-suffixLen:]

	return prefix + "..." + suffix
}
