package detect

import (
	"path/filepath"
	"strings"
)

const (
	// PathSensitiveBonus is the score bonus for sensitive filenames (+10).
	PathSensitiveBonus = 10

	// PathTestPenalty is the score penalty for test/example/fixture paths (-30).
	PathTestPenalty = -30
)

// Known sensitive base filenames and patterns (§10).
var sensitiveFilenames = map[string]bool{
	".env":             true,
	".env.local":       true,
	".env.production":  true,
	".env.development": true,
	"credentials":      true,
	"credentials.json": true,
	"id_rsa":           true,
	"id_dsa":           true,
	"id_ecdsa":         true,
	"id_ed25519":       true,
	"secrets.json":     true,
	"secrets.yaml":     true,
	"secrets.yml":      true,
	"id_rsa.pub":       false, // public key is not private secret
}

// Test / example path directory names (§10).
var testDirectoryComponents = map[string]bool{
	"test":     true,
	"tests":    true,
	"testdata": true,
	"fixture":  true,
	"fixtures": true,
	"example":  true,
	"examples": true,
	"spec":     true,
	"specs":    true,
	"mock":     true,
	"mocks":    true,
}

// EvaluatePath calculates the path bonus (+10) or penalty (-30) for a given relative path (§10).
// Invariant: Matches full path components, not loose substrings (e.g. "contest" does not trigger "test").
func EvaluatePath(path string) (int, bool, bool) {
	if path == "" {
		return 0, false, false
	}

	cleanPath := filepath.ToSlash(path)
	parts := strings.Split(cleanPath, "/")

	isTest := false
	for _, part := range parts {
		lowerPart := strings.ToLower(part)
		if testDirectoryComponents[lowerPart] {
			isTest = true
			break
		}
		// Also check if filename has test/spec prefix/suffix e.g. foo_test.go
		if strings.HasSuffix(lowerPart, "_test.go") || strings.HasSuffix(lowerPart, ".test.js") || strings.HasSuffix(lowerPart, ".spec.ts") {
			isTest = true
			break
		}
	}

	baseName := strings.ToLower(filepath.Base(cleanPath))
	isSensitive := sensitiveFilenames[baseName]
	if !isSensitive {
		// Check for .env.* patterns or key files
		if strings.HasPrefix(baseName, ".env.") || strings.HasSuffix(baseName, ".pem") || strings.HasSuffix(baseName, ".key") {
			isSensitive = true
		}
	}

	score := 0
	if isSensitive {
		score += PathSensitiveBonus
	}
	if isTest {
		score += PathTestPenalty
	}

	return score, isSensitive, isTest
}
