package detect

import (
	"bytes"
	"regexp"
)

// ContextKeywords list the recognized sensitive variable / context keywords (§10).
var contextKeywordsRegex = regexp.MustCompile(`(?i)(?:^|[^a-zA-Z0-9])(api_key|secret|token|password|authorization|private_key)(?:$|[^a-zA-Z0-9])`)

const (
	// ContextWindowRadius defines the byte radius around the candidate to inspect (±100 bytes).
	ContextWindowRadius = 100

	// ContextScoreContribution is the score bonus granted if any keyword is present (+20).
	ContextScoreContribution = 20
)

// EvaluateContext inspects the ±100 byte local window around [start, end] within the payload.
// Returns ContextScoreContribution (+20) if one or more keywords are found; otherwise 0.
// Invariant (§10): Context contribution is granted at most ONCE per candidate; multiple keywords do NOT stack.
func EvaluateContext(payload []byte, start, end int) (int, []string) {
	if len(payload) == 0 || start < 0 || end > len(payload) || start > end {
		return 0, nil
	}

	windowStart := start - ContextWindowRadius
	if windowStart < 0 {
		windowStart = 0
	}

	windowEnd := end + ContextWindowRadius
	if windowEnd > len(payload) {
		windowEnd = len(payload)
	}

	windowBytes := payload[windowStart:windowEnd]
	matches := contextKeywordsRegex.FindAllSubmatch(windowBytes, -1)
	if len(matches) == 0 {
		return 0, nil
	}

	seen := make(map[string]bool)
	var keywordsFound []string
	for _, m := range matches {
		if len(m) > 1 {
			lower := string(bytes.ToLower(m[1]))
			if !seen[lower] {
				seen[lower] = true
				keywordsFound = append(keywordsFound, lower)
			}
		}
	}

	return ContextScoreContribution, keywordsFound
}
