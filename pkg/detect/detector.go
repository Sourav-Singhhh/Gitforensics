package detect

import (
	"bytes"
)

const (
	// MaxScanBlobSize defines the oversize blob ceiling (10 MB) (§10, §19).
	MaxScanBlobSize = 10 * 1024 * 1024

	// BinaryInspectionLength is the byte window to check for NUL bytes (8 KB).
	BinaryInspectionLength = 8192
)

// CandidateFinding represents a detected secret candidate before finding aggregation.
type CandidateFinding struct {
	PatternName     string
	Category        string
	ByteOffset      int
	LineNumber      int
	CandidateBytes  []byte
	BaseScore       int
	EntropyScore    int
	EntropyValue    float64
	ContextScore    int
	ContextKeywords []string
	IsPrivateKey    bool
	IsBinary        bool
}

// IsBinaryBlob evaluates whether a payload represents binary data by scanning the first 8KB for NUL bytes (§10).
func IsBinaryBlob(payload []byte) bool {
	inspectLen := len(payload)
	if inspectLen > BinaryInspectionLength {
		inspectLen = BinaryInspectionLength
	}
	return bytes.IndexByte(payload[:inspectLen], 0x00) != -1
}

// computeLineNumber computes the 1-indexed line number for a given byte offset within payload.
func computeLineNumber(payload []byte, offset int) int {
	if offset < 0 || offset > len(payload) {
		return 1
	}
	line := 1
	for i := 0; i < offset; i++ {
		if payload[i] == '\n' {
			line++
		}
	}
	return line
}

// ScanBlob scans a raw blob payload for strong secret patterns (§10).
//
// Invariants enforced:
// 1. Oversize check (>10MB): returns isOversize=true so caller can record a skippedOversizeBlob coverage gap.
// 2. Binary heuristic: binary blobs skip line-oriented candidate extraction but STILL execute strong raw-byte pattern scanning.
// 3. Text blobs: accurately track 1-indexed line numbers and byte offsets.
// 4. Multiple patterns on same candidate offset: maximum applicable strong pattern is used.
func ScanBlob(payload []byte) (candidates []CandidateFinding, isOversize bool, isBinary bool) {
	if len(payload) > MaxScanBlobSize {
		return nil, true, false
	}

	isBinary = IsBinaryBlob(payload)

	for _, patternDef := range StrongPatterns {
		locs := patternDef.Regex.FindAllIndex(payload, -1)
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			matchBytes := payload[start:end]

			line := 1
			if !isBinary {
				line = computeLineNumber(payload, start)
			}

			// Entropy evaluation
			entropyVal := CalculateShannonEntropy(matchBytes)
			entropyScore := EntropyContribution(entropyVal)

			// Context window evaluation (±100 bytes)
			contextScore, contextKeywords := EvaluateContext(payload, start, end)

			candidates = append(candidates, CandidateFinding{
				PatternName:     patternDef.Name,
				Category:        patternDef.Category,
				ByteOffset:      start,
				LineNumber:      line,
				CandidateBytes:  append([]byte(nil), matchBytes...),
				BaseScore:       patternDef.BaseConfidence,
				EntropyScore:    entropyScore,
				EntropyValue:    entropyVal,
				ContextScore:    contextScore,
				ContextKeywords: contextKeywords,
				IsPrivateKey:    patternDef.IsPrivateKey,
				IsBinary:        isBinary,
			})
		}
	}

	return candidates, false, isBinary
}
