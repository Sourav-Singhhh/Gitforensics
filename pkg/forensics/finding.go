package forensics

import (
	"crypto/sha256"
	"encoding/hex"
	"gitforensics/pkg/detect"
	"gitforensics/pkg/traversal"
	"sort"
	"strconv"
)

// Occurrence represents a point in Git commit history where a blob was referenced (§11).
type Occurrence struct {
	CommitSHA  string `json:"commitSha"`
	CommitDate int64  `json:"commitTimestamp"`
	DateString string `json:"commitDate"`
	Author     string `json:"author"`
	Path       string `json:"path"`
}

// Timeline summarizes the chronological lifecycle of a secret across repository history (§12).
type Timeline struct {
	EarliestObservedCommit string `json:"earliestObservedCommit"`
	EarliestObservedDate   string `json:"earliestObservedDate"`
	EarliestObservedAuthor string `json:"earliestObservedAuthor"`
	RemovalObservedCommit  string `json:"removalObservedCommit,omitempty"`
	RemovalObservedDate    string `json:"removalObservedDate,omitempty"`
	EvidenceNote           string `json:"evidenceNote"`
}

// EvidenceSignal captures an individual scoring signal contributing to confidence (§10).
type EvidenceSignal struct {
	Rule   string `json:"rule"`
	Score  int    `json:"score"`
	Detail string `json:"detail"`
}

// Finding represents an individual forensic secret finding (§11, §14).
type Finding struct {
	ID              string                  `json:"id"`
	FullDigest      string                  `json:"fullDigest"`
	BlobID          string                  `json:"blobId"`
	Fingerprint     string                  `json:"fingerprint"`
	Exposure        traversal.ExposureState `json:"exposureState"`
	PatternName     string                  `json:"patternName"`
	Category        string                  `json:"category"`
	ConfidenceScore int                     `json:"confidenceScore"`
	ConfidenceTier  detect.ConfidenceTier   `json:"confidenceTier"`
	Redacted        string                  `json:"redacted"`
	LineNumber      int                     `json:"lineNumber"`
	ByteOffset      int                     `json:"byteOffset"`
	IsBinary        bool                    `json:"isBinary"`
	Occurrences     []Occurrence            `json:"occurrences"`
	Timeline        *Timeline               `json:"timeline"`
	EvidenceSignals []EvidenceSignal        `json:"evidenceSignals"`
}

// ComputeFindingID computes the deterministic 16-hex finding ID and full 64-hex digest (§11).
//
// Formula:
//
//	digest = SHA256(blobID || 0x00 || byteOffset || 0x00 || patternName)
//	id     = first16hex(digest)
func ComputeFindingID(blobID string, byteOffset int, patternName string) (string, string) {
	h := sha256.New()
	h.Write([]byte(blobID))
	h.Write([]byte{0x00})
	h.Write([]byte(strconv.Itoa(byteOffset)))
	h.Write([]byte{0x00})
	h.Write([]byte(patternName))

	sum := h.Sum(nil)
	fullDigest := hex.EncodeToString(sum)
	id16 := fullDigest[:16]

	return id16, fullDigest
}

// ComputeFingerprint computes the SHA-256 digest of the raw matched secret bytes (§11).
// Invariant: Distinct from the Git object ID.
func ComputeFingerprint(candidateBytes []byte) string {
	sum := sha256.Sum256(candidateBytes)
	return hex.EncodeToString(sum[:])
}

// SortOccurrences sorts a slice of occurrences deterministically:
// commit date ascending, then path ascending (§17).
func SortOccurrences(occurrences []Occurrence) {
	sort.Slice(occurrences, func(i, j int) bool {
		if occurrences[i].CommitDate != occurrences[j].CommitDate {
			return occurrences[i].CommitDate < occurrences[j].CommitDate
		}
		if occurrences[i].CommitSHA != occurrences[j].CommitSHA {
			return occurrences[i].CommitSHA < occurrences[j].CommitSHA
		}
		return occurrences[i].Path < occurrences[j].Path
	})
}

// SortFindings sorts findings deterministically (§17):
// confidence tier descending (Critical > High > Medium > Low), then ID ascending.
func SortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		rankI := detect.TierRank(findings[i].ConfidenceTier)
		rankJ := detect.TierRank(findings[j].ConfidenceTier)
		if rankI != rankJ {
			return rankI > rankJ
		}
		if findings[i].ConfidenceScore != findings[j].ConfidenceScore {
			return findings[i].ConfidenceScore > findings[j].ConfidenceScore
		}
		return findings[i].ID < findings[j].ID
	})
}
