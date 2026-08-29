package forensics

import (
	"fmt"
	"gitforensics/pkg/detect"
	"gitforensics/pkg/traversal"
	"strings"
)

// ExplainResult encapsulates the complete explanation for a specific finding (§15).
type ExplainResult struct {
	Finding             Finding `json:"finding"`
	RecoveryExplanation string  `json:"recoveryExplanation"`
	RepositoryPath      string  `json:"repositoryPath"`
}

// ExplainFinding re-runs the deterministic scan and resolves a finding by its 16-hex ID or 64-hex digest (§15).
// Invariant: Stateless execution; accepts both 16-character and 64-character finding IDs.
func ExplainFinding(repoPath string, findingID string) (*ExplainResult, error) {
	cleanID := strings.ToLower(strings.TrimSpace(findingID))
	if len(cleanID) != 16 && len(cleanID) != 64 {
		return nil, fmt.Errorf("invalid finding ID length (%d characters); expected 16 or 64 hex characters", len(cleanID))
	}

	opts := ScanOptions{
		RepoPath:      repoPath,
		MinConfidence: detect.TierLow, // explain should find findings regardless of confidence filter
	}

	report, err := RunScan(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to scan repository: %w", err)
	}

	var matchedFinding *Finding
	for _, f := range report.AllFindings {
		if strings.ToLower(f.ID) == cleanID || strings.ToLower(f.FullDigest) == cleanID {
			fCopy := f
			matchedFinding = &fCopy
			break
		}
	}

	if matchedFinding == nil {
		return nil, fmt.Errorf("finding %q was not found in current repository state", findingID)
	}

	var recoveryExplanation string
	switch matchedFinding.Exposure {
	case traversal.StateActive:
		recoveryExplanation = "ACTIVE EXPOSURE: The secret exists in the current worktree HEAD. It is directly checked out on the working tree and visible in HEAD commit history."
	case traversal.StateHistorical:
		recoveryExplanation = "HISTORICAL EXPOSURE: The secret is no longer present in current HEAD, but is reachable through other Git branches, tags, or refs. Anyone cloning or fetching refs can extract this secret."
	case traversal.StateZombie:
		recoveryExplanation = "ZOMBIE (DANGLING) EXPOSURE: The secret is an unreferenced orphan object physically persisting on disk in loose or pack storage. It is invisible to standard 'git log' or branch checkouts, but remains fully recoverable by direct object inspection until Git garbage collection ('git gc --prune=now') deletes or repacks the object."
	case traversal.StateUnresolved:
		recoveryExplanation = "UNRESOLVED STORAGE: The secret is referenced in the Git DAG but its payload could not be extracted from storage."
	default:
		recoveryExplanation = "Unknown exposure state."
	}

	return &ExplainResult{
		Finding:             *matchedFinding,
		RecoveryExplanation: recoveryExplanation,
		RepositoryPath:      report.Repository.Path,
	}, nil
}
