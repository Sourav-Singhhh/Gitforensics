package forensics

import (
	"fmt"
	"gitforensics/pkg/detect"
	"gitforensics/pkg/repository"
	"gitforensics/pkg/traversal"
	"sort"
	"time"
)

// CoverageGap represents an uninspected area of storage (§14).
type CoverageGap struct {
	Type        string `json:"type"`
	Target      string `json:"target"`
	Description string `json:"description"`
}

const (
	CoverageGapUnresolvedPackOnly = "unresolvedPackOnly"
	CoverageGapSkippedOversize    = "skippedOversizeBlob"
)

// ScanSummary records aggregate counts and execution metadata (§14).
type ScanSummary struct {
	TotalBlobsScanned     int `json:"totalBlobsScanned"`
	ActiveBlobsCount      int `json:"activeBlobsCount"`
	HistoricalBlobsCount  int `json:"historicalBlobsCount"`
	ZombieBlobsCount      int `json:"zombieBlobsCount"`
	TotalFindingsCount    int `json:"totalFindingsCount"`
	DisplayedFindingCount int `json:"displayedFindingsCount"`
	CriticalFindingsCount int `json:"criticalFindingsCount"`
	HighFindingsCount     int `json:"highFindingsCount"`
	MediumFindingsCount   int `json:"mediumFindingsCount"`
	LowFindingsCount      int `json:"lowFindingsCount"`
}

// ScanReport is the top-level structured outcome of a forensic analysis (§14).
type ScanReport struct {
	SchemaVersion       string                        `json:"schemaVersion"`
	Tool                ToolMetadata                  `json:"tool"`
	Repository          RepositoryMetadata            `json:"repository"`
	Scan                ScanMetadata                  `json:"scan"`
	Summary             ScanSummary                   `json:"summary"`
	Findings            []Finding                     `json:"findings"`
	AllFindings         []Finding                     `json:"-"` // complete undisplayed findings for accurate exit code calculation
	CoverageGaps        []CoverageGap                 `json:"coverageGaps"`
	StructuralAnomalies []traversal.StructuralAnomaly `json:"structuralAnomalies"`
	FatalError          *string                       `json:"fatalError"`
}

// ToolMetadata identifies the binary and version (§14).
type ToolMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RepositoryMetadata describes the analyzed repository (§14).
type RepositoryMetadata struct {
	Path         string `json:"path"`
	GitDir       string `json:"gitDir"`
	CommonDir    string `json:"commonDir"`
	IsBare       bool   `json:"isBare"`
	HeadResolved string `json:"headResolved,omitempty"`
}

// ScanMetadata records runtime parameters (§14).
type ScanMetadata struct {
	StartTime     string                `json:"startTime"`
	DurationMs    int64                 `json:"durationMs"`
	MinConfidence detect.ConfidenceTier `json:"minConfidence"`
}

const (
	ToolVersion   = "0.1.0-dev"
	SchemaVersion = "1.0"
)

// ScanOptions configures a forensic repository scan (§13).
type ScanOptions struct {
	RepoPath      string
	MinConfidence detect.ConfidenceTier
	Limits        traversal.TraversalLimits
}

// RunScan executes the full Phase 4 forensic scanning pipeline.
//
// Invariants enforced:
// 1. Exposure state is read-only input from Phase 3 classification.
// 2. Unresolved pack-only objects are never scanned and recorded as coverage gaps.
// 3. Raw secrets are NEVER placed in report findings; all findings are redacted.
// 4. Same blob ID + candidate = 1 finding; same secret in different blobs = separate findings.
// 5. Total vs displayed finding count separation: MinConfidence filters displayed findings only.
// 6. Output findings and occurrences are sorted deterministically.
func RunScan(opts ScanOptions) (*ScanReport, error) {
	startTime := time.Now().UTC()

	if opts.MinConfidence == "" {
		opts.MinConfidence = detect.TierLow
	}
	if opts.Limits.MaxTreeDepth <= 0 {
		opts.Limits = traversal.DefaultTraversalLimits()
	}

	repo, err := repository.Discover(opts.RepoPath)
	if err != nil {
		return nil, fmt.Errorf("repository discovery failed: %w", err)
	}

	store, _, packGaps, storeErr := repository.NewRepositoryStore(repo.GitDir, repo.CommonDir, 0)
	if storeErr != nil {
		return nil, fmt.Errorf("storage initialization failed: %w", storeErr)
	}

	// Phase 3 & 5 Classification pipeline
	classification, err := traversal.ClassifyRepository(repo, store, opts.Limits)
	if err != nil {
		return nil, fmt.Errorf("graph classification failed: %w", err)
	}

	// Discover all reachable commits for history mapping
	allRefsMap, _, _ := repository.AllRefs(repo)
	rootSet := make([]string, 0, len(allRefsMap)+1)
	headOID, isUnborn, _ := repository.ResolveHEAD(repo)
	if headOID != "" && !isUnborn {
		rootSet = append(rootSet, headOID)
	}
	for _, oid := range allRefsMap {
		rootSet = append(rootSet, oid)
	}
	reachableResult, _ := traversal.TraverseReachable(store, rootSet, opts.Limits)
	reachableCommits := make(map[string]bool)
	if reachableResult != nil {
		reachableCommits = reachableResult.Commits
	}

	// Build history path index
	historyIndex, _ := BuildHistoryIndex(store, reachableCommits)

	var coverageGaps []CoverageGap
	if coverageGaps == nil {
		coverageGaps = make([]CoverageGap, 0)
	}
	if historyIndex != nil {
		coverageGaps = append(coverageGaps, historyIndex.CoverageGaps...)
		if classification != nil {
			classification.Anomalies = append(classification.Anomalies, historyIndex.Anomalies...)
		}
	}

	// Unresolved missing/pack-only objects become coverage gaps (§14)
	for _, uOID := range classification.UnresolvedOIDs {
		coverageGaps = append(coverageGaps, CoverageGap{
			Type:        CoverageGapUnresolvedPackOnly,
			Target:      uOID,
			Description: fmt.Sprintf("referenced object %s could not be resolved from storage", uOID),
		})
	}

	// Pack-level coverage gaps (e.g. unsupported REF_DELTA)
	for _, gap := range packGaps {
		coverageGaps = append(coverageGaps, CoverageGap{
			Type:        gap.Type,
			Target:      gap.Location,
			Description: gap.Description,
		})
	}

	// Deduplication map: findingKey -> *Finding
	dedupMap := make(map[string]*Finding)

	// Helper to process a set of blobs under a specific exposure state
	processBlobSet := func(blobOIDs []string, state traversal.ExposureState) {
		for _, blobOID := range blobOIDs {
			obj, getErr := store.Get(blobOID)
			if getErr != nil {
				continue
			}

			candidates, isOversize, isBinary := detect.ScanBlob(obj.Payload)
			if isOversize {
				coverageGaps = append(coverageGaps, CoverageGap{
					Type:        CoverageGapSkippedOversize,
					Target:      blobOID,
					Description: fmt.Sprintf("blob %s size %d exceeds 10MB limit and was skipped", blobOID, len(obj.Payload)),
				})
				continue
			}

			occurrences := historyIndex.BlobOccurrences[blobOID]

			// Path evaluation across occurrences
			pathScore := 0
			bestPathScore := 0
			hasSensitivePath := false
			allTestPaths := len(occurrences) > 0

			for _, occ := range occurrences {
				pScore, isSens, isTest := detect.EvaluatePath(occ.Path)
				if isSens {
					hasSensitivePath = true
				}
				if !isTest {
					allTestPaths = false
				}
				if pScore > bestPathScore {
					bestPathScore = pScore
				}
			}

			if hasSensitivePath {
				pathScore = detect.PathSensitiveBonus
			} else if allTestPaths {
				pathScore = detect.PathTestPenalty
			}

			for _, cand := range candidates {
				confScore, confTier := detect.ConfidenceScore(cand.BaseScore, cand.EntropyScore, cand.ContextScore, pathScore)
				findingID, fullDigest := ComputeFindingID(blobOID, cand.ByteOffset, cand.PatternName)
				fingerprint := ComputeFingerprint(cand.CandidateBytes)
				redacted := detect.RedactSecret(cand.CandidateBytes, cand.IsPrivateKey)

				var evidence []EvidenceSignal
				evidence = append(evidence, EvidenceSignal{
					Rule:   "Strong Pattern Match",
					Score:  cand.BaseScore,
					Detail: fmt.Sprintf("Matched %s (%s)", cand.PatternName, cand.Category),
				})
				if cand.EntropyScore > 0 {
					evidence = append(evidence, EvidenceSignal{
						Rule:   "Shannon Entropy Analysis",
						Score:  cand.EntropyScore,
						Detail: fmt.Sprintf("Entropy: %.2f bits/byte", cand.EntropyValue),
					})
				}
				if cand.ContextScore > 0 {
					evidence = append(evidence, EvidenceSignal{
						Rule:   "Context Keywords",
						Score:  cand.ContextScore,
						Detail: fmt.Sprintf("Nearby keywords: %v", cand.ContextKeywords),
					})
				}
				if pathScore != 0 {
					evidence = append(evidence, EvidenceSignal{
						Rule:   "Path Sensitivity",
						Score:  pathScore,
						Detail: fmt.Sprintf("Path signal score: %+d", pathScore),
					})
				}

				timeline := BuildTimeline(occurrences, state == traversal.StateActive)

				findingKey := fmt.Sprintf("%s:%d:%s", blobOID, cand.ByteOffset, cand.PatternName)
				if existing, exists := dedupMap[findingKey]; exists {
					// Aggregated occurrence
					existing.Occurrences = append(existing.Occurrences, occurrences...)
					SortOccurrences(existing.Occurrences)
				} else {
					dedupMap[findingKey] = &Finding{
						ID:              findingID,
						FullDigest:      fullDigest,
						BlobID:          blobOID,
						Fingerprint:     fingerprint,
						Exposure:        state,
						PatternName:     cand.PatternName,
						Category:        cand.Category,
						ConfidenceScore: confScore,
						ConfidenceTier:  confTier,
						Redacted:        redacted,
						LineNumber:      cand.LineNumber,
						ByteOffset:      cand.ByteOffset,
						IsBinary:        isBinary,
						Occurrences:     occurrences,
						Timeline:        timeline,
						EvidenceSignals: evidence,
					}
				}
			}
		}
	}

	// 1. Process ACTIVE blobs
	processBlobSet(classification.ActiveBlobs, traversal.StateActive)
	// 2. Process HISTORICAL blobs
	processBlobSet(classification.HistoricalBlobs, traversal.StateHistorical)
	// 3. Process ZOMBIE blobs
	processBlobSet(classification.ZombieBlobs, traversal.StateZombie)

	// Collect and sort all findings
	var allFindings []Finding
	for _, f := range dedupMap {
		allFindings = append(allFindings, *f)
	}
	SortFindings(allFindings)

	// Filter displayed findings based on MinConfidence
	minRank := detect.TierRank(opts.MinConfidence)
	var displayedFindings []Finding
	if displayedFindings == nil {
		displayedFindings = make([]Finding, 0)
	}

	summary := ScanSummary{
		TotalBlobsScanned:    len(classification.ActiveBlobs) + len(classification.HistoricalBlobs) + len(classification.ZombieBlobs),
		ActiveBlobsCount:     len(classification.ActiveBlobs),
		HistoricalBlobsCount: len(classification.HistoricalBlobs),
		ZombieBlobsCount:     len(classification.ZombieBlobs),
		TotalFindingsCount:   len(allFindings),
	}

	for _, f := range allFindings {
		switch f.ConfidenceTier {
		case detect.TierCritical:
			summary.CriticalFindingsCount++
		case detect.TierHigh:
			summary.HighFindingsCount++
		case detect.TierMedium:
			summary.MediumFindingsCount++
		case detect.TierLow:
			summary.LowFindingsCount++
		}

		if detect.TierRank(f.ConfidenceTier) >= minRank {
			displayedFindings = append(displayedFindings, f)
		}
	}
	summary.DisplayedFindingCount = len(displayedFindings)

	// Sort coverage gaps deterministically by target OID (§17)
	sort.Slice(coverageGaps, func(i, j int) bool {
		return coverageGaps[i].Target < coverageGaps[j].Target
	})

	anomalies := classification.Anomalies
	if anomalies == nil {
		anomalies = make([]traversal.StructuralAnomaly, 0)
	}

	duration := time.Since(startTime).Milliseconds()

	return &ScanReport{
		SchemaVersion: SchemaVersion,
		Tool: ToolMetadata{
			Name:    "gitforensics",
			Version: ToolVersion,
		},
		Repository: RepositoryMetadata{
			Path:         repo.WorktreeRoot,
			GitDir:       repo.GitDir,
			CommonDir:    repo.CommonDir,
			IsBare:       repo.IsBare,
			HeadResolved: headOID,
		},
		Scan: ScanMetadata{
			StartTime:     startTime.Format(time.RFC3339),
			DurationMs:    duration,
			MinConfidence: opts.MinConfidence,
		},
		Summary:             summary,
		Findings:            displayedFindings,
		AllFindings:         allFindings,
		CoverageGaps:        coverageGaps,
		StructuralAnomalies: anomalies,
		FatalError:          nil,
	}, nil
}
