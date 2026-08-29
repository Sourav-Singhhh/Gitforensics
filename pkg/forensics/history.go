package forensics

import (
	"fmt"
	"gitforensics/pkg/object"
	"gitforensics/pkg/parser"
	"gitforensics/pkg/repository"
	"gitforensics/pkg/traversal"
	"time"
)

// TreeEntryBlob holds the path and OID of a blob discovered in a tree hierarchy.
type TreeEntryBlob struct {
	Path    string
	BlobOID string
}

// HistoryIndex maps blob OIDs to all observed historical occurrences (§11).
type HistoryIndex struct {
	BlobOccurrences map[string][]Occurrence
	CoverageGaps    []CoverageGap
	Anomalies       []traversal.StructuralAnomaly
}

// BuildHistoryIndex walks all reachable commits to associate blob OIDs with file paths and commit metadata (§11).
func BuildHistoryIndex(store repository.ObjectStore, reachableCommits map[string]bool) (*HistoryIndex, error) {
	index := &HistoryIndex{
		BlobOccurrences: make(map[string][]Occurrence),
		CoverageGaps:    make([]CoverageGap, 0),
		Anomalies:       make([]traversal.StructuralAnomaly, 0),
	}

	// Cache to memoize tree expansion: treeOID -> []TreeEntryBlob
	treeCache := make(map[string][]TreeEntryBlob)

	var expandTree func(treeOID string, currentPath string, depth int) ([]TreeEntryBlob, error)
	expandTree = func(treeOID string, currentPath string, depth int) ([]TreeEntryBlob, error) {
		if depth > 1000 {
			index.CoverageGaps = append(index.CoverageGaps, CoverageGap{
				Type:        "treeDepthLimitExceeded",
				Target:      treeOID,
				Description: fmt.Sprintf("tree %s exceeds maximum history traversal depth of 1000", treeOID),
			})
			index.Anomalies = append(index.Anomalies, traversal.StructuralAnomaly{
				Type:        traversal.AnomalyRecursionDepthExceeded,
				Location:    treeOID,
				Description: fmt.Sprintf("tree %s exceeds maximum history traversal depth of 1000", treeOID),
			})
			return nil, object.ErrMaxTreeDepthExceeded
		}

		obj, err := store.Get(treeOID)
		if err != nil {
			return nil, err
		}

		tree, err := parser.ParseTree(obj.Payload)
		if err != nil {
			return nil, err
		}

		var entries []TreeEntryBlob
		for _, entry := range tree.Entries {
			entryName := string(entry.Name)
			entryPath := entryName
			if currentPath != "" {
				entryPath = currentPath + "/" + entryName
			}

			switch entry.Mode {
			case parser.ModeTree:
				subEntries, subErr := expandTree(entry.OIDHex, entryPath, depth+1)
				if subErr == nil {
					entries = append(entries, subEntries...)
				}
			case parser.ModeRegular, parser.ModeExecutable, parser.ModeSymlink:
				entries = append(entries, TreeEntryBlob{
					Path:    entryPath,
					BlobOID: entry.OIDHex,
				})
			}
		}

		return entries, nil
	}

	for commitOID := range reachableCommits {
		obj, err := store.Get(commitOID)
		if err != nil {
			continue
		}

		commit, err := parser.ParseCommit(obj.Payload)
		if err != nil {
			continue
		}

		if commit.TreeSHA == "" {
			continue
		}

		treeEntries, cached := treeCache[commit.TreeSHA]
		if !cached {
			expanded, expErr := expandTree(commit.TreeSHA, "", 0)
			if expErr == nil {
				treeEntries = expanded
				treeCache[commit.TreeSHA] = expanded
			}
		}

		authorStr := fmt.Sprintf("%s <%s>", commit.Author.Name, commit.Author.Email)

		dateStr := ""
		if commit.Author.Timestamp != 0 {
			t := time.Unix(commit.Author.Timestamp, 0).UTC()
			dateStr = t.Format(time.RFC3339)
		}

		for _, te := range treeEntries {
			occ := Occurrence{
				CommitSHA:  commitOID,
				CommitDate: commit.Author.Timestamp,
				DateString: dateStr,
				Author:     authorStr,
				Path:       te.Path,
			}
			index.BlobOccurrences[te.BlobOID] = append(index.BlobOccurrences[te.BlobOID], occ)
		}
	}

	// Sort occurrences deterministically for each blob
	for blobOID := range index.BlobOccurrences {
		SortOccurrences(index.BlobOccurrences[blobOID])
	}

	return index, nil
}

// BuildTimeline generates the lifecycle timeline for a finding (§12).
// Invariant: Uses cautious wording ("earliest observed", "evidence indicates removal").
// Returns nil if no occurrence metadata is available.
func BuildTimeline(occurrences []Occurrence, isHeadReachable bool) *Timeline {
	if len(occurrences) == 0 {
		return nil
	}

	earliest := occurrences[0]
	timeline := &Timeline{
		EarliestObservedCommit: earliest.CommitSHA,
		EarliestObservedDate:   earliest.DateString,
		EarliestObservedAuthor: earliest.Author,
	}

	if isHeadReachable {
		timeline.EvidenceNote = "Secret remains active and reachable from current HEAD."
	} else {
		latest := occurrences[len(occurrences)-1]
		timeline.RemovalObservedCommit = latest.CommitSHA
		timeline.RemovalObservedDate = latest.DateString
		timeline.EvidenceNote = "Evidence indicates secret is no longer present in current HEAD; historical commit reference preserved."
	}

	return timeline
}
