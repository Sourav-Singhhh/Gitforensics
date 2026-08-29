package traversal

import (
	"fmt"
	"gitforensics/pkg/object"
	"gitforensics/pkg/parser"
	"gitforensics/pkg/repository"
	"sort"
)

// TraversalLimits defines safety constants and circuit breakers for graph traversal (§8, §19).
type TraversalLimits struct {
	// MaxTreeDepth is the maximum allowable tree recursion depth before halting (default 1000).
	MaxTreeDepth int

	// MaxPeelDepth is the maximum allowable tag peel depth (default 10).
	MaxPeelDepth int

	// MaxTotalObjects is the maximum number of objects visited per scan (default 500,000).
	MaxTotalObjects int
}

// DefaultTraversalLimits returns standard production safety limits.
func DefaultTraversalLimits() TraversalLimits {
	return TraversalLimits{
		MaxTreeDepth:    1000,
		MaxPeelDepth:    10,
		MaxTotalObjects: 500000,
	}
}

// ReachableResult represents the sets of reachable objects discovered across the Git graph (§8).
type ReachableResult struct {
	Commits   map[string]bool
	Trees     map[string]bool
	Blobs     map[string]bool
	Gitlinks  map[string]string // submodule entry name -> target commit OID
	Anomalies []StructuralAnomaly
}

// TraverseReachable traverses the Git object graph starting from the provided root OIDs (§8).
//
// Invariants enforced:
// 1. Three independent visited sets: visitedCommits, visitedTrees, visitedBlobs.
// 2. Traversal order: Roots are sorted; commit parents and tree entries are visited in stored order.
// 3. Gitlinks (mode 160000): Boundary recorded; zero submodule recursion or filesystem/network access.
// 4. Unsafe tree names: Anomaly recorded, but referenced OID is fully traversed.
// 5. Unknown tree modes: Anomaly recorded; blobs marked reachable; tree recursion inhibited on type mismatch.
// 6. Malformed objects: Branch-local failure; anomaly recorded; unrelated branches continue.
// 7. Tree recursion limit: Halted at MaxTreeDepth with AnomalyRecursionDepthExceeded.
func TraverseReachable(store repository.ObjectStore, rootOIDs []string, limits TraversalLimits) (*ReachableResult, error) {
	if limits.MaxTreeDepth <= 0 {
		limits.MaxTreeDepth = 1000
	}
	if limits.MaxPeelDepth <= 0 {
		limits.MaxPeelDepth = 10
	}
	if limits.MaxTotalObjects <= 0 {
		limits.MaxTotalObjects = 500000
	}

	result := &ReachableResult{
		Commits:   make(map[string]bool),
		Trees:     make(map[string]bool),
		Blobs:     make(map[string]bool),
		Gitlinks:  make(map[string]string),
		Anomalies: make([]StructuralAnomaly, 0),
	}

	// Sort root OIDs for deterministic traversal ordering
	sortedRoots := append([]string(nil), rootOIDs...)
	sort.Strings(sortedRoots)

	totalVisited := 0

	var traverseTree func(treeOID string, depth int)
	var traverseCommit func(commitOID string)

	traverseTree = func(treeOID string, depth int) {
		if result.Trees[treeOID] {
			return
		}
		if totalVisited >= limits.MaxTotalObjects {
			result.Anomalies = append(result.Anomalies, StructuralAnomaly{
				Type:        AnomalyRecursionDepthExceeded,
				Location:    treeOID,
				Description: "total object traversal safety ceiling reached",
			})
			return
		}

		if depth > limits.MaxTreeDepth {
			result.Anomalies = append(result.Anomalies, StructuralAnomaly{
				Type:        AnomalyRecursionDepthExceeded,
				Location:    treeOID,
				Description: fmt.Sprintf("tree recursion depth %d exceeds ceiling %d", depth, limits.MaxTreeDepth),
			})
			return
		}

		result.Trees[treeOID] = true
		totalVisited++

		obj, err := store.Get(treeOID)
		if err != nil {
			result.Anomalies = append(result.Anomalies, StructuralAnomaly{
				Type:        AnomalyMissingReferencedObject,
				Location:    treeOID,
				Description: fmt.Sprintf("missing tree object: %v", err),
			})
			return
		}

		if obj.IntegrityMismatch {
			result.Anomalies = append(result.Anomalies, StructuralAnomaly{
				Type:        AnomalyLooseIntegrityMismatch,
				Location:    treeOID,
				Description: fmt.Sprintf("loose object hash mismatch (expected %s, computed %s)", obj.ID, obj.ComputedID),
			})
		}

		tree, parseErr := parser.ParseTree(obj.Payload)
		if parseErr != nil {
			result.Anomalies = append(result.Anomalies, StructuralAnomaly{
				Type:        AnomalyMalformedTree,
				Location:    treeOID,
				Description: fmt.Sprintf("malformed tree payload: %v", parseErr),
			})
			return
		}

		// Traverse tree entries in stored order
		for _, entry := range tree.Entries {
			// Check unsafe entry name (inhibit path construction, but traverse OID)
			if entry.SafetyFlag != parser.NameSafetyClean {
				result.Anomalies = append(result.Anomalies, StructuralAnomaly{
					Type:        AnomalyUnsafeTreeName,
					Location:    fmt.Sprintf("%s:%s", treeOID, string(entry.Name)),
					Description: fmt.Sprintf("unsafe entry name flag=%d", entry.SafetyFlag),
				})
			}

			// Unknown numeric mode handling (§6, §8)
			if entry.UnknownMode {
				result.Anomalies = append(result.Anomalies, StructuralAnomaly{
					Type:        AnomalyUnknownTreeMode,
					Location:    fmt.Sprintf("%s:%s", treeOID, string(entry.Name)),
					Description: fmt.Sprintf("unknown octal mode: %s", entry.Mode),
				})

				targetObj, err := store.Get(entry.OIDHex)
				if err != nil {
					result.Anomalies = append(result.Anomalies, StructuralAnomaly{
						Type:        AnomalyMissingReferencedObject,
						Location:    entry.OIDHex,
						Description: fmt.Sprintf("missing object for unknown mode entry: %v", err),
					})
					continue
				}

				if targetObj.Type == object.TypeBlob {
					result.Blobs[entry.OIDHex] = true
					totalVisited++
				} else if targetObj.Type == object.TypeTree {
					// Non-40000 mode referencing tree: record type mismatch and do NOT recurse
					result.Anomalies = append(result.Anomalies, StructuralAnomaly{
						Type:        AnomalyTreeTypeMismatch,
						Location:    entry.OIDHex,
						Description: fmt.Sprintf("tree object under non-40000 mode %s; subtree recursion inhibited", entry.Mode),
					})
					result.Trees[entry.OIDHex] = true
				}
				continue
			}

			// Standard Git modes
			switch entry.Mode {
			case parser.ModeTree:
				traverseTree(entry.OIDHex, depth+1)

			case parser.ModeRegular, parser.ModeExecutable, parser.ModeSymlink:
				if !store.Exists(entry.OIDHex) {
					result.Anomalies = append(result.Anomalies, StructuralAnomaly{
						Type:        AnomalyMissingReferencedObject,
						Location:    entry.OIDHex,
						Description: fmt.Sprintf("referenced blob %s missing from storage", entry.OIDHex),
					})
				} else {
					result.Blobs[entry.OIDHex] = true
					totalVisited++
				}

			case parser.ModeGitlink:
				// Record gitlink boundary; never recurse into submodule
				result.Gitlinks[string(entry.Name)] = entry.OIDHex
			}
		}
	}

	traverseCommit = func(commitOID string) {
		if result.Commits[commitOID] {
			return
		}
		if totalVisited >= limits.MaxTotalObjects {
			result.Anomalies = append(result.Anomalies, StructuralAnomaly{
				Type:        AnomalyRecursionDepthExceeded,
				Location:    commitOID,
				Description: "total object traversal safety ceiling reached",
			})
			return
		}

		result.Commits[commitOID] = true
		totalVisited++

		obj, err := store.Get(commitOID)
		if err != nil {
			result.Anomalies = append(result.Anomalies, StructuralAnomaly{
				Type:        AnomalyMissingReferencedObject,
				Location:    commitOID,
				Description: fmt.Sprintf("missing commit object: %v", err),
			})
			return
		}

		if obj.IntegrityMismatch {
			result.Anomalies = append(result.Anomalies, StructuralAnomaly{
				Type:        AnomalyLooseIntegrityMismatch,
				Location:    commitOID,
				Description: fmt.Sprintf("loose object hash mismatch (expected %s, computed %s)", obj.ID, obj.ComputedID),
			})
		}

		commit, parseErr := parser.ParseCommit(obj.Payload)
		if parseErr != nil {
			result.Anomalies = append(result.Anomalies, StructuralAnomaly{
				Type:        AnomalyMalformedCommit,
				Location:    commitOID,
				Description: fmt.Sprintf("malformed commit payload: %v", parseErr),
			})
			return
		}

		// 1. Traverse root tree
		if commit.TreeSHA != "" {
			traverseTree(commit.TreeSHA, 0)
		}

		// 2. Traverse parent commits in stored order
		for _, parentSHA := range commit.ParentSHAs {
			traverseCommit(parentSHA)
		}
	}

	// Traverse each root
	for _, rootOID := range sortedRoots {
		if rootOID == "" {
			continue
		}

		// Minimal tag peeling if root is a tag
		peeledOID, objType, err := repository.PeelTag(store, rootOID, limits.MaxPeelDepth)
		if err != nil {
			result.Anomalies = append(result.Anomalies, StructuralAnomaly{
				Type:        AnomalyMissingReferencedObject,
				Location:    rootOID,
				Description: fmt.Sprintf("failed to resolve root ref target: %v", err),
			})
			continue
		}

		switch objType {
		case object.TypeCommit:
			traverseCommit(peeledOID)
		case object.TypeTree:
			traverseTree(peeledOID, 0)
		case object.TypeBlob:
			if !store.Exists(peeledOID) {
				result.Anomalies = append(result.Anomalies, StructuralAnomaly{
					Type:        AnomalyMissingReferencedObject,
					Location:    peeledOID,
					Description: fmt.Sprintf("root blob %s missing from storage", peeledOID),
				})
			} else {
				result.Blobs[peeledOID] = true
				totalVisited++
			}
		default:
			// Fallback: attempt commit traversal
			traverseCommit(peeledOID)
		}
	}

	return result, nil
}
