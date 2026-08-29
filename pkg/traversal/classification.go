package traversal

import (
	"fmt"
	"gitforensics/pkg/object"
	"gitforensics/pkg/repository"
	"sort"
)

// ExposureState represents the reachability classification of a blob in the Git object graph (§9).
type ExposureState string

const (
	// StateActive represents blobs reachable from current worktree HEAD.
	StateActive ExposureState = "ACTIVE"

	// StateHistorical represents blobs reachable from other branches/tags/refs, but not current HEAD.
	StateHistorical ExposureState = "HISTORICAL"

	// StateZombie represents unreferenced loose blobs physically present on disk.
	StateZombie ExposureState = "ZOMBIE"

	// StateUnresolved represents referenced blobs missing from loose storage.
	StateUnresolved ExposureState = "UNRESOLVED_MISSING"
)

// ClassifiedBlob represents a blob with its computed exposure state.
type ClassifiedBlob struct {
	OID   string
	State ExposureState
}

// ClassificationResult holds the complete exposure classification sets and structural anomalies (§9).
type ClassificationResult struct {
	ActiveBlobs     []string
	HistoricalBlobs []string
	ZombieBlobs     []string
	UnresolvedOIDs  []string
	Anomalies       []StructuralAnomaly
}

// ClassifyRepository executes the complete Phase 3 reachability, dangling discovery,
// and blob classification pipeline on a repository.
//
// Invariants enforced (§8, §9):
// 1. HEAD reachability is isolated: Active = HeadReachableBlobs.
// 2. All-ref reachability: Historical = AllReachableBlobs \ HeadReachableBlobs.
// 3. Independent physical scan: Zombie = AllOnDiskBlobs \ AllReachableBlobs.
// 4. Unresolved objects: Missing referenced objects are classified as UNRESOLVED_MISSING, NEVER ZOMBIE.
// 5. All returned slices are sorted deterministically by OID.
func ClassifyRepository(
	repo *repository.Repository,
	store repository.ObjectStore,
	limits TraversalLimits,
) (*ClassificationResult, error) {
	var allAnomalies []StructuralAnomaly

	// 1. Resolve HEAD
	headOID, isUnborn, headErr := repository.ResolveHEAD(repo)
	if headErr != nil {
		allAnomalies = append(allAnomalies, StructuralAnomaly{
			Type:        AnomalyMalformedRef,
			Location:    "HEAD",
			Description: fmt.Sprintf("failed to resolve HEAD: %v", headErr),
		})
	}

	headReachableBlobs := make(map[string]bool)

	// 2. Compute HEAD-reachable graph strictly from HEAD if resolved and not unborn (§9)
	if headOID != "" && !isUnborn {
		headResult, err := TraverseReachable(store, []string{headOID}, limits)
		if err == nil && headResult != nil {
			headReachableBlobs = headResult.Blobs
			allAnomalies = append(allAnomalies, headResult.Anomalies...)
		}
	}

	// 3. Discover and resolve all refs under refs/**
	allRefsMap, refAnomalies, refErr := repository.AllRefs(repo)
	if refErr != nil {
		allAnomalies = append(allAnomalies, StructuralAnomaly{
			Type:        AnomalyMalformedRef,
			Location:    "refs",
			Description: fmt.Sprintf("error scanning refs: %v", refErr),
		})
	}
	for _, a := range refAnomalies {
		allAnomalies = append(allAnomalies, StructuralAnomaly{
			Type:        AnomalyType(a.Type),
			Location:    a.Location,
			Description: a.Description,
		})
	}

	// 4. Construct complete RootSet: { resolve(HEAD) } ∪ { resolve(r) : r ∈ refs/** }
	rootSetMap := make(map[string]bool)
	if headOID != "" && !isUnborn {
		rootSetMap[headOID] = true
	}
	for _, refOID := range allRefsMap {
		rootSetMap[refOID] = true
	}

	rootOIDs := make([]string, 0, len(rootSetMap))
	for oid := range rootSetMap {
		rootOIDs = append(rootOIDs, oid)
	}
	sort.Strings(rootOIDs)

	// 5. Compute AllReachable graph starting from the complete RootSet
	allReachableResult, err := TraverseReachable(store, rootOIDs, limits)
	if err != nil {
		return nil, fmt.Errorf("reachable traversal failed: %w", err)
	}
	allAnomalies = append(allAnomalies, allReachableResult.Anomalies...)

	allReachableBlobs := allReachableResult.Blobs

	// 6. Independent physical loose-object enumeration (§8)
	physicalObjects, looseAnomalies, err := EnumerateLooseObjects(repo.CommonDir, store)
	if err != nil {
		return nil, fmt.Errorf("physical loose object enumeration failed: %w", err)
	}
	allAnomalies = append(allAnomalies, looseAnomalies...)

	allOnDiskBlobs := make(map[string]bool)
	for _, phys := range physicalObjects {
		if !phys.Malformed && phys.Type == object.TypeBlob {
			allOnDiskBlobs[phys.OID] = true
		}
	}

	// 7. Compute exposure sets
	var activeBlobs []string
	var historicalBlobs []string
	var zombieBlobs []string
	var unresolvedOIDs []string

	// ACTIVE = HeadReachableBlobs
	for oid := range headReachableBlobs {
		activeBlobs = append(activeBlobs, oid)
	}

	// HISTORICAL = AllReachableBlobs \ HeadReachableBlobs
	for oid := range allReachableBlobs {
		if !headReachableBlobs[oid] {
			historicalBlobs = append(historicalBlobs, oid)
		}
	}

	// ZOMBIE = AllOnDiskBlobs \ AllReachableBlobs
	for oid := range allOnDiskBlobs {
		if !allReachableBlobs[oid] {
			zombieBlobs = append(zombieBlobs, oid)
		}
	}

	// Extract unresolved references from traversal anomalies
	unresolvedMap := make(map[string]bool)
	for _, a := range allAnomalies {
		if a.Type == AnomalyMissingReferencedObject && object.ValidateOID(a.Location) == nil {
			unresolvedMap[a.Location] = true
		}
	}
	for oid := range unresolvedMap {
		unresolvedOIDs = append(unresolvedOIDs, oid)
	}

	// Sort all result sets deterministically by OID
	sort.Strings(activeBlobs)
	sort.Strings(historicalBlobs)
	sort.Strings(zombieBlobs)
	sort.Strings(unresolvedOIDs)

	return &ClassificationResult{
		ActiveBlobs:     activeBlobs,
		HistoricalBlobs: historicalBlobs,
		ZombieBlobs:     zombieBlobs,
		UnresolvedOIDs:  unresolvedOIDs,
		Anomalies:       allAnomalies,
	}, nil
}
