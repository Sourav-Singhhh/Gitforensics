package repository

import (
	"fmt"
	"gitforensics/pkg/object"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ObjectStore is the storage-agnostic interface for retrieving Git objects by OID.
// Traversal and classification layers interact strictly with this abstraction,
// allowing packfile and loose storage implementations without modifying graph algorithms.
type ObjectStore interface {
	// Get retrieves a canonical Git object by its 40-character hexadecimal OID.
	// Returns object.ErrObjectNotFound if the object does not exist in storage.
	Get(oid string) (*object.Object, error)

	// Exists returns true if the object exists in storage without fully decompressing it.
	Exists(oid string) bool
}

// LooseStore provides an ObjectStore implementation backed by on-disk loose Git objects.
type LooseStore struct {
	gitDir  string
	maxSize int64
}

// NewLooseStore creates a new LooseStore rooted at the given git administrative directory.
func NewLooseStore(gitDir string, maxSize int64) *LooseStore {
	if maxSize <= 0 {
		maxSize = object.DefaultMaxObjectSize
	}
	return &LooseStore{
		gitDir:  gitDir,
		maxSize: maxSize,
	}
}

// Get reads and decodes a loose object from disk.
func (s *LooseStore) Get(oid string) (*object.Object, error) {
	obj, err := object.ReadLooseObject(s.gitDir, oid, s.maxSize)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, object.ErrObjectNotFound
		}
		return nil, err
	}
	return obj, nil
}

// Exists checks whether a loose object file exists on disk.
func (s *LooseStore) Exists(oid string) bool {
	path, err := object.LooseObjectPath(s.gitDir, oid)
	if err != nil {
		return false
	}
	_, statErr := os.Stat(path)
	return statErr == nil
}

// CombinedStore provides a unified ObjectStore backed by both loose objects and packfiles (§16).
type CombinedStore struct {
	loose        *LooseStore
	packObjects  map[string]*object.Object
	packList     []*object.Object
	packResults  []*PackFileResult
	coverageGaps []PackCoverageGap
	anomalies    []PackAnomaly
}

// NewRepositoryStore discovers and loads both loose objects and packfiles under commonDir (§16).
func NewRepositoryStore(
	gitDir string,
	commonDir string,
	maxSize int64,
) (*CombinedStore, []PackAnomaly, []PackCoverageGap, error) {
	if commonDir == "" {
		commonDir = gitDir
	}
	if maxSize <= 0 {
		maxSize = object.DefaultMaxObjectSize
	}

	loose := NewLooseStore(commonDir, maxSize)

	store := &CombinedStore{
		loose:        loose,
		packObjects:  make(map[string]*object.Object),
		packList:     make([]*object.Object, 0),
		packResults:  make([]*PackFileResult, 0),
		coverageGaps: make([]PackCoverageGap, 0),
		anomalies:    make([]PackAnomaly, 0),
	}

	// 1. Discover pack files in commonDir/objects/pack/
	packDir := filepath.Join(commonDir, "objects", "pack")
	entries, err := os.ReadDir(packDir)
	if err != nil {
		if os.IsNotExist(err) {
			return store, nil, nil, nil
		}
		return nil, nil, nil, err
	}

	var packFilenames []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".pack") {
			packFilenames = append(packFilenames, entry.Name())
		}
	}

	// Deterministic multi-pack enumeration (lexicographically by filename)
	sort.Strings(packFilenames)

	// 2. Parse each pack file
	for _, fname := range packFilenames {
		packPath := filepath.Join(packDir, fname)
		res, pErr := ParsePackFile(packPath, maxSize, DefaultMaxDeltaDepth)
		if pErr != nil {
			store.anomalies = append(store.anomalies, PackAnomaly{
				Type:        "PACK_TRUNCATED_OR_CORRUPTED",
				Location:    packPath,
				Description: fmt.Sprintf("failed to parse packfile %s: %v", fname, pErr),
			})
			continue
		}

		store.packResults = append(store.packResults, res)
		store.anomalies = append(store.anomalies, res.Anomalies...)
		store.coverageGaps = append(store.coverageGaps, res.CoverageGaps...)

		for oid, obj := range res.Objects {
			if _, exists := store.packObjects[oid]; !exists {
				store.packObjects[oid] = obj
				store.packList = append(store.packList, obj)
			}
		}
	}

	return store, store.anomalies, store.coverageGaps, nil
}

// Get retrieves an object by OID, checking loose storage first, then pack storage (§16).
func (cs *CombinedStore) Get(oid string) (*object.Object, error) {
	// 1. Precedence: Check loose objects first
	obj, err := cs.loose.Get(oid)
	if err == nil {
		return obj, nil
	}

	// 2. Check pack objects
	if pObj, found := cs.packObjects[oid]; found {
		return pObj, nil
	}

	return nil, object.ErrObjectNotFound
}

// Exists checks whether an object exists in either loose or pack storage.
func (cs *CombinedStore) Exists(oid string) bool {
	if cs.loose.Exists(oid) {
		return true
	}
	_, found := cs.packObjects[oid]
	return found
}

// AllDecodedObjects returns all decoded packed objects.
func (cs *CombinedStore) AllDecodedObjects() []*object.Object {
	return cs.packList
}

// AllPackCoverageGaps returns all coverage gaps recorded during pack loading.
func (cs *CombinedStore) AllPackCoverageGaps() []PackCoverageGap {
	return cs.coverageGaps
}

// AllPackAnomalies returns all anomalies recorded during pack loading.
func (cs *CombinedStore) AllPackAnomalies() []PackAnomaly {
	return cs.anomalies
}
