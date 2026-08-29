package traversal

import (
	"fmt"
	"gitforensics/pkg/object"
	"gitforensics/pkg/repository"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// PhysicalObject represents an object discovered on disk from loose storage or a packfile (§8, §16).
type PhysicalObject struct {
	OID       string
	Path      string
	Source    string // "loose" or "pack"
	Type      object.ObjectType
	Size      int64
	Malformed bool
}

// PhysicalLooseObject is an alias to PhysicalObject for backwards compatibility.
type PhysicalLooseObject = PhysicalObject

// isHexDigit returns true if c is a lowercase hexadecimal digit ('0'-'9', 'a'-'f').
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

// isTwoHexChars returns true if s is exactly 2 lowercase hex characters.
func isTwoHexChars(s string) bool {
	if len(s) != 2 {
		return false
	}
	return isHexDigit(s[0]) && isHexDigit(s[1])
}

// is38HexChars returns true if s is exactly 38 lowercase hex characters.
func is38HexChars(s string) bool {
	if len(s) != 38 {
		return false
	}
	for i := 0; i < 38; i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// EnumeratePhysicalObjects scans loose objects and includes decoded packed objects from store (§8, §16).
func EnumeratePhysicalObjects(commonDir string, store repository.ObjectStore) ([]PhysicalObject, []StructuralAnomaly, error) {
	objectsRoot := filepath.Join(commonDir, "objects")
	dirEntries, err := os.ReadDir(objectsRoot)
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, err
	}

	var physicalObjects []PhysicalObject
	var anomalies []StructuralAnomaly
	seenOIDs := make(map[string]bool)

	if err == nil {
		for _, dEntry := range dirEntries {
			if !dEntry.IsDir() {
				continue
			}
			prefix := strings.ToLower(dEntry.Name())
			if !isTwoHexChars(prefix) {
				// Skips "info", "pack", etc.
				continue
			}

			subDir := filepath.Join(objectsRoot, dEntry.Name())
			files, readErr := os.ReadDir(subDir)
			if readErr != nil {
				continue
			}

			for _, f := range files {
				if f.IsDir() {
					continue
				}
				rest := strings.ToLower(f.Name())
				if !is38HexChars(rest) {
					continue
				}

				oid := prefix + rest
				fullPath := filepath.Join(subDir, f.Name())

				obj, getErr := store.Get(oid)
				if getErr != nil {
					// Corrupted / unreadable loose object on disk
					anomalies = append(anomalies, StructuralAnomaly{
						Type:        AnomalyCorruptedLooseObject,
						Location:    fullPath,
						Description: fmt.Sprintf("failed to read loose object %s: %v", oid, getErr),
					})
					physicalObjects = append(physicalObjects, PhysicalObject{
						OID:       oid,
						Path:      fullPath,
						Source:    "loose",
						Malformed: true,
					})
					seenOIDs[oid] = true
					continue
				}

				if obj.IntegrityMismatch {
					anomalies = append(anomalies, StructuralAnomaly{
						Type:        AnomalyLooseIntegrityMismatch,
						Location:    fullPath,
						Description: fmt.Sprintf("loose object hash mismatch (expected %s, computed %s)", obj.ID, obj.ComputedID),
					})
				}

				physicalObjects = append(physicalObjects, PhysicalObject{
					OID:       oid,
					Path:      fullPath,
					Source:    "loose",
					Type:      obj.Type,
					Size:      obj.Size,
					Malformed: false,
				})
				seenOIDs[oid] = true
			}
		}
	}

	// 2. Include decoded packed objects from store (§16)
	if combined, ok := store.(*repository.CombinedStore); ok {
		for _, pObj := range combined.AllDecodedObjects() {
			if !seenOIDs[pObj.ID] {
				seenOIDs[pObj.ID] = true
				physicalObjects = append(physicalObjects, PhysicalObject{
					OID:       pObj.ID,
					Path:      "pack",
					Source:    "pack",
					Type:      pObj.Type,
					Size:      pObj.Size,
					Malformed: false,
				})
			}
		}
	}

	// Sort physical objects deterministically by OID
	sort.Slice(physicalObjects, func(i, j int) bool {
		return physicalObjects[i].OID < physicalObjects[j].OID
	})

	return physicalObjects, anomalies, nil
}

// EnumerateLooseObjects provides backwards compatibility with Phase 3 tests.
func EnumerateLooseObjects(gitDir string, store repository.ObjectStore) ([]PhysicalLooseObject, []StructuralAnomaly, error) {
	return EnumeratePhysicalObjects(gitDir, store)
}

// FindDangling computes Dangling = AllOnDiskObjects \ ReachableOIDs (§8).
// Malformed physical objects remain visible in the result set.
func FindDangling(allPhysical []PhysicalObject, reachableOIDs map[string]bool) ([]PhysicalObject, []StructuralAnomaly) {
	var dangling []PhysicalObject
	var anomalies []StructuralAnomaly

	for _, phys := range allPhysical {
		if !reachableOIDs[phys.OID] {
			dangling = append(dangling, phys)
			if phys.Malformed {
				anomalies = append(anomalies, StructuralAnomaly{
					Type:        AnomalyCorruptedLooseObject,
					Location:    phys.Path,
					Description: fmt.Sprintf("dangling object %s is malformed", phys.OID),
				})
			}
		}
	}

	return dangling, anomalies
}
