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

// PhysicalLooseObject represents an object discovered through direct filesystem scanning of .git/objects/ (§8).
type PhysicalLooseObject struct {
	OID       string
	Path      string
	Type      object.ObjectType
	Size      int64
	Malformed bool
}

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

// EnumerateLooseObjects scans .git/objects/[0-9a-f]{2}/[0-9a-f]{38} directly on disk.
// Skips objects/info, objects/pack, temporary files, and directories.
// Corrupted or malformed files are recorded as anomalies and retained as Malformed = true (§8).
func EnumerateLooseObjects(gitDir string, store repository.ObjectStore) ([]PhysicalLooseObject, []StructuralAnomaly, error) {
	objectsRoot := filepath.Join(gitDir, "objects")
	dirEntries, err := os.ReadDir(objectsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}

	var physicalObjects []PhysicalLooseObject
	var anomalies []StructuralAnomaly

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
				physicalObjects = append(physicalObjects, PhysicalLooseObject{
					OID:       oid,
					Path:      fullPath,
					Malformed: true,
				})
				continue
			}

			if obj.IntegrityMismatch {
				anomalies = append(anomalies, StructuralAnomaly{
					Type:        AnomalyLooseIntegrityMismatch,
					Location:    fullPath,
					Description: fmt.Sprintf("loose object hash mismatch (expected %s, computed %s)", obj.ID, obj.ComputedID),
				})
			}

			physicalObjects = append(physicalObjects, PhysicalLooseObject{
				OID:       oid,
				Path:      fullPath,
				Type:      obj.Type,
				Size:      obj.Size,
				Malformed: false,
			})
		}
	}

	// Sort physical objects deterministically by OID
	sort.Slice(physicalObjects, func(i, j int) bool {
		return physicalObjects[i].OID < physicalObjects[j].OID
	})

	return physicalObjects, anomalies, nil
}

// FindDangling computes Dangling = AllOnDiskObjects \ ReachableOIDs (§8).
// Malformed physical objects remain visible in the result set.
func FindDangling(allLoose []PhysicalLooseObject, reachableOIDs map[string]bool) ([]PhysicalLooseObject, []StructuralAnomaly) {
	var dangling []PhysicalLooseObject
	var anomalies []StructuralAnomaly

	for _, phys := range allLoose {
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
