package repository

import (
	"bytes"
	"fmt"
	"gitforensics/pkg/object"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Ref represents a Git reference.
type Ref struct {
	Name     string
	Target   string
	IsSymbol bool
}

// RefAnomaly represents a non-fatal irregularity encountered during ref resolution.
type RefAnomaly struct {
	Type        string
	Location    string
	Description string
}

// ResolveHEAD resolves the current worktree HEAD reference.
// Returns:
// - oid: the 40-character hex target OID if resolved
// - isUnborn: true if HEAD points to a valid branch that does not yet exist (unborn branch)
// - err: non-nil if HEAD is missing or malformed
func ResolveHEAD(repo *Repository) (string, bool, error) {
	headPath := filepath.Join(repo.GitDir, "HEAD")
	data, err := os.ReadFile(headPath)
	if err != nil {
		return "", false, err
	}

	content := strings.TrimSpace(string(data))
	if len(content) == 0 {
		return "", false, fmt.Errorf("empty HEAD file")
	}

	// Case 1: Symbolic reference (e.g. "ref: refs/heads/main")
	if strings.HasPrefix(content, "ref:") {
		targetRef := strings.TrimSpace(strings.TrimPrefix(content, "ref:"))
		if len(targetRef) == 0 {
			return "", false, fmt.Errorf("malformed symbolic HEAD")
		}

		oid, err := ResolveSymbolicRef(repo, targetRef, 10)
		if err != nil {
			if os.IsNotExist(err) || err == object.ErrObjectNotFound {
				// Target ref does not exist yet -> unborn branch (valid state per §4)
				return "", true, nil
			}
			return "", false, err
		}
		return oid, false, nil
	}

	// Case 2: Detached HEAD (direct 40-hex OID)
	if err := object.ValidateOID(content); err != nil {
		return "", false, fmt.Errorf("malformed detached HEAD OID: %w", err)
	}

	return content, false, nil
}

// ResolveSymbolicRef resolves a symbolic reference name (e.g. "refs/heads/main") to its 40-hex OID.
// Guards against infinite symbolic reference loops using a visited set and maxDepth (typically 10).
func ResolveSymbolicRef(repo *Repository, refName string, maxDepth int) (string, error) {
	visited := make(map[string]bool)
	currRef := refName

	for depth := 0; depth < maxDepth; depth++ {
		if visited[currRef] {
			return "", object.ErrSymbolicRefCycle
		}
		visited[currRef] = true

		// Check loose ref first (precedence)
		loosePath := filepath.Join(repo.CommonDir, filepath.FromSlash(currRef))
		data, err := os.ReadFile(loosePath)
		if err == nil {
			content := strings.TrimSpace(string(data))
			if strings.HasPrefix(content, "ref:") {
				currRef = strings.TrimSpace(strings.TrimPrefix(content, "ref:"))
				continue
			}
			if err := object.ValidateOID(content); err == nil {
				return content, nil
			}
			return "", fmt.Errorf("malformed loose ref %s: invalid OID", currRef)
		}

		// Check packed-refs
		packedRefs, _, err := parsePackedRefs(repo.CommonDir)
		if err == nil {
			if targetOID, exists := packedRefs[currRef]; exists {
				return targetOID, nil
			}
		}

		return "", object.ErrObjectNotFound
	}

	return "", object.ErrSymbolicRefCycle
}

// AllRefs discovers and resolves all references across the entire refs/** namespace.
// Merges loose refs over packed-refs (loose takes precedence).
// Returns a map of ref name -> 40-hex OID, sorted deterministically.
func AllRefs(repo *Repository) (map[string]string, []RefAnomaly, error) {
	var anomalies []RefAnomaly
	resolved := make(map[string]string)

	// 1. Parse packed-refs first
	packedMap, packedAnomalies, err := parsePackedRefs(repo.CommonDir)
	if err != nil && !os.IsNotExist(err) {
		anomalies = append(anomalies, RefAnomaly{
			Type:        "MALFORMED_PACKED_REF",
			Location:    filepath.Join(repo.CommonDir, "packed-refs"),
			Description: err.Error(),
		})
	}
	anomalies = append(anomalies, packedAnomalies...)
	for name, oid := range packedMap {
		resolved[name] = oid
	}

	// 2. Enumerate all loose refs under CommonDir/refs/** (loose overrides packed)
	refsRoot := filepath.Join(repo.CommonDir, "refs")
	if _, err := os.Stat(refsRoot); err == nil {
		walkErr := filepath.Walk(refsRoot, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if info.IsDir() {
				return nil
			}

			relPath, err := filepath.Rel(repo.CommonDir, path)
			if err != nil {
				return nil
			}
			refName := filepath.ToSlash(relPath)

			data, readErr := os.ReadFile(path)
			if readErr != nil {
				anomalies = append(anomalies, RefAnomaly{
					Type:        "MALFORMED_REF",
					Location:    refName,
					Description: readErr.Error(),
				})
				return nil
			}

			content := strings.TrimSpace(string(data))
			if strings.HasPrefix(content, "ref:") {
				// Symbolic ref
				targetRef := strings.TrimSpace(strings.TrimPrefix(content, "ref:"))
				targetOID, resolveErr := ResolveSymbolicRef(repo, targetRef, 10)
				if resolveErr != nil {
					anomalies = append(anomalies, RefAnomaly{
						Type:        "MALFORMED_REF",
						Location:    refName,
						Description: resolveErr.Error(),
					})
					return nil
				}
				resolved[refName] = targetOID
			} else {
				// Direct 40-hex OID
				if valErr := object.ValidateOID(content); valErr != nil {
					anomalies = append(anomalies, RefAnomaly{
						Type:        "MALFORMED_REF",
						Location:    refName,
						Description: fmt.Sprintf("invalid OID: %s", content),
					})
					return nil
				}
				resolved[refName] = content
			}
			return nil
		})
		if walkErr != nil {
			return nil, anomalies, walkErr
		}
	}

	return resolved, anomalies, nil
}

// parsePackedRefs reads and parses the packed-refs file according to Git packed-refs format (§4).
func parsePackedRefs(commonDir string) (map[string]string, []RefAnomaly, error) {
	packedPath := filepath.Join(commonDir, "packed-refs")
	data, err := os.ReadFile(packedPath)
	if err != nil {
		return nil, nil, err
	}

	refs := make(map[string]string)
	var anomalies []RefAnomaly

	lines := bytes.Split(data, []byte("\n"))
	var lastRefName string

	for lineNum, line := range lines {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}

		// Header or comment line
		if line[0] == '#' {
			continue
		}

		// Peeled ref line attached to preceding ref: "^<40-hex-oid>"
		if line[0] == '^' {
			peeledOID := string(line[1:])
			if err := object.ValidateOID(peeledOID); err != nil {
				anomalies = append(anomalies, RefAnomaly{
					Type:        "MALFORMED_PACKED_REF",
					Location:    fmt.Sprintf("packed-refs:%d", lineNum+1),
					Description: fmt.Sprintf("invalid peeled OID: %s", peeledOID),
				})
			}
			// (Peeled tag is documented; underlying ref target already captured)
			continue
		}

		// Format: "<40-hex-oid> <refname>"
		spIdx := bytes.IndexByte(line, ' ')
		if spIdx == -1 {
			anomalies = append(anomalies, RefAnomaly{
				Type:        "MALFORMED_PACKED_REF",
				Location:    fmt.Sprintf("packed-refs:%d", lineNum+1),
				Description: "missing space separator",
			})
			continue
		}

		oidStr := string(line[:spIdx])
		refName := string(line[spIdx+1:])

		if err := object.ValidateOID(oidStr); err != nil {
			anomalies = append(anomalies, RefAnomaly{
				Type:        "MALFORMED_PACKED_REF",
				Location:    fmt.Sprintf("packed-refs:%d", lineNum+1),
				Description: fmt.Sprintf("invalid OID: %s", oidStr),
			})
			continue
		}

		refs[refName] = oidStr
		lastRefName = refName
	}
	_ = lastRefName

	return refs, anomalies, nil
}

// SortedRefNames returns the keys of a ref map sorted lexicographically for deterministic processing.
func SortedRefNames(refs map[string]string) []string {
	names := make([]string, 0, len(refs))
	for name := range refs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
