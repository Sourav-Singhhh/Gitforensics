package repository

import (
	"bytes"
	"fmt"
	"gitforensics/pkg/object"
)

// PeelTag implements minimal tag peeling (§4):
// If the object at oid is a Git tag (TypeTag), inspects the first line:
//
//	object <40-hex>
//
// Follows nested tag-to-tag references up to maxDepth (default 10) with cycle protection.
// Returns the final peeled target OID, its resolved object type, and any error.
func PeelTag(store ObjectStore, oid string, maxDepth int) (string, object.ObjectType, error) {
	if maxDepth <= 0 {
		maxDepth = 10
	}

	visited := make(map[string]bool)
	currOID := oid

	for depth := 0; depth < maxDepth; depth++ {
		if visited[currOID] {
			return "", "", object.ErrSymbolicRefCycle
		}
		visited[currOID] = true

		obj, err := store.Get(currOID)
		if err != nil {
			return "", "", err
		}

		if obj.Type != object.TypeTag {
			// Resolved to non-tag object (commit, tree, blob)
			return currOID, obj.Type, nil
		}

		// Parse first line of tag payload: "object <40-hex>"
		nlIdx := bytes.IndexByte(obj.Payload, '\n')
		firstLine := obj.Payload
		if nlIdx != -1 {
			firstLine = obj.Payload[:nlIdx]
		}
		firstLine = bytes.TrimSpace(firstLine)

		prefix := []byte("object ")
		if !bytes.HasPrefix(firstLine, prefix) {
			return "", "", fmt.Errorf("malformed tag %s: missing object header", currOID)
		}

		targetOID := string(bytes.TrimSpace(firstLine[len(prefix):]))
		if err := object.ValidateOID(targetOID); err != nil {
			return "", "", fmt.Errorf("malformed tag %s: invalid target OID %s: %w", currOID, targetOID, err)
		}

		currOID = targetOID
	}

	return "", "", object.ErrMaxPeelDepthExceeded
}
