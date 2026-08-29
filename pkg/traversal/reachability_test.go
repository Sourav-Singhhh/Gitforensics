package traversal

import (
	"encoding/hex"
	"fmt"
	"gitforensics/pkg/object"
	"testing"
)

// inMemoryStore implements repository.ObjectStore for unit testing traversal.
type inMemoryStore struct {
	objects map[string]*object.Object
}

func (s *inMemoryStore) Get(oid string) (*object.Object, error) {
	obj, exists := s.objects[oid]
	if !exists {
		return nil, object.ErrObjectNotFound
	}
	return obj, nil
}

func (s *inMemoryStore) Exists(oid string) bool {
	_, exists := s.objects[oid]
	return exists
}

func hexTo20Bytes(h string) [20]byte {
	b, _ := hex.DecodeString(h)
	var arr [20]byte
	copy(arr[:], b)
	return arr
}

func TestReachableCleanDAG(t *testing.T) {
	blob1OID := "1111111111111111111111111111111111111111"
	blob2OID := "2222222222222222222222222222222222222222"
	subTreeOID := "3333333333333333333333333333333333333333"
	rootTreeOID := "4444444444444444444444444444444444444444"
	commitOID := "5555555555555555555555555555555555555555"

	// Construct subtree: 100644 sub.txt -> blob2
	b2 := hexTo20Bytes(blob2OID)
	subTreePayload := append([]byte("100644 sub.txt\x00"), b2[:]...)

	// Construct root tree: 100644 root.txt -> blob1, 40000 dir -> subTree
	b1 := hexTo20Bytes(blob1OID)
	st := hexTo20Bytes(subTreeOID)
	var rootTreePayload []byte
	rootTreePayload = append(rootTreePayload, []byte("40000 dir\x00")...)
	rootTreePayload = append(rootTreePayload, st[:]...)
	rootTreePayload = append(rootTreePayload, []byte("100644 root.txt\x00")...)
	rootTreePayload = append(rootTreePayload, b1[:]...)

	// Construct commit
	commitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Alice <alice@example.com> 1700000000 +0000\ncommitter Alice <alice@example.com> 1700000000 +0000\n\nInitial\n",
		rootTreeOID,
	))

	store := &inMemoryStore{
		objects: map[string]*object.Object{
			blob1OID:    {Type: object.TypeBlob, ID: blob1OID, Payload: []byte("root file")},
			blob2OID:    {Type: object.TypeBlob, ID: blob2OID, Payload: []byte("sub file")},
			subTreeOID:  {Type: object.TypeTree, ID: subTreeOID, Payload: subTreePayload},
			rootTreeOID: {Type: object.TypeTree, ID: rootTreeOID, Payload: rootTreePayload},
			commitOID:   {Type: object.TypeCommit, ID: commitOID, Payload: commitPayload},
		},
	}

	result, err := TraverseReachable(store, []string{commitOID}, DefaultTraversalLimits())
	if err != nil {
		t.Fatalf("unexpected traversal error: %v", err)
	}

	if !result.Commits[commitOID] {
		t.Errorf("expected commit %s reachable", commitOID)
	}
	if !result.Trees[rootTreeOID] {
		t.Errorf("expected root tree %s reachable", rootTreeOID)
	}
	if !result.Trees[subTreeOID] {
		t.Errorf("expected sub tree %s reachable", subTreeOID)
	}
	if !result.Blobs[blob1OID] {
		t.Errorf("expected blob1 %s reachable", blob1OID)
	}
	if !result.Blobs[blob2OID] {
		t.Errorf("expected blob2 %s reachable", blob2OID)
	}
	if len(result.Anomalies) != 0 {
		t.Errorf("expected 0 anomalies on clean DAG, got %v", result.Anomalies)
	}
}

func TestMergeCommitHistory(t *testing.T) {
	blob1 := "1111111111111111111111111111111111111111"
	blob2 := "2222222222222222222222222222222222222222"
	tree1 := "3333333333333333333333333333333333333333"
	tree2 := "4444444444444444444444444444444444444444"
	parent1 := "5555555555555555555555555555555555555555"
	parent2 := "6666666666666666666666666666666666666666"
	mergeCommit := "7777777777777777777777777777777777777777"

	b1 := hexTo20Bytes(blob1)
	tree1Payload := append([]byte("100644 a.txt\x00"), b1[:]...)

	b2 := hexTo20Bytes(blob2)
	tree2Payload := append([]byte("100644 b.txt\x00"), b2[:]...)

	c1Payload := []byte(fmt.Sprintf("tree %s\nauthor A <a@b.c> 100 +0000\ncommitter A <a@b.c> 100 +0000\n\nP1\n", tree1))
	c2Payload := []byte(fmt.Sprintf("tree %s\nauthor B <b@b.c> 100 +0000\ncommitter B <b@b.c> 100 +0000\n\nP2\n", tree2))
	mergePayload := []byte(fmt.Sprintf("tree %s\nparent %s\nparent %s\nauthor M <m@b.c> 100 +0000\ncommitter M <m@b.c> 100 +0000\n\nMerge\n", tree1, parent1, parent2))

	store := &inMemoryStore{
		objects: map[string]*object.Object{
			blob1:       {Type: object.TypeBlob, ID: blob1, Payload: []byte("a")},
			blob2:       {Type: object.TypeBlob, ID: blob2, Payload: []byte("b")},
			tree1:       {Type: object.TypeTree, ID: tree1, Payload: tree1Payload},
			tree2:       {Type: object.TypeTree, ID: tree2, Payload: tree2Payload},
			parent1:     {Type: object.TypeCommit, ID: parent1, Payload: c1Payload},
			parent2:     {Type: object.TypeCommit, ID: parent2, Payload: c2Payload},
			mergeCommit: {Type: object.TypeCommit, ID: mergeCommit, Payload: mergePayload},
		},
	}

	result, err := TraverseReachable(store, []string{mergeCommit}, DefaultTraversalLimits())
	if err != nil {
		t.Fatalf("merge traversal failed: %v", err)
	}

	if !result.Commits[mergeCommit] || !result.Commits[parent1] || !result.Commits[parent2] {
		t.Errorf("expected all 3 commits reachable: %v", result.Commits)
	}
	if !result.Blobs[blob1] || !result.Blobs[blob2] {
		t.Errorf("expected both lineage blobs reachable: %v", result.Blobs)
	}
}

func TestGitlinkBoundary(t *testing.T) {
	submoduleOID := "1111111111111111111111111111111111111111"
	treeOID := "2222222222222222222222222222222222222222"
	commitOID := "3333333333333333333333333333333333333333"

	// Tree contains mode 160000 (gitlink) pointing to external commit OID
	subBytes := hexTo20Bytes(submoduleOID)
	treePayload := append([]byte("160000 submod\x00"), subBytes[:]...)
	commitPayload := []byte(fmt.Sprintf("tree %s\nauthor A <a@b.c> 100 +0000\ncommitter A <a@b.c> 100 +0000\n\nSubmod\n", treeOID))

	store := &inMemoryStore{
		objects: map[string]*object.Object{
			treeOID:   {Type: object.TypeTree, ID: treeOID, Payload: treePayload},
			commitOID: {Type: object.TypeCommit, ID: commitOID, Payload: commitPayload},
			// Notice submoduleOID is intentionally NOT in the store (submodule history is external)
		},
	}

	result, err := TraverseReachable(store, []string{commitOID}, DefaultTraversalLimits())
	if err != nil {
		t.Fatalf("traversal failed on gitlink: %v", err)
	}

	if result.Gitlinks["submod"] != submoduleOID {
		t.Errorf("expected gitlink recorded as %s, got %s", submoduleOID, result.Gitlinks["submod"])
	}
	// Crucial: gitlink must not attempt store.Get or fail with missing object
	if len(result.Anomalies) != 0 {
		t.Errorf("expected 0 anomalies on valid gitlink boundary, got %v", result.Anomalies)
	}
}

func TestUnsafeTreeNameTraversal(t *testing.T) {
	blob1 := "1111111111111111111111111111111111111111"
	blob2 := "2222222222222222222222222222222222222222"
	treeOID := "3333333333333333333333333333333333333333"

	b1 := hexTo20Bytes(blob1)
	b2 := hexTo20Bytes(blob2)
	var treePayload []byte
	// Unsafe names: ".." and "sub/dir"
	treePayload = append(treePayload, []byte("100644 ..\x00")...)
	treePayload = append(treePayload, b1[:]...)
	treePayload = append(treePayload, []byte("100644 sub/dir\x00")...)
	treePayload = append(treePayload, b2[:]...)

	store := &inMemoryStore{
		objects: map[string]*object.Object{
			blob1:   {Type: object.TypeBlob, ID: blob1, Payload: []byte("content 1")},
			blob2:   {Type: object.TypeBlob, ID: blob2, Payload: []byte("content 2")},
			treeOID: {Type: object.TypeTree, ID: treeOID, Payload: treePayload},
		},
	}

	result, err := TraverseReachable(store, []string{treeOID}, DefaultTraversalLimits())
	if err != nil {
		t.Fatalf("traversal failed on unsafe tree names: %v", err)
	}

	// Invariant §6, §8: OIDs must still be traversed and reachable
	if !result.Blobs[blob1] || !result.Blobs[blob2] {
		t.Errorf("expected blobs with unsafe names to remain reachable: %v", result.Blobs)
	}

	// Invariant: Unsafe names must generate structural anomalies
	unsafeCount := 0
	for _, a := range result.Anomalies {
		if a.Type == AnomalyUnsafeTreeName {
			unsafeCount++
		}
	}
	if unsafeCount != 2 {
		t.Errorf("expected 2 AnomalyUnsafeTreeName anomalies, got %d", unsafeCount)
	}
}

func TestUnknownTreeModeTraversal(t *testing.T) {
	blobOID := "1111111111111111111111111111111111111111"
	treeUnderUnknownMode := "2222222222222222222222222222222222222222"
	rootTreeOID := "3333333333333333333333333333333333333333"

	b := hexTo20Bytes(blobOID)
	tr := hexTo20Bytes(treeUnderUnknownMode)

	var rootPayload []byte
	// 100664 custom mode pointing to blob
	rootPayload = append(rootPayload, []byte("100664 custom.txt\x00")...)
	rootPayload = append(rootPayload, b[:]...)
	// 100664 custom mode pointing to tree object (type mismatch)
	rootPayload = append(rootPayload, []byte("100664 wrong_type\x00")...)
	rootPayload = append(rootPayload, tr[:]...)

	store := &inMemoryStore{
		objects: map[string]*object.Object{
			blobOID:              {Type: object.TypeBlob, ID: blobOID, Payload: []byte("blob data")},
			treeUnderUnknownMode: {Type: object.TypeTree, ID: treeUnderUnknownMode, Payload: []byte{}},
			rootTreeOID:          {Type: object.TypeTree, ID: rootTreeOID, Payload: rootPayload},
		},
	}

	result, err := TraverseReachable(store, []string{rootTreeOID}, DefaultTraversalLimits())
	if err != nil {
		t.Fatalf("traversal failed on unknown mode: %v", err)
	}

	// Invariant: blob reached
	if !result.Blobs[blobOID] {
		t.Errorf("expected blob %s reachable under unknown mode", blobOID)
	}

	// Invariant: Tree under non-40000 mode records type mismatch anomaly and is NOT recursed
	hasUnknownModeAnomaly := false
	hasTypeMismatchAnomaly := false
	for _, a := range result.Anomalies {
		if a.Type == AnomalyUnknownTreeMode {
			hasUnknownModeAnomaly = true
		}
		if a.Type == AnomalyTreeTypeMismatch {
			hasTypeMismatchAnomaly = true
		}
	}
	if !hasUnknownModeAnomaly {
		t.Errorf("expected AnomalyUnknownTreeMode recorded")
	}
	if !hasTypeMismatchAnomaly {
		t.Errorf("expected AnomalyTreeTypeMismatch recorded for tree under non-40000 mode")
	}
}

func TestTreeRecursionDepthLimit(t *testing.T) {
	// Construct a chain of 15 trees
	store := &inMemoryStore{objects: make(map[string]*object.Object)}
	for i := 0; i < 15; i++ {
		currOID := fmt.Sprintf("%040d", i)
		nextOID := fmt.Sprintf("%040d", i+1)
		nextBytes := hexTo20Bytes(nextOID)
		payload := append([]byte("40000 next\x00"), nextBytes[:]...)
		store.objects[currOID] = &object.Object{
			Type:    object.TypeTree,
			ID:      currOID,
			Payload: payload,
		}
	}

	limits := TraversalLimits{
		MaxTreeDepth:    5, // deliberately small limit
		MaxPeelDepth:    10,
		MaxTotalObjects: 1000,
	}

	result, err := TraverseReachable(store, []string{fmt.Sprintf("%040d", 0)}, limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasDepthAnomaly := false
	for _, a := range result.Anomalies {
		if a.Type == AnomalyRecursionDepthExceeded {
			hasDepthAnomaly = true
		}
	}
	if !hasDepthAnomaly {
		t.Errorf("expected AnomalyRecursionDepthExceeded when exceeding MaxTreeDepth")
	}
}

func TestMalformedBranchContainment(t *testing.T) {
	goodBlob := "1111111111111111111111111111111111111111"
	goodTree := "2222222222222222222222222222222222222222"
	parentCommit := "3333333333333333333333333333333333333333"
	corruptTree := "4444444444444444444444444444444444444444"
	headCommit := "5555555555555555555555555555555555555555"

	gb := hexTo20Bytes(goodBlob)
	goodTreePayload := append([]byte("100644 good.txt\x00"), gb[:]...)

	pCommitPayload := []byte(fmt.Sprintf("tree %s\nauthor A <a@b.c> 100 +0000\ncommitter A <a@b.c> 100 +0000\n\nParent\n", goodTree))
	headPayload := []byte(fmt.Sprintf("tree %s\nparent %s\nauthor A <a@b.c> 100 +0000\ncommitter A <a@b.c> 100 +0000\n\nHead\n", corruptTree, parentCommit))

	store := &inMemoryStore{
		objects: map[string]*object.Object{
			goodBlob:     {Type: object.TypeBlob, ID: goodBlob, Payload: []byte("good content")},
			goodTree:     {Type: object.TypeTree, ID: goodTree, Payload: goodTreePayload},
			parentCommit: {Type: object.TypeCommit, ID: parentCommit, Payload: pCommitPayload},
			corruptTree:  {Type: object.TypeTree, ID: corruptTree, Payload: []byte("corrupt tree payload without separator")},
			headCommit:   {Type: object.TypeCommit, ID: headCommit, Payload: headPayload},
		},
	}

	result, err := TraverseReachable(store, []string{headCommit}, DefaultTraversalLimits())
	if err != nil {
		t.Fatalf("traversal aborted on malformed branch: %v", err)
	}

	// Invariant §8: Malformed tree in headCommit must NOT abort parentCommit traversal
	if !result.Commits[headCommit] {
		t.Errorf("expected head commit reachable")
	}
	if !result.Commits[parentCommit] {
		t.Errorf("expected parent commit reachable despite head tree failure")
	}
	if !result.Blobs[goodBlob] {
		t.Errorf("expected good blob from parent commit reachable")
	}

	// Invariant: Malformed tree recorded as anomaly
	hasMalformedAnomaly := false
	for _, a := range result.Anomalies {
		if a.Type == AnomalyMalformedTree {
			hasMalformedAnomaly = true
		}
	}
	if !hasMalformedAnomaly {
		t.Errorf("expected AnomalyMalformedTree recorded")
	}
}
