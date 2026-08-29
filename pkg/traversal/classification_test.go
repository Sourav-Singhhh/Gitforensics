package traversal

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"gitforensics/pkg/object"
	"gitforensics/pkg/repository"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func compressZlib(data []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func writeLooseObject(t *testing.T, gitDir string, objType object.ObjectType, payload []byte) string {
	t.Helper()
	oid := object.ComputeEnvelopeSHA1(objType, int64(len(payload)), payload)
	rawEnvelope := append([]byte(fmt.Sprintf("%s %d\x00", objType, len(payload))), payload...)
	compressed := compressZlib(rawEnvelope)

	objDir := filepath.Join(gitDir, "objects", oid[:2])
	if err := os.MkdirAll(objDir, 0755); err != nil {
		t.Fatalf("failed to create object dir: %v", err)
	}

	objPath := filepath.Join(objDir, oid[2:])
	if err := os.WriteFile(objPath, compressed, 0644); err != nil {
		t.Fatalf("failed to write loose object: %v", err)
	}
	return oid
}

func TestClassificationThreeWay(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0755); err != nil {
		t.Fatalf("failed to setup git dir: %v", err)
	}

	repo := &repository.Repository{
		WorktreeRoot: tempDir,
		GitDir:       gitDir,
		CommonDir:    gitDir,
		IsBare:       false,
	}

	// 1. Create active blob & commit (on HEAD -> main)
	activeBlobOID := writeLooseObject(t, gitDir, object.TypeBlob, []byte("active secret content"))
	bActive := hexTo20Bytes(activeBlobOID)
	activeTreePayload := append([]byte("100644 active.txt\x00"), bActive[:]...)
	activeTreeOID := writeLooseObject(t, gitDir, object.TypeTree, activeTreePayload)

	activeCommitPayload := []byte(fmt.Sprintf("tree %s\nauthor Alice <alice@example.com> 100 +0000\ncommitter Alice <alice@example.com> 100 +0000\n\nActive Commit\n", activeTreeOID))
	activeCommitOID := writeLooseObject(t, gitDir, object.TypeCommit, activeCommitPayload)

	// Set HEAD -> refs/heads/main -> activeCommitOID
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		t.Fatalf("failed to write HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(activeCommitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write main ref: %v", err)
	}

	// 2. Create historical blob & commit (on refs/heads/old_branch only, not on main)
	histBlobOID := writeLooseObject(t, gitDir, object.TypeBlob, []byte("historical secret content"))
	bHist := hexTo20Bytes(histBlobOID)
	histTreePayload := append([]byte("100644 old.txt\x00"), bHist[:]...)
	histTreeOID := writeLooseObject(t, gitDir, object.TypeTree, histTreePayload)

	histCommitPayload := []byte(fmt.Sprintf("tree %s\nauthor Bob <bob@example.com> 100 +0000\ncommitter Bob <bob@example.com> 100 +0000\n\nHistorical Commit\n", histTreeOID))
	histCommitOID := writeLooseObject(t, gitDir, object.TypeCommit, histCommitPayload)

	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "old_branch"), []byte(histCommitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write old_branch ref: %v", err)
	}

	// 3. Create zombie/dangling blob (unreferenced orphan on disk)
	zombieBlobOID := writeLooseObject(t, gitDir, object.TypeBlob, []byte("zombie orphan secret"))

	store := repository.NewLooseStore(gitDir, 0)
	result, err := ClassifyRepository(repo, store, DefaultTraversalLimits())
	if err != nil {
		t.Fatalf("ClassifyRepository failed: %v", err)
	}

	// Invariant §9: Check ACTIVE blob
	if len(result.ActiveBlobs) != 1 || result.ActiveBlobs[0] != activeBlobOID {
		t.Errorf("expected ActiveBlobs=[%s], got %v", activeBlobOID, result.ActiveBlobs)
	}

	// Invariant §9: Check HISTORICAL blob
	if len(result.HistoricalBlobs) != 1 || result.HistoricalBlobs[0] != histBlobOID {
		t.Errorf("expected HistoricalBlobs=[%s], got %v", histBlobOID, result.HistoricalBlobs)
	}

	// Invariant §9: Check ZOMBIE blob
	if len(result.ZombieBlobs) != 1 || result.ZombieBlobs[0] != zombieBlobOID {
		t.Errorf("expected ZombieBlobs=[%s], got %v", zombieBlobOID, result.ZombieBlobs)
	}
}

func TestHEADIsolation(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0755); err != nil {
		t.Fatalf("failed to setup git dir: %v", err)
	}

	repo := &repository.Repository{
		WorktreeRoot: tempDir,
		GitDir:       gitDir,
		CommonDir:    gitDir,
		IsBare:       false,
	}

	// Empty HEAD commit
	emptyTreePayload := []byte{}
	emptyTreeOID := writeLooseObject(t, gitDir, object.TypeTree, emptyTreePayload)
	headCommitPayload := []byte(fmt.Sprintf("tree %s\nauthor A <a@b.c> 100 +0000\ncommitter A <a@b.c> 100 +0000\n\nEmpty Head\n", emptyTreeOID))
	headCommitOID := writeLooseObject(t, gitDir, object.TypeCommit, headCommitPayload)

	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		t.Fatalf("failed to write HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(headCommitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write main ref: %v", err)
	}

	// Branch with a secret blob
	secretBlobOID := writeLooseObject(t, gitDir, object.TypeBlob, []byte("super secret"))
	bSec := hexTo20Bytes(secretBlobOID)
	branchTreePayload := append([]byte("100644 secret.txt\x00"), bSec[:]...)
	branchTreeOID := writeLooseObject(t, gitDir, object.TypeTree, branchTreePayload)
	branchCommitPayload := []byte(fmt.Sprintf("tree %s\nauthor A <a@b.c> 100 +0000\ncommitter A <a@b.c> 100 +0000\n\nBranch Commit\n", branchTreeOID))
	branchCommitOID := writeLooseObject(t, gitDir, object.TypeCommit, branchCommitPayload)

	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "feature"), []byte(branchCommitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write feature ref: %v", err)
	}

	store := repository.NewLooseStore(gitDir, 0)
	result, err := ClassifyRepository(repo, store, DefaultTraversalLimits())
	if err != nil {
		t.Fatalf("ClassifyRepository failed: %v", err)
	}

	// Invariant: secretBlob must NEVER be ACTIVE merely because feature branch exists
	if len(result.ActiveBlobs) != 0 {
		t.Errorf("expected 0 active blobs on empty HEAD, got %v", result.ActiveBlobs)
	}
	if len(result.HistoricalBlobs) != 1 || result.HistoricalBlobs[0] != secretBlobOID {
		t.Errorf("expected secretBlob in HistoricalBlobs, got %v", result.HistoricalBlobs)
	}
}

func TestDanglingIndependentScan(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0755); err != nil {
		t.Fatalf("failed to setup git dir: %v", err)
	}

	// Write 1 reachable blob and 1 orphan/dangling blob
	reachableBlob := writeLooseObject(t, gitDir, object.TypeBlob, []byte("reachable"))
	orphanBlob := writeLooseObject(t, gitDir, object.TypeBlob, []byte("dangling orphan"))

	rb := hexTo20Bytes(reachableBlob)
	treePayload := append([]byte("100644 file.txt\x00"), rb[:]...)
	treeOID := writeLooseObject(t, gitDir, object.TypeTree, treePayload)
	commitPayload := []byte(fmt.Sprintf("tree %s\nauthor A <a@b.c> 100 +0000\ncommitter A <a@b.c> 100 +0000\n\nC\n", treeOID))
	commitOID := writeLooseObject(t, gitDir, object.TypeCommit, commitPayload)

	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		t.Fatalf("failed to write HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(commitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write main ref: %v", err)
	}

	store := repository.NewLooseStore(gitDir, 0)
	allLoose, _, err := EnumerateLooseObjects(gitDir, store)
	if err != nil {
		t.Fatalf("EnumerateLooseObjects failed: %v", err)
	}

	// 4 physical objects: reachableBlob, orphanBlob, treeOID, commitOID
	if len(allLoose) != 4 {
		t.Fatalf("expected 4 physical loose objects, got %d", len(allLoose))
	}

	reachableMap := map[string]bool{
		commitOID:     true,
		treeOID:       true,
		reachableBlob: true,
	}

	dangling, _ := FindDangling(allLoose, reachableMap)
	if len(dangling) != 1 || dangling[0].OID != orphanBlob {
		t.Errorf("expected dangling object [%s], got %v", orphanBlob, dangling)
	}
}

func TestMalformedDanglingObject(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")

	// Write a corrupt / truncated file inside .git/objects/ab/12345678901234567890123456789012345678
	objDir := filepath.Join(gitDir, "objects", "ab")
	if err := os.MkdirAll(objDir, 0755); err != nil {
		t.Fatalf("failed to create obj dir: %v", err)
	}
	corruptOID := "ab12345678901234567890123456789012345678"
	if err := os.WriteFile(filepath.Join(objDir, "12345678901234567890123456789012345678"), []byte("NOT_ZLIB_CORRUPT"), 0644); err != nil {
		t.Fatalf("failed to write corrupt object: %v", err)
	}

	store := repository.NewLooseStore(gitDir, 0)
	physicalObjects, anomalies, err := EnumerateLooseObjects(gitDir, store)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Invariant §8: Malformed physical object must remain visible
	if len(physicalObjects) != 1 || !physicalObjects[0].Malformed {
		t.Errorf("expected 1 malformed physical object, got %v", physicalObjects)
	}
	if len(anomalies) != 1 || anomalies[0].Type != AnomalyCorruptedLooseObject {
		t.Errorf("expected AnomalyCorruptedLooseObject recorded, got %v", anomalies)
	}

	// Dangling test
	dangling, danglingAnomalies := FindDangling(physicalObjects, map[string]bool{})
	if len(dangling) != 1 || dangling[0].OID != corruptOID {
		t.Errorf("expected malformed object to remain visible in dangling results: %v", dangling)
	}
	if len(danglingAnomalies) != 1 {
		t.Errorf("expected dangling anomaly recorded")
	}
}

func TestUnresolvedNotZombie(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0755); err != nil {
		t.Fatalf("failed to setup git dir: %v", err)
	}

	repo := &repository.Repository{
		WorktreeRoot: tempDir,
		GitDir:       gitDir,
		CommonDir:    gitDir,
		IsBare:       false,
	}

	// Tree references missingBlobOID which is NOT on disk in loose storage
	missingBlobOID := "1111111111111111111111111111111111111111"
	mb := hexTo20Bytes(missingBlobOID)
	treePayload := append([]byte("100644 missing.txt\x00"), mb[:]...)
	treeOID := writeLooseObject(t, gitDir, object.TypeTree, treePayload)

	commitPayload := []byte(fmt.Sprintf("tree %s\nauthor A <a@b.c> 100 +0000\ncommitter A <a@b.c> 100 +0000\n\nCommit\n", treeOID))
	commitOID := writeLooseObject(t, gitDir, object.TypeCommit, commitPayload)

	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		t.Fatalf("failed to write HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(commitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write main ref: %v", err)
	}

	store := repository.NewLooseStore(gitDir, 0)
	result, err := ClassifyRepository(repo, store, DefaultTraversalLimits())
	if err != nil {
		t.Fatalf("ClassifyRepository failed: %v", err)
	}

	// Invariant §9: Unresolved missing blob must NEVER be placed in ZombieBlobs
	for _, z := range result.ZombieBlobs {
		if z == missingBlobOID {
			t.Fatalf("CRITICAL BUG: unresolved missing blob %s was incorrectly classified as ZOMBIE!", missingBlobOID)
		}
	}

	// Must be captured in UnresolvedOIDs
	foundUnresolved := false
	for _, u := range result.UnresolvedOIDs {
		if u == missingBlobOID {
			foundUnresolved = true
		}
	}
	if !foundUnresolved {
		t.Errorf("expected missing blob %s in UnresolvedOIDs, got %v", missingBlobOID, result.UnresolvedOIDs)
	}
}

func TestDeterministicSorting(t *testing.T) {
	// Verify that result lists are strictly sorted
	res := &ClassificationResult{
		ActiveBlobs:     []string{"bbb", "aaa", "ccc"},
		HistoricalBlobs: []string{"zzz", "aaa"},
		ZombieBlobs:     []string{"444", "111", "222"},
	}
	sort.Strings(res.ActiveBlobs)
	sort.Strings(res.HistoricalBlobs)
	sort.Strings(res.ZombieBlobs)

	if !sort.StringsAreSorted(res.ActiveBlobs) || !sort.StringsAreSorted(res.HistoricalBlobs) || !sort.StringsAreSorted(res.ZombieBlobs) {
		t.Errorf("slices must be sorted")
	}
}
