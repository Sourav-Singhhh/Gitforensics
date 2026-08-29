package forensics

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"gitforensics/pkg/detect"
	"gitforensics/pkg/object"
	"gitforensics/pkg/repository"
	"gitforensics/pkg/traversal"
	"os"
	"path/filepath"
	"testing"
)

// Helper: compress data with zlib
func packZlibCompress(data []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// Helper: encode pack entry header
func packEntryHeader(objType int, size int64) []byte {
	var out []byte
	b := byte((objType&0x07)<<4) | byte(size&0x0F)
	size >>= 4
	for size > 0 {
		b |= 0x80
		out = append(out, b)
		b = byte(size & 0x7F)
		size >>= 7
	}
	out = append(out, b)
	return out
}

// Helper: create a valid packfile containing given objects
type packItem struct {
	objType int
	payload []byte
}

func writePackFile(t *testing.T, packDir string, packName string, items []packItem) string {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("PACK")
	_ = binary.Write(&buf, binary.BigEndian, uint32(2))
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(items)))

	for _, item := range items {
		hdr := packEntryHeader(item.objType, int64(len(item.payload)))
		comp := packZlibCompress(item.payload)
		buf.Write(hdr)
		buf.Write(comp)
	}

	h := sha1.New()
	h.Write(buf.Bytes())
	checksum := h.Sum(nil)
	buf.Write(checksum)

	if err := os.MkdirAll(packDir, 0755); err != nil {
		t.Fatalf("failed to create pack dir: %v", err)
	}

	packPath := filepath.Join(packDir, packName)
	if err := os.WriteFile(packPath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("failed to write packfile: %v", err)
	}
	return packPath
}

func TestPackedRepositoryEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	packDir := filepath.Join(gitDir, "objects", "pack")
	headsDir := filepath.Join(gitDir, "refs", "heads")
	if err := os.MkdirAll(headsDir, 0755); err != nil {
		t.Fatalf("failed to create heads dir: %v", err)
	}

	synthAKIA := "AKIA" + "0123456789ABCDEF"
	synthGHP := "ghp_" + "0123456789ABCDEFGHIJKLMNOPQRSTUV" + "WXYZ"
	synthSlack := "xoxb-" + "123456789012" + "-" + "123456789012" + "-" + "abcdefABCDEF"

	// 1. ACTIVE secret blob on HEAD (stored inside pack-1.pack)
	activeSecretPayload := []byte("export AWS_ACCESS_KEY_ID=" + synthAKIA + "\n")
	activeBlobOID := object.ComputeEnvelopeSHA1(object.TypeBlob, int64(len(activeSecretPayload)), activeSecretPayload)
	bActive := hexTo20Bytes(activeBlobOID)
	activeTreePayload := append([]byte("100644 config.env\x00"), bActive[:]...)
	activeTreeOID := object.ComputeEnvelopeSHA1(object.TypeTree, int64(len(activeTreePayload)), activeTreePayload)
	activeCommitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Alice <alice@example.com> 1700000000 +0000\ncommitter Alice <alice@example.com> 1700000000 +0000\n\nActive Commit\n",
		activeTreeOID,
	))
	activeCommitOID := object.ComputeEnvelopeSHA1(object.TypeCommit, int64(len(activeCommitPayload)), activeCommitPayload)

	// 2. HISTORICAL secret on feature branch (stored inside pack-1.pack)
	histSecretPayload := []byte("gh_token = \"" + synthGHP + "\"\n")
	histBlobOID := object.ComputeEnvelopeSHA1(object.TypeBlob, int64(len(histSecretPayload)), histSecretPayload)
	bHist := hexTo20Bytes(histBlobOID)
	histTreePayload := append([]byte("100644 token.txt\x00"), bHist[:]...)
	histTreeOID := object.ComputeEnvelopeSHA1(object.TypeTree, int64(len(histTreePayload)), histTreePayload)
	histCommitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Bob <bob@example.com> 1700001000 +0000\ncommitter Bob <bob@example.com> 1700001000 +0000\n\nBranch Commit\n",
		histTreeOID,
	))
	histCommitOID := object.ComputeEnvelopeSHA1(object.TypeCommit, int64(len(histCommitPayload)), histCommitPayload)

	// 3. ZOMBIE secret (stored inside pack-2.pack as an unreferenced packed blob)
	zombieSecretPayload := []byte("slack_token = \"" + synthSlack + "\"\n")
	zombieBlobOID := object.ComputeEnvelopeSHA1(object.TypeBlob, int64(len(zombieSecretPayload)), zombieSecretPayload)

	// Write pack-1.pack with Active & Historical DAG objects
	writePackFile(t, packDir, "pack-1.pack", []packItem{
		{repository.PackTypeBlob, activeSecretPayload},
		{repository.PackTypeTree, activeTreePayload},
		{repository.PackTypeCommit, activeCommitPayload},
		{repository.PackTypeBlob, histSecretPayload},
		{repository.PackTypeTree, histTreePayload},
		{repository.PackTypeCommit, histCommitPayload},
	})

	// Write pack-2.pack with unreachable Zombie blob
	writePackFile(t, packDir, "pack-2.pack", []packItem{
		{repository.PackTypeBlob, zombieSecretPayload},
	})

	// Set HEAD -> main and refs/heads/feature
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		t.Fatalf("failed to write HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(headsDir, "main"), []byte(activeCommitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write main ref: %v", err)
	}
	if err := os.WriteFile(filepath.Join(headsDir, "feature"), []byte(histCommitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write feature ref: %v", err)
	}

	// Execute Scan
	report, err := RunScan(ScanOptions{
		RepoPath:      tempDir,
		MinConfidence: detect.TierLow,
	})
	if err != nil {
		t.Fatalf("RunScan on packed repo failed: %v", err)
	}

	if report.Summary.TotalFindingsCount != 3 {
		t.Fatalf("expected 3 total findings, got %d", report.Summary.TotalFindingsCount)
	}

	// Verify Exposure Classifications
	foundActive := false
	foundHistorical := false
	foundZombie := false

	for _, f := range report.Findings {
		switch f.Exposure {
		case traversal.StateActive:
			if f.BlobID == activeBlobOID {
				foundActive = true
			}
		case traversal.StateHistorical:
			if f.BlobID == histBlobOID {
				foundHistorical = true
			}
		case traversal.StateZombie:
			if f.BlobID == zombieBlobOID {
				foundZombie = true
			}
		}
	}

	if !foundActive {
		t.Errorf("expected packed ACTIVE blob %s to be classified as ACTIVE", activeBlobOID)
	}
	if !foundHistorical {
		t.Errorf("expected packed HISTORICAL blob %s to be classified as HISTORICAL", histBlobOID)
	}
	if !foundZombie {
		t.Errorf("expected packed unreferenced blob %s to be classified as ZOMBIE", zombieBlobOID)
	}

	// Determinism Check: Scan again and ensure identical report
	report2, err := RunScan(ScanOptions{
		RepoPath:      tempDir,
		MinConfidence: detect.TierLow,
	})
	if err != nil {
		t.Fatalf("second RunScan failed: %v", err)
	}

	if report.Summary.TotalFindingsCount != report2.Summary.TotalFindingsCount {
		t.Errorf("non-deterministic findings count")
	}
	for i := range report.Findings {
		if report.Findings[i].ID != report2.Findings[i].ID {
			t.Errorf("non-deterministic finding ordering: %s vs %s", report.Findings[i].ID, report2.Findings[i].ID)
		}
	}
}

func TestMixedLooseAndPackedRepository(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	packDir := filepath.Join(gitDir, "objects", "pack")
	headsDir := filepath.Join(gitDir, "refs", "heads")
	if err := os.MkdirAll(headsDir, 0755); err != nil {
		t.Fatalf("failed to create heads dir: %v", err)
	}

	synthAKIA := "AKIA" + "0123456789ABCDEF"

	// 1. Packed blob
	packedBlobPayload := []byte("secret = '" + synthAKIA + "'\n")
	packedBlobOID := object.ComputeEnvelopeSHA1(object.TypeBlob, int64(len(packedBlobPayload)), packedBlobPayload)
	writePackFile(t, packDir, "data.pack", []packItem{
		{repository.PackTypeBlob, packedBlobPayload},
	})

	// 2. Loose tree pointing to packed blob
	bPacked := hexTo20Bytes(packedBlobOID)
	treePayload := append([]byte("100644 secret.py\x00"), bPacked[:]...)
	treeOID := writeLooseObject(t, gitDir, object.TypeTree, treePayload)

	// 3. Loose commit pointing to loose tree
	commitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Alice <alice@example.com> 1700000000 +0000\ncommitter Alice <alice@example.com> 1700000000 +0000\n\nMixed commit\n",
		treeOID,
	))
	commitOID := writeLooseObject(t, gitDir, object.TypeCommit, commitPayload)

	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		t.Fatalf("failed to write HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(headsDir, "main"), []byte(commitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write main ref: %v", err)
	}

	report, err := RunScan(ScanOptions{
		RepoPath: tempDir,
	})
	if err != nil {
		t.Fatalf("RunScan failed on mixed repository: %v", err)
	}

	if report.Summary.TotalFindingsCount != 1 {
		t.Fatalf("expected 1 finding, got %d", report.Summary.TotalFindingsCount)
	}
	if report.Findings[0].Exposure != traversal.StateActive {
		t.Errorf("expected ACTIVE exposure for packed blob via loose commit/tree, got %s", report.Findings[0].Exposure)
	}
}

func TestLinkedWorktreePackStorage(t *testing.T) {
	tempDir := t.TempDir()

	// Common administrative directory (bare repo / main admin store)
	commonDir := filepath.Join(tempDir, "main_repo", ".git")
	commonPackDir := filepath.Join(commonDir, "objects", "pack")
	commonHeadsDir := filepath.Join(commonDir, "refs", "heads")
	if err := os.MkdirAll(commonHeadsDir, 0755); err != nil {
		t.Fatalf("failed to create common heads dir: %v", err)
	}

	synthAKIA := "AKIA" + "0123456789ABCDEF"

	// Packed secret blob in shared CommonDir
	secretPayload := []byte("secret = '" + synthAKIA + "'\n")
	blobOID := object.ComputeEnvelopeSHA1(object.TypeBlob, int64(len(secretPayload)), secretPayload)
	bBlob := hexTo20Bytes(blobOID)
	treePayload := append([]byte("100644 file.txt\x00"), bBlob[:]...)
	treeOID := object.ComputeEnvelopeSHA1(object.TypeTree, int64(len(treePayload)), treePayload)
	commitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Worktree <wt@example.com> 1700000000 +0000\ncommitter Worktree <wt@example.com> 1700000000 +0000\n\nWT Commit\n",
		treeOID,
	))
	commitOID := object.ComputeEnvelopeSHA1(object.TypeCommit, int64(len(commitPayload)), commitPayload)

	writePackFile(t, commonPackDir, "shared.pack", []packItem{
		{repository.PackTypeBlob, secretPayload},
		{repository.PackTypeTree, treePayload},
		{repository.PackTypeCommit, commitPayload},
	})

	// Linked worktree working tree directory
	worktreeRoot := filepath.Join(tempDir, "wt")
	if err := os.MkdirAll(worktreeRoot, 0755); err != nil {
		t.Fatalf("failed to create worktree root: %v", err)
	}

	// Linked worktree per-worktree admin directory inside commonDir/worktrees/wt
	wtGitDir := filepath.Join(commonDir, "worktrees", "wt")
	if err := os.MkdirAll(wtGitDir, 0755); err != nil {
		t.Fatalf("failed to create wt git dir: %v", err)
	}

	// write commondir file pointing back to commonDir
	if err := os.WriteFile(filepath.Join(wtGitDir, "commondir"), []byte("../../\n"), 0644); err != nil {
		t.Fatalf("failed to write commondir: %v", err)
	}

	// write worktree HEAD pointing to ref
	if err := os.WriteFile(filepath.Join(wtGitDir, "HEAD"), []byte("ref: refs/heads/worktree-branch\n"), 0644); err != nil {
		t.Fatalf("failed to write wt HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(commonHeadsDir, "worktree-branch"), []byte(commitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write worktree branch ref: %v", err)
	}

	// write worktreeRoot/.git file containing "gitdir: <path>"
	if err := os.WriteFile(filepath.Join(worktreeRoot, ".git"), []byte("gitdir: "+wtGitDir+"\n"), 0644); err != nil {
		t.Fatalf("failed to write .git file: %v", err)
	}

	// Scan from worktreeRoot
	report, err := RunScan(ScanOptions{
		RepoPath: worktreeRoot,
	})
	if err != nil {
		t.Fatalf("RunScan on linked worktree failed: %v", err)
	}

	if report.Summary.TotalFindingsCount != 1 {
		t.Fatalf("expected 1 finding from linked worktree, got %d", report.Summary.TotalFindingsCount)
	}
	if report.Findings[0].Exposure != traversal.StateActive {
		t.Errorf("expected ACTIVE exposure in linked worktree scan, got %s", report.Findings[0].Exposure)
	}
}
