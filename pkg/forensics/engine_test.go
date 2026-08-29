package forensics

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gitforensics/pkg/detect"
	"gitforensics/pkg/object"
	"gitforensics/pkg/traversal"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func compressZlib(data []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func hexTo20Bytes(h string) [20]byte {
	b, _ := hex.DecodeString(h)
	var arr [20]byte
	copy(arr[:], b)
	return arr
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

func TestForensicsEngineEndToEnd(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0755); err != nil {
		t.Fatalf("failed to setup git dir: %v", err)
	}

	// 1. ACTIVE secret blob on HEAD
	activeSecretPayload := []byte("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n")
	activeBlobOID := writeLooseObject(t, gitDir, object.TypeBlob, activeSecretPayload)
	bActive := hexTo20Bytes(activeBlobOID)
	activeTreePayload := append([]byte("100644 config.env\x00"), bActive[:]...)
	activeTreeOID := writeLooseObject(t, gitDir, object.TypeTree, activeTreePayload)
	activeCommitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Alice <alice@example.com> 1700000000 +0000\ncommitter Alice <alice@example.com> 1700000000 +0000\n\nActive Commit\n",
		activeTreeOID,
	))
	activeCommitOID := writeLooseObject(t, gitDir, object.TypeCommit, activeCommitPayload)

	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		t.Fatalf("failed to write HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(activeCommitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write main ref: %v", err)
	}

	// 2. HISTORICAL secret on feature branch (GitHub token)
	histSecretPayload := []byte("gh_token = \"ghp_123456789012345678901234567890123456\"\n")
	histBlobOID := writeLooseObject(t, gitDir, object.TypeBlob, histSecretPayload)
	bHist := hexTo20Bytes(histBlobOID)
	histTreePayload := append([]byte("100644 token.txt\x00"), bHist[:]...)
	histTreeOID := writeLooseObject(t, gitDir, object.TypeTree, histTreePayload)
	histCommitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Bob <bob@example.com> 1700001000 +0000\ncommitter Bob <bob@example.com> 1700001000 +0000\n\nBranch Commit\n",
		histTreeOID,
	))
	histCommitOID := writeLooseObject(t, gitDir, object.TypeCommit, histCommitPayload)
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "feature"), []byte(histCommitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write feature ref: %v", err)
	}

	// 3. ZOMBIE secret (Private Key unreferenced orphan on disk)
	zombieSecretPayload := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----\n")
	zombieBlobOID := writeLooseObject(t, gitDir, object.TypeBlob, zombieSecretPayload)

	// Run forensic scan
	report, err := RunScan(ScanOptions{
		RepoPath:      tempDir,
		MinConfidence: detect.TierLow,
	})
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}

	if report.Summary.TotalFindingsCount != 3 {
		t.Fatalf("expected 3 total findings, got %d", report.Summary.TotalFindingsCount)
	}

	// Verify exposures
	foundActive := false
	foundHistorical := false
	foundZombie := false

	for _, f := range report.Findings {
		// Assert zero raw secret leakage
		if strings.Contains(f.Redacted, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("raw AWS secret leaked in redacted field: %s", f.Redacted)
		}
		if strings.Contains(f.Redacted, "ghp_123456789012345678901234567890123456") {
			t.Errorf("raw GitHub token leaked in redacted field: %s", f.Redacted)
		}
		if f.PatternName == "Private Key" && f.Redacted != detect.RedactedPrivateKeyString {
			t.Errorf("PEM private key must use zero-reveal redaction %q, got %s", detect.RedactedPrivateKeyString, f.Redacted)
		}

		// Assert fingerprint != blob ID
		if f.Fingerprint == f.BlobID {
			t.Errorf("CRITICAL: secret fingerprint must NOT equal Git blob ID")
		}

		// Assert deterministic finding ID calculation
		expectedID, expectedFull := ComputeFindingID(f.BlobID, f.ByteOffset, f.PatternName)
		if f.ID != expectedID || f.FullDigest != expectedFull {
			t.Errorf("finding ID mismatch: expected %s / %s, got %s / %s", expectedID, expectedFull, f.ID, f.FullDigest)
		}

		switch f.Exposure {
		case traversal.StateActive:
			if f.BlobID == activeBlobOID {
				foundActive = true
				if len(f.Occurrences) != 1 || f.Occurrences[0].Path != "config.env" {
					t.Errorf("active occurrence mismatch: %+v", f.Occurrences)
				}
			}
		case traversal.StateHistorical:
			if f.BlobID == histBlobOID {
				foundHistorical = true
			}
		case traversal.StateZombie:
			if f.BlobID == zombieBlobOID {
				foundZombie = true
				if len(f.Occurrences) != 0 {
					t.Errorf("zombie finding must have 0 occurrences, got %d", len(f.Occurrences))
				}
			}
		}
	}

	if !foundActive {
		t.Errorf("expected active finding not detected")
	}
	if !foundHistorical {
		t.Errorf("expected historical finding not detected")
	}
	if !foundZombie {
		t.Errorf("expected zombie finding not detected")
	}

	// 4. Test JSON formatting
	jsonBytes, err := FormatJSON(report)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}
	var unmarshaled ScanReport
	if err := json.Unmarshal(jsonBytes, &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal generated JSON: %v", err)
	}
	if unmarshaled.SchemaVersion != "1.0" {
		t.Errorf("expected schemaVersion 1.0, got %s", unmarshaled.SchemaVersion)
	}

	// 5. Test Explain Round-trip with both 16-hex and 64-hex IDs
	for _, f := range report.Findings {
		// 16-hex ID
		res16, err16 := ExplainFinding(tempDir, f.ID)
		if err16 != nil {
			t.Fatalf("ExplainFinding(16) failed for ID %s: %v", f.ID, err16)
		}
		if res16.Finding.ID != f.ID {
			t.Errorf("explain ID mismatch: expected %s, got %s", f.ID, res16.Finding.ID)
		}

		// 64-hex ID
		res64, err64 := ExplainFinding(tempDir, f.FullDigest)
		if err64 != nil {
			t.Fatalf("ExplainFinding(64) failed for digest %s: %v", f.FullDigest, err64)
		}
		if res64.Finding.FullDigest != f.FullDigest {
			t.Errorf("explain digest mismatch: expected %s, got %s", f.FullDigest, res64.Finding.FullDigest)
		}
	}

	// Invalid ID -> explain error
	_, errInvalid := ExplainFinding(tempDir, "invalid_id_not_16_hex")
	if errInvalid == nil {
		t.Errorf("expected error for malformed finding ID")
	}
}

func TestDeduplicationRules(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0755); err != nil {
		t.Fatalf("failed to setup git dir: %v", err)
	}

	secretLiteral := []byte("AKIAIOSFODNN7EXAMPLE")

	// Same secret in TWO different blobs (different file headers or whitespace)
	blob1Payload := append([]byte("header 1\n"), secretLiteral...)
	blob2Payload := append([]byte("header 2\n"), secretLiteral...)

	blob1OID := writeLooseObject(t, gitDir, object.TypeBlob, blob1Payload)
	blob2OID := writeLooseObject(t, gitDir, object.TypeBlob, blob2Payload)

	if blob1OID == blob2OID {
		t.Fatalf("blob OIDs must be different for test")
	}

	b1 := hexTo20Bytes(blob1OID)
	b2 := hexTo20Bytes(blob2OID)

	// Tree references blob1 twice under different paths: a.txt and b.txt
	var treePayload []byte
	treePayload = append(treePayload, []byte("100644 a.txt\x00")...)
	treePayload = append(treePayload, b1[:]...)
	treePayload = append(treePayload, []byte("100644 b.txt\x00")...)
	treePayload = append(treePayload, b1[:]...)
	treePayload = append(treePayload, []byte("100644 c.txt\x00")...)
	treePayload = append(treePayload, b2[:]...)

	treeOID := writeLooseObject(t, gitDir, object.TypeTree, treePayload)
	commitPayload := []byte(fmt.Sprintf("tree %s\nauthor A <a@b.c> 100 +0000\ncommitter A <a@b.c> 100 +0000\n\nC\n", treeOID))
	commitOID := writeLooseObject(t, gitDir, object.TypeCommit, commitPayload)

	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		t.Fatalf("failed to write HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(commitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write main ref: %v", err)
	}

	report, err := RunScan(ScanOptions{RepoPath: tempDir, MinConfidence: detect.TierLow})
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}

	// Invariant §11:
	// 1. Same literal secret in different blob IDs -> SEPARATE findings (2 findings total: 1 for blob1, 1 for blob2).
	// 2. Same blob referenced under multiple paths -> ONE finding with occurrences aggregated (blob1 has 2 occurrences: a.txt and b.txt).
	if len(report.Findings) != 2 {
		t.Fatalf("expected exactly 2 findings, got %d", len(report.Findings))
	}

	var findingBlob1 *Finding
	for i := range report.Findings {
		if report.Findings[i].BlobID == blob1OID {
			findingBlob1 = &report.Findings[i]
		}
	}
	if findingBlob1 == nil {
		t.Fatalf("missing finding for blob1")
	}

	if len(findingBlob1.Occurrences) != 2 {
		t.Errorf("expected 2 occurrences for blob1, got %d", len(findingBlob1.Occurrences))
	}
}

func TestMinConfidenceFiltering(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0755); err != nil {
		t.Fatalf("failed to setup git dir: %v", err)
	}

	// Write Slack token (Base score 40 -> MEDIUM tier)
	slackPayload := []byte("slack_token = 'xoxb-123456789012-123456789012-abcdefABCDEF'\n")
	blobOID := writeLooseObject(t, gitDir, object.TypeBlob, slackPayload)
	b := hexTo20Bytes(blobOID)
	treePayload := append([]byte("100644 app.js\x00"), b[:]...)
	treeOID := writeLooseObject(t, gitDir, object.TypeTree, treePayload)
	commitPayload := []byte(fmt.Sprintf("tree %s\nauthor A <a@b.c> 100 +0000\ncommitter A <a@b.c> 100 +0000\n\nC\n", treeOID))
	commitOID := writeLooseObject(t, gitDir, object.TypeCommit, commitPayload)

	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		t.Fatalf("failed to write HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(commitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write main ref: %v", err)
	}

	// Scan with MinConfidence = CRITICAL (which filters the medium finding from display)
	report, err := RunScan(ScanOptions{
		RepoPath:      tempDir,
		MinConfidence: detect.TierCritical,
	})
	if err != nil {
		t.Fatalf("RunScan failed: %v", err)
	}

	// Invariant §13: DisplayedFindings is 0, but TotalFindingsCount is 1
	if len(report.Findings) != 0 {
		t.Errorf("expected 0 displayed findings under critical filter, got %d", len(report.Findings))
	}
	if report.Summary.TotalFindingsCount != 1 {
		t.Errorf("expected TotalFindingsCount == 1, got %d", report.Summary.TotalFindingsCount)
	}
	if len(report.AllFindings) != 1 {
		t.Errorf("expected AllFindings to retain all 1 finding, got %d", len(report.AllFindings))
	}
}
