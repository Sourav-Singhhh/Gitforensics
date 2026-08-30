package main

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gitforensics/pkg/detect"
	"gitforensics/pkg/forensics"
	"gitforensics/pkg/object"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Helper: compress data with zlib
func testCompressZlib(data []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// Helper: write loose git object to disk
func testWriteLooseObject(t *testing.T, gitDir string, objType object.ObjectType, payload []byte) string {
	t.Helper()
	oid := object.ComputeEnvelopeSHA1(objType, int64(len(payload)), payload)
	header := fmt.Sprintf("%s %d\x00", objType, len(payload))
	envelope := append([]byte(header), payload...)
	compressed := testCompressZlib(envelope)

	objDir := filepath.Join(gitDir, "objects", oid[:2])
	if err := os.MkdirAll(objDir, 0755); err != nil {
		t.Fatalf("failed to create object dir: %v", err)
	}
	objPath := filepath.Join(objDir, oid[2:])
	if err := os.WriteFile(objPath, compressed, 0644); err != nil {
		t.Fatalf("failed to write object: %v", err)
	}
	return oid
}

func testHexTo20Bytes(s string) [20]byte {
	b, _ := hex.DecodeString(s)
	var out [20]byte
	copy(out[:], b)
	return out
}

// Setup a clean git repository
func setupCleanRepo(t *testing.T) string {
	t.Helper()
	repoDir := t.TempDir()
	gitDir := filepath.Join(repoDir, ".git")
	headsDir := filepath.Join(gitDir, "refs", "heads")
	_ = os.MkdirAll(headsDir, 0755)

	blobPayload := []byte("Clean repository content with zero secrets.\n")
	blobOID := testWriteLooseObject(t, gitDir, object.TypeBlob, blobPayload)
	bBlob := testHexTo20Bytes(blobOID)
	treePayload := append([]byte("100644 readme.txt\x00"), bBlob[:]...)
	treeOID := testWriteLooseObject(t, gitDir, object.TypeTree, treePayload)
	commitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Alice <alice@example.com> 1700000000 +0000\ncommitter Alice <alice@example.com> 1700000000 +0000\n\nInitial clean commit\n",
		treeOID,
	))
	commitOID := testWriteLooseObject(t, gitDir, object.TypeCommit, commitPayload)

	_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644)
	_ = os.WriteFile(filepath.Join(headsDir, "main"), []byte(commitOID+"\n"), 0644)
	return repoDir
}

// Setup a repository with synthetic secret fixtures
func setupSecretRepo(t *testing.T) (string, string, string) {
	t.Helper()
	repoDir := t.TempDir()
	gitDir := filepath.Join(repoDir, ".git")
	headsDir := filepath.Join(gitDir, "refs", "heads")
	_ = os.MkdirAll(headsDir, 0755)

	// Safe synthetic fragment construction
	synthAKIA := "AKIA" + "0123456789ABCDEF"
	synthPEM := "-----BEGIN " + "RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEA0syntheticTestFixtureKeyMaterialOnlyDoNotUse123456789\n" +
		"-----END " + "RSA PRIVATE KEY-----\n"

	// 1. AWS Secret blob on HEAD (ACTIVE)
	awsPayload := []byte("aws_key = \"" + synthAKIA + "\"\n")
	awsBlobOID := testWriteLooseObject(t, gitDir, object.TypeBlob, awsPayload)
	bAWS := testHexTo20Bytes(awsBlobOID)

	// 2. PEM Private Key blob on HEAD (ACTIVE)
	pemPayload := []byte(synthPEM)
	pemBlobOID := testWriteLooseObject(t, gitDir, object.TypeBlob, pemPayload)
	bPEM := testHexTo20Bytes(pemBlobOID)

	treePayload := append([]byte("100644 creds.env\x00"), bAWS[:]...)
	treePayload = append(treePayload, append([]byte("100644 id_rsa\x00"), bPEM[:]...)...)
	treeOID := testWriteLooseObject(t, gitDir, object.TypeTree, treePayload)

	commitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Alice <alice@example.com> 1700000000 +0000\ncommitter Alice <alice@example.com> 1700000000 +0000\n\nCommit with credentials\n",
		treeOID,
	))
	commitOID := testWriteLooseObject(t, gitDir, object.TypeCommit, commitPayload)

	_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644)
	_ = os.WriteFile(filepath.Join(headsDir, "main"), []byte(commitOID+"\n"), 0644)

	return repoDir, synthAKIA, synthPEM
}

// Vector 1: Clean repository exit code 0 and empty arrays (§18)
func TestContract1_CleanRepo(t *testing.T) {
	repoDir := setupCleanRepo(t)
	var stdout, stderr bytes.Buffer

	code := runCLI([]string{"scan", repoDir, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit code 0 for clean repo, got %d (stderr: %s)", code, stderr.String())
	}

	var report forensics.ScanReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("failed to parse JSON: %v (raw: %s)", err, stdout.String())
	}

	if len(report.Findings) != 0 {
		t.Errorf("expected 0 findings for clean repo, got %d", len(report.Findings))
	}
	if report.Summary.TotalFindingsCount != 0 {
		t.Errorf("expected TotalFindingsCount == 0, got %d", report.Summary.TotalFindingsCount)
	}
	if report.CoverageGaps == nil {
		t.Errorf("expected non-nil coverageGaps array")
	}
	if report.StructuralAnomalies == nil {
		t.Errorf("expected non-nil structuralAnomalies array")
	}
}

// Vector 2: --min-confidence filtering exit code preservation (§18)
func TestContract2_MinConfidenceExitCode(t *testing.T) {
	repoDir, _, _ := setupSecretRepo(t)
	var stdout, stderr bytes.Buffer

	// Filter with CRITICAL: if findings are below critical, displayed findings is 0, but exit code MUST still be 1
	code := runCLI([]string{"scan", repoDir, "--json", "--min-confidence", "critical"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 when total findings exist regardless of filter, got %d", code)
	}

	var report forensics.ScanReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if report.Summary.TotalFindingsCount == 0 {
		t.Errorf("expected total findings > 0 in summary")
	}
}

// Vector 3: --json stdout/stderr purity (§18)
func TestContract3_JSONStdoutStderrPurity(t *testing.T) {
	repoDir, _, _ := setupSecretRepo(t)
	var stdout, stderr bytes.Buffer

	_ = runCLI([]string{"scan", repoDir, "--json"}, &stdout, &stderr)

	// stdout must be valid JSON starting with '{'
	trimmedStdout := bytes.TrimSpace(stdout.Bytes())
	if len(trimmedStdout) == 0 || trimmedStdout[0] != '{' || trimmedStdout[len(trimmedStdout)-1] != '}' {
		t.Errorf("stdout does not contain a single pure JSON document: %s", stdout.String())
	}

	var js map[string]interface{}
	if err := json.Unmarshal(trimmedStdout, &js); err != nil {
		t.Errorf("stdout failed JSON unmarshaling: %v", err)
	}
}

// Vector 4: Atomic JSON output on fatal error (§18)
func TestContract4_AtomicJSONOnFatalError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	nonExistentPath := filepath.Join(t.TempDir(), "does_not_exist_git_repo")

	code := runCLI([]string{"scan", nonExistentPath, "--json"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit code 2 for invalid repository path, got %d", code)
	}

	var report forensics.ScanReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("stdout on error was not valid atomic JSON: %v (raw: %s)", err, stdout.String())
	}
	if report.FatalError == nil {
		t.Errorf("expected fatalError field to be populated in JSON")
	}
}

// Vector 5: Deterministic finding ID generation (§18)
func TestContract5_DeterministicFindingID(t *testing.T) {
	repoDir, _, _ := setupSecretRepo(t)

	var stdout1, stderr1, stdout2, stderr2 bytes.Buffer
	_ = runCLI([]string{"scan", repoDir, "--json"}, &stdout1, &stderr1)
	_ = runCLI([]string{"scan", repoDir, "--json"}, &stdout2, &stderr2)

	var report1, report2 forensics.ScanReport
	_ = json.Unmarshal(stdout1.Bytes(), &report1)
	_ = json.Unmarshal(stdout2.Bytes(), &report2)

	if len(report1.Findings) != len(report2.Findings) {
		t.Fatalf("findings count mismatch: %d vs %d", len(report1.Findings), len(report2.Findings))
	}

	for i := range report1.Findings {
		if report1.Findings[i].ID != report2.Findings[i].ID {
			t.Errorf("finding ID mismatch at %d: %s vs %s", i, report1.Findings[i].ID, report2.Findings[i].ID)
		}
		if report1.Findings[i].FullDigest != report2.Findings[i].FullDigest {
			t.Errorf("finding FullDigest mismatch at %d: %s vs %s", i, report1.Findings[i].FullDigest, report2.Findings[i].FullDigest)
		}
	}
}

// Vector 6: Explain round-trip identity with full field-by-field verification (§18)
func TestContract6_ExplainRoundTrip(t *testing.T) {
	repoDir, _, _ := setupSecretRepo(t)
	var stdout, stderr bytes.Buffer

	_ = runCLI([]string{"scan", repoDir, "--json"}, &stdout, &stderr)
	var report forensics.ScanReport
	_ = json.Unmarshal(stdout.Bytes(), &report)

	if len(report.Findings) == 0 {
		t.Fatalf("expected findings in secret repo")
	}

	for _, targetFinding := range report.Findings {
		// 1. Test 16-hex short ID lookup
		var expStdout, expStderr bytes.Buffer
		code := runCLI([]string{"explain", targetFinding.ID, "--repo", repoDir, "--json"}, &expStdout, &expStderr)
		if code != 0 {
			t.Fatalf("explain with 16-hex ID failed: code=%d, stderr=%s", code, expStderr.String())
		}

		var expResult forensics.ExplainResult
		if err := json.Unmarshal(expStdout.Bytes(), &expResult); err != nil {
			t.Fatalf("failed to unmarshal explain result: %v", err)
		}

		// Comprehensive field-by-field verification
		ef := expResult.Finding
		if ef.ID != targetFinding.ID {
			t.Errorf("explain ID mismatch: %s vs %s", ef.ID, targetFinding.ID)
		}
		if ef.FullDigest != targetFinding.FullDigest {
			t.Errorf("explain FullDigest mismatch: %s vs %s", ef.FullDigest, targetFinding.FullDigest)
		}
		if ef.Category != targetFinding.Category {
			t.Errorf("explain Category mismatch: %s vs %s", ef.Category, targetFinding.Category)
		}
		if ef.PatternName != targetFinding.PatternName {
			t.Errorf("explain PatternName mismatch: %s vs %s", ef.PatternName, targetFinding.PatternName)
		}
		if ef.ConfidenceScore != targetFinding.ConfidenceScore {
			t.Errorf("explain ConfidenceScore mismatch: %d vs %d", ef.ConfidenceScore, targetFinding.ConfidenceScore)
		}
		if ef.ConfidenceTier != targetFinding.ConfidenceTier {
			t.Errorf("explain ConfidenceTier mismatch: %s vs %s", ef.ConfidenceTier, targetFinding.ConfidenceTier)
		}
		if ef.Exposure != targetFinding.Exposure {
			t.Errorf("explain Exposure mismatch: %s vs %s", ef.Exposure, targetFinding.Exposure)
		}
		if ef.BlobID != targetFinding.BlobID {
			t.Errorf("explain BlobID mismatch: %s vs %s", ef.BlobID, targetFinding.BlobID)
		}
		if ef.Redacted != targetFinding.Redacted {
			t.Errorf("explain Redacted mismatch: %s vs %s", ef.Redacted, targetFinding.Redacted)
		}
		if ef.Fingerprint != targetFinding.Fingerprint {
			t.Errorf("explain Fingerprint mismatch: %s vs %s", ef.Fingerprint, targetFinding.Fingerprint)
		}
		if len(ef.Occurrences) != len(targetFinding.Occurrences) {
			t.Errorf("explain Occurrences length mismatch: %d vs %d", len(ef.Occurrences), len(targetFinding.Occurrences))
		}
		if expResult.RecoveryExplanation == "" {
			t.Errorf("expected non-empty RecoveryExplanation")
		}

		// 2. Test 64-hex full digest lookup
		var expStdout64, expStderr64 bytes.Buffer
		code64 := runCLI([]string{"explain", targetFinding.FullDigest, "--repo", repoDir, "--json"}, &expStdout64, &expStderr64)
		if code64 != 0 {
			t.Fatalf("explain with 64-hex digest failed: code=%d, stderr=%s", code64, expStderr64.String())
		}

		var expResult64 forensics.ExplainResult
		if err := json.Unmarshal(expStdout64.Bytes(), &expResult64); err != nil {
			t.Fatalf("failed to unmarshal explain 64 result: %v", err)
		}
		if expResult64.Finding.ID != targetFinding.ID {
			t.Errorf("explain 64 ID mismatch: %s vs %s", expResult64.Finding.ID, targetFinding.ID)
		}
	}
}

// Vector 7: Malformed explain ID rejection (§18)
func TestContract7_MalformedExplainID(t *testing.T) {
	repoDir := setupCleanRepo(t)

	testCases := []string{
		"abc12",            // invalid length (5 chars)
		"0123456789ghijkl", // 16 chars with non-hex 'g'-'l'
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdegz", // 64 chars with non-hex 'g', 'z'
	}

	for _, malformedID := range testCases {
		var stdout, stderr bytes.Buffer
		code := runCLI([]string{"explain", malformedID, "--repo", repoDir}, &stdout, &stderr)
		if code != 2 {
			t.Errorf("expected exit code 2 for malformed explain ID %q, got %d", malformedID, code)
		}
		if !strings.Contains(stderr.String(), "invalid finding ID") && !strings.Contains(stderr.String(), "malformed finding ID") {
			t.Errorf("expected error message in stderr for %q, got: %s", malformedID, stderr.String())
		}
	}
}

// Vector 8: Real repository mutation explain test (§18)
func TestContract8_ExplainRealMutation(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	headsDir := filepath.Join(gitDir, "refs", "heads")
	_ = os.MkdirAll(headsDir, 0755)

	synthAKIA := "AKIA" + "0123456789ABCDEF"
	secretPayload := []byte("aws_key = \"" + synthAKIA + "\"\n")
	blobOID := testWriteLooseObject(t, gitDir, object.TypeBlob, secretPayload)
	bBlob := testHexTo20Bytes(blobOID)
	treePayload := append([]byte("100644 secret.env\x00"), bBlob[:]...)
	treeOID := testWriteLooseObject(t, gitDir, object.TypeTree, treePayload)
	commitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Alice <alice@example.com> 1700000000 +0000\ncommitter Alice <alice@example.com> 1700000000 +0000\n\nCommit with secret\n",
		treeOID,
	))
	commitOID := testWriteLooseObject(t, gitDir, object.TypeCommit, commitPayload)

	_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644)
	_ = os.WriteFile(filepath.Join(headsDir, "main"), []byte(commitOID+"\n"), 0644)

	// 1. Initial scan: finding is discovered
	var stdout1, stderr1 bytes.Buffer
	code1 := runCLI([]string{"scan", tempDir, "--json"}, &stdout1, &stderr1)
	if code1 != 1 {
		t.Fatalf("expected exit code 1 for secret repo, got %d", code1)
	}

	var report1 forensics.ScanReport
	if err := json.Unmarshal(stdout1.Bytes(), &report1); err != nil {
		t.Fatalf("failed to unmarshal scan report: %v", err)
	}
	if len(report1.Findings) == 0 {
		t.Fatalf("expected at least 1 finding in initial scan")
	}
	targetID := report1.Findings[0].ID

	// 2. Mutate repository: delete the secret blob file and rewrite HEAD to a clean commit
	blobPath := filepath.Join(gitDir, "objects", blobOID[:2], blobOID[2:])
	_ = os.Remove(blobPath)

	cleanPayload := []byte("Clean repository content.\n")
	cleanBlobOID := testWriteLooseObject(t, gitDir, object.TypeBlob, cleanPayload)
	bClean := testHexTo20Bytes(cleanBlobOID)
	cleanTreePayload := append([]byte("100644 readme.txt\x00"), bClean[:]...)
	cleanTreeOID := testWriteLooseObject(t, gitDir, object.TypeTree, cleanTreePayload)
	cleanCommitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Alice <alice@example.com> 1700000001 +0000\ncommitter Alice <alice@example.com> 1700000001 +0000\n\nClean commit\n",
		cleanTreeOID,
	))
	cleanCommitOID := testWriteLooseObject(t, gitDir, object.TypeCommit, cleanCommitPayload)
	_ = os.WriteFile(filepath.Join(headsDir, "main"), []byte(cleanCommitOID+"\n"), 0644)

	// 3. Explain the previous finding ID on the mutated repo in human mode
	var expStdoutHuman, expStderrHuman bytes.Buffer
	expCodeHuman := runCLI([]string{"explain", targetID, "--repo", tempDir}, &expStdoutHuman, &expStderrHuman)
	if expCodeHuman != 1 {
		t.Errorf("expected exit code 1 for mutated finding in human explain, got %d", expCodeHuman)
	}
	if !strings.Contains(expStderrHuman.String(), "not found") {
		t.Errorf("expected 'not found' message in stderr, got: %s", expStderrHuman.String())
	}
	if strings.Contains(expStdoutHuman.String(), synthAKIA) || strings.Contains(expStderrHuman.String(), synthAKIA) {
		t.Errorf("CRITICAL LEAK: raw secret appeared during explain on mutated repo")
	}

	// 4. Explain in JSON mode
	var expStdoutJSON, expStderrJSON bytes.Buffer
	expCodeJSON := runCLI([]string{"explain", targetID, "--repo", tempDir, "--json"}, &expStdoutJSON, &expStderrJSON)
	if expCodeJSON != 1 {
		t.Errorf("expected exit code 1 for mutated finding in JSON explain, got %d", expCodeJSON)
	}
	var errJSON map[string]string
	if err := json.Unmarshal(expStdoutJSON.Bytes(), &errJSON); err != nil {
		t.Fatalf("expected valid JSON error response on explain not-found, got: %s", expStdoutJSON.String())
	}
	if errJSON["id"] != targetID {
		t.Errorf("expected id %q in JSON error, got %q", targetID, errJSON["id"])
	}
	if !strings.Contains(strings.ToLower(errJSON["error"]), "not found") {
		t.Errorf("expected 'not found' in error message, got: %q", errJSON["error"])
	}
}

// Vector 9: Comprehensive multi-family raw secret non-leakage (§18)
func TestContract9_CorpusWideRawSecretNonLeakage(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	headsDir := filepath.Join(gitDir, "refs", "heads")
	_ = os.MkdirAll(headsDir, 0755)

	synthAKIA := "AKIA" + "0123456789ABCDEF"
	synthGHP := "ghp_" + "0123456789ABCDEFGHIJKLMNOPQRSTUV" + "WXYZ"
	synthSlack := "xoxb-" + "012345678901-" + "0123456789012-" + "0123456789abcdefghijklmn"
	synthGeneric := "SECRET_KEY_" + "ABCDEF0123456789ABCDEF0123456789"
	synthPEM := "-----BEGIN " + "RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEA0syntheticTestFixtureKeyMaterialOnlyDoNotUse123456789\n" +
		"-----END " + "RSA PRIVATE KEY-----\n"

	rawSecrets := []string{synthAKIA, synthGHP, synthSlack, synthGeneric, "MIIEowIBAAKCAQEA0syntheticTestFixtureKeyMaterialOnlyDoNotUse123456789"}

	multiSecretPayload := []byte(fmt.Sprintf(
		"aws = %q\nghp = %q\nslack = %q\ngeneric = %q\npem = %q\n",
		synthAKIA, synthGHP, synthSlack, synthGeneric, synthPEM,
	))
	blobOID := testWriteLooseObject(t, gitDir, object.TypeBlob, multiSecretPayload)
	bBlob := testHexTo20Bytes(blobOID)
	treePayload := append([]byte("100644 vault.env\x00"), bBlob[:]...)
	treeOID := testWriteLooseObject(t, gitDir, object.TypeTree, treePayload)
	commitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Alice <alice@example.com> 1700000000 +0000\ncommitter Alice <alice@example.com> 1700000000 +0000\n\nVault commit\n",
		treeOID,
	))
	commitOID := testWriteLooseObject(t, gitDir, object.TypeCommit, commitPayload)

	_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644)
	_ = os.WriteFile(filepath.Join(headsDir, "main"), []byte(commitOID+"\n"), 0644)

	// 1. Test in JSON mode
	var stdoutJSON, stderrJSON bytes.Buffer
	_ = runCLI([]string{"scan", tempDir, "--json"}, &stdoutJSON, &stderrJSON)
	for _, sec := range rawSecrets {
		if strings.Contains(stdoutJSON.String(), sec) {
			t.Errorf("CRITICAL LEAK: raw secret %q appeared in scan --json stdout", sec)
		}
		if strings.Contains(stderrJSON.String(), sec) {
			t.Errorf("CRITICAL LEAK: raw secret %q appeared in scan --json stderr", sec)
		}
	}

	// 2. Test in Human mode
	var stdoutHuman, stderrHuman bytes.Buffer
	_ = runCLI([]string{"scan", tempDir, "--no-color"}, &stdoutHuman, &stderrHuman)
	for _, sec := range rawSecrets {
		if strings.Contains(stdoutHuman.String(), sec) {
			t.Errorf("CRITICAL LEAK: raw secret %q appeared in scan human stdout", sec)
		}
		if strings.Contains(stderrHuman.String(), sec) {
			t.Errorf("CRITICAL LEAK: raw secret %q appeared in scan human stderr", sec)
		}
	}

	// 3. Test in Explain mode
	var report forensics.ScanReport
	_ = json.Unmarshal(stdoutJSON.Bytes(), &report)
	for _, f := range report.Findings {
		var expOut, expErr bytes.Buffer
		_ = runCLI([]string{"explain", f.ID, "--repo", tempDir, "--json"}, &expOut, &expErr)
		for _, sec := range rawSecrets {
			if strings.Contains(expOut.String(), sec) {
				t.Errorf("CRITICAL LEAK: raw secret %q appeared in explain JSON for %s", sec, f.ID)
			}
			if strings.Contains(expErr.String(), sec) {
				t.Errorf("CRITICAL LEAK: raw secret %q appeared in explain stderr for %s", sec, f.ID)
			}
		}
	}
}

// Vector 10: PEM zero-reveal enforcement (§18)
func TestContract10_PEMZeroReveal(t *testing.T) {
	repoDir, _, rawPEM := setupSecretRepo(t)

	// Extract private key body line
	lines := strings.Split(rawPEM, "\n")
	pemBody := lines[1]

	// 1. Scan JSON
	var stdoutJSON, stderrJSON bytes.Buffer
	_ = runCLI([]string{"scan", repoDir, "--json"}, &stdoutJSON, &stderrJSON)
	if strings.Contains(stdoutJSON.String(), pemBody) {
		t.Errorf("CRITICAL LEAK: PEM key body appeared in scan JSON output")
	}

	// 2. Scan Human
	var stdoutHuman, stderrHuman bytes.Buffer
	_ = runCLI([]string{"scan", repoDir, "--no-color"}, &stdoutHuman, &stderrHuman)
	if strings.Contains(stdoutHuman.String(), pemBody) {
		t.Errorf("CRITICAL LEAK: PEM key body appeared in scan human output")
	}

	var report forensics.ScanReport
	_ = json.Unmarshal(stdoutJSON.Bytes(), &report)

	foundPEM := false
	var pemFindingID string
	for _, f := range report.Findings {
		if strings.Contains(f.PatternName, "Private Key") || strings.Contains(f.Category, "private_key") {
			foundPEM = true
			pemFindingID = f.ID
			if f.Redacted != detect.RedactedPrivateKeyString {
				t.Errorf("expected exact placeholder %q for PEM key, got %q", detect.RedactedPrivateKeyString, f.Redacted)
			}
		}
	}
	if !foundPEM {
		t.Fatalf("expected PEM private key finding in report")
	}

	// 3. Explain Human & JSON
	var expHOut, expHErr bytes.Buffer
	_ = runCLI([]string{"explain", pemFindingID, "--repo", repoDir, "--no-color"}, &expHOut, &expHErr)
	if strings.Contains(expHOut.String(), pemBody) {
		t.Errorf("CRITICAL LEAK: PEM key body appeared in explain human output")
	}
	if !strings.Contains(expHOut.String(), detect.RedactedPrivateKeyString) {
		t.Errorf("expected exact %q in explain human output", detect.RedactedPrivateKeyString)
	}

	var expJOut, expJErr bytes.Buffer
	_ = runCLI([]string{"explain", pemFindingID, "--repo", repoDir, "--json"}, &expJOut, &expJErr)
	if strings.Contains(expJOut.String(), pemBody) {
		t.Errorf("CRITICAL LEAK: PEM key body appeared in explain JSON output")
	}
}

// Vector 11: Coverage gaps and anomalies presence discipline (§18)
func TestContract11_CoverageAndAnomaliesPresence(t *testing.T) {
	repoDir := setupCleanRepo(t)
	var stdout, stderr bytes.Buffer

	_ = runCLI([]string{"scan", repoDir, "--json"}, &stdout, &stderr)

	var report forensics.ScanReport
	_ = json.Unmarshal(stdout.Bytes(), &report)

	if report.CoverageGaps == nil {
		t.Errorf("CoverageGaps must be serialized as empty slice, not nil/omitted")
	}
	if report.StructuralAnomalies == nil {
		t.Errorf("StructuralAnomalies must be serialized as empty slice, not nil/omitted")
	}
}

// Vector 12: Deterministic cross-run sorting (§18)
func TestContract12_DeterministicSorting(t *testing.T) {
	repoDir, _, _ := setupSecretRepo(t)

	var runs [][]byte
	for i := 0; i < 5; i++ {
		var stdout, stderr bytes.Buffer
		_ = runCLI([]string{"scan", repoDir, "--json"}, &stdout, &stderr)
		runs = append(runs, stdout.Bytes())
	}

	var baseReport forensics.ScanReport
	if err := json.Unmarshal(runs[0], &baseReport); err != nil {
		t.Fatalf("run 0 unmarshal failed: %v", err)
	}

	for i := 1; i < len(runs); i++ {
		var r forensics.ScanReport
		if err := json.Unmarshal(runs[i], &r); err != nil {
			t.Fatalf("run %d unmarshal failed: %v", i, err)
		}
		if r.Summary != baseReport.Summary {
			t.Errorf("summary mismatch between run 0 and run %d", i)
		}
		if len(r.Findings) != len(baseReport.Findings) {
			t.Fatalf("findings length mismatch: %d vs %d", len(r.Findings), len(baseReport.Findings))
		}
		for j := range baseReport.Findings {
			b1, _ := json.Marshal(baseReport.Findings[j])
			b2, _ := json.Marshal(r.Findings[j])
			if !bytes.Equal(b1, b2) {
				t.Errorf("finding %d mismatch between run 0 and run %d:\n%s\nvs\n%s", j, i, b1, b2)
			}
		}
	}
}

// Vector 13: Field-presence and timeline null discipline (§18)
func TestContract13_TimelineNullDiscipline(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	headsDir := filepath.Join(gitDir, "refs", "heads")
	_ = os.MkdirAll(headsDir, 0755)

	synthAKIA := "AKIA" + "0123456789ABCDEF"
	secretPayload := []byte("aws_key = \"" + synthAKIA + "\"\n")
	blobOID := testWriteLooseObject(t, gitDir, object.TypeBlob, secretPayload)
	bBlob := testHexTo20Bytes(blobOID)
	treePayload := append([]byte("100644 secret.env\x00"), bBlob[:]...)
	treeOID := testWriteLooseObject(t, gitDir, object.TypeTree, treePayload)

	// Commit with malformed non-numeric timestamp (triggers hard-fail per §7)
	malformedCommitPayload := []byte(fmt.Sprintf(
		"tree %s\nauthor Alice <alice@example.com> NOT_A_TIMESTAMP +0000\ncommitter Alice <alice@example.com> NOT_A_TIMESTAMP +0000\n\nMalformed commit\n",
		treeOID,
	))
	commitOID := testWriteLooseObject(t, gitDir, object.TypeCommit, malformedCommitPayload)

	_ = os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644)
	_ = os.WriteFile(filepath.Join(headsDir, "main"), []byte(commitOID+"\n"), 0644)

	var stdout, stderr bytes.Buffer
	_ = runCLI([]string{"scan", tempDir, "--json"}, &stdout, &stderr)

	var report forensics.ScanReport
	_ = json.Unmarshal(stdout.Bytes(), &report)

	if len(report.Findings) == 0 {
		t.Fatalf("expected finding for secret in malformed commit repo")
	}

	// For a finding from a commit with hard-failed timestamp, Timeline should be nil (serialized as null in JSON)
	f := report.Findings[0]
	if f.Timeline != nil {
		t.Errorf("expected finding timeline to be null for commit with malformed timestamp, got: %+v", f.Timeline)
	}

	// Verify that the JSON output explicitly contains "timeline": null (field-presence discipline §18)
	var rawJSON map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &rawJSON); err != nil {
		t.Fatalf("failed to parse JSON report: %v", err)
	}
	findingsList, ok := rawJSON["findings"].([]interface{})
	if !ok || len(findingsList) == 0 {
		t.Fatalf("expected non-empty findings list in JSON")
	}
	firstFinding, ok := findingsList[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected finding object in JSON")
	}
	val, exists := firstFinding["timeline"]
	if !exists {
		t.Errorf("expected 'timeline' field to be present in JSON")
	}
	if val != nil {
		t.Errorf("expected 'timeline' field in JSON to be null, got %v", val)
	}
}
