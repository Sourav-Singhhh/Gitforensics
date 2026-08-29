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

// Vector 6: Explain round-trip identity (§18)
func TestContract6_ExplainRoundTrip(t *testing.T) {
	repoDir, _, _ := setupSecretRepo(t)
	var stdout, stderr bytes.Buffer

	_ = runCLI([]string{"scan", repoDir, "--json"}, &stdout, &stderr)
	var report forensics.ScanReport
	_ = json.Unmarshal(stdout.Bytes(), &report)

	if len(report.Findings) == 0 {
		t.Fatalf("expected findings in secret repo")
	}

	targetFinding := report.Findings[0]

	// 16-hex explain
	var expStdout, expStderr bytes.Buffer
	code := runCLI([]string{"explain", targetFinding.ID, "--repo", repoDir, "--json"}, &expStdout, &expStderr)
	if code != 0 {
		t.Fatalf("explain with 16-hex ID failed: code=%d, stderr=%s", code, expStderr.String())
	}

	var expResult forensics.ExplainResult
	if err := json.Unmarshal(expStdout.Bytes(), &expResult); err != nil {
		t.Fatalf("failed to unmarshal explain result: %v", err)
	}

	if expResult.Finding.ID != targetFinding.ID {
		t.Errorf("explain finding ID mismatch: %s vs %s", expResult.Finding.ID, targetFinding.ID)
	}
	if expResult.RecoveryExplanation == "" {
		t.Errorf("expected non-empty RecoveryExplanation")
	}

	// 64-hex explain
	var expStdout64, expStderr64 bytes.Buffer
	code64 := runCLI([]string{"explain", targetFinding.FullDigest, "--repo", repoDir, "--json"}, &expStdout64, &expStderr64)
	if code64 != 0 {
		t.Fatalf("explain with 64-hex digest failed: code=%d, stderr=%s", code64, expStderr64.String())
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

// Vector 8: Explain after repository mutation / not-found (§18)
func TestContract8_ExplainNotFound(t *testing.T) {
	repoDir := setupCleanRepo(t)
	var stdout, stderr bytes.Buffer

	// Valid 16-hex format but nonexistent ID
	nonExistentID := "0123456789abcdef"
	code := runCLI([]string{"explain", nonExistentID, "--repo", repoDir}, &stdout, &stderr)
	if code != 1 {
		t.Errorf("expected exit code 1 for finding not found, got %d", code)
	}
	if !strings.Contains(stderr.String(), "not found") {
		t.Errorf("expected 'not found' in stderr, got: %s", stderr.String())
	}
}

// Vector 9: Corpus-wide raw secret non-leakage (§18)
func TestContract9_CorpusWideRawSecretNonLeakage(t *testing.T) {
	repoDir, rawAKIA, _ := setupSecretRepo(t)

	// Test in JSON mode
	var stdoutJSON, stderrJSON bytes.Buffer
	_ = runCLI([]string{"scan", repoDir, "--json"}, &stdoutJSON, &stderrJSON)
	if strings.Contains(stdoutJSON.String(), rawAKIA) {
		t.Errorf("CRITICAL LEAK: raw AWS AKIA appeared in scan --json output")
	}

	// Test in Human mode
	var stdoutHuman, stderrHuman bytes.Buffer
	_ = runCLI([]string{"scan", repoDir, "--no-color"}, &stdoutHuman, &stderrHuman)
	if strings.Contains(stdoutHuman.String(), rawAKIA) {
		t.Errorf("CRITICAL LEAK: raw AWS AKIA appeared in scan human output")
	}
}

// Vector 10: PEM zero-reveal enforcement (§18)
func TestContract10_PEMZeroReveal(t *testing.T) {
	repoDir, _, rawPEM := setupSecretRepo(t)

	// Extract private key body line
	lines := strings.Split(rawPEM, "\n")
	pemBody := lines[1]

	var stdoutJSON, stderrJSON bytes.Buffer
	_ = runCLI([]string{"scan", repoDir, "--json"}, &stdoutJSON, &stderrJSON)

	if strings.Contains(stdoutJSON.String(), pemBody) {
		t.Errorf("CRITICAL LEAK: PEM key body appeared in scan JSON output")
	}

	var report forensics.ScanReport
	_ = json.Unmarshal(stdoutJSON.Bytes(), &report)

	foundPEM := false
	for _, f := range report.Findings {
		if strings.Contains(f.PatternName, "Private Key") || strings.Contains(f.Category, "private_key") {
			foundPEM = true
			if f.Redacted != detect.RedactedPrivateKeyString {
				t.Errorf("expected exact placeholder %q for PEM key, got %q", detect.RedactedPrivateKeyString, f.Redacted)
			}
		}
	}
	if !foundPEM {
		t.Errorf("expected PEM private key finding in report")
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

	var run1, run2 bytes.Buffer
	var stderr bytes.Buffer

	_ = runCLI([]string{"scan", repoDir, "--json"}, &run1, &stderr)
	_ = runCLI([]string{"scan", repoDir, "--json"}, &run2, &stderr)

	var report1, report2 forensics.ScanReport
	if err := json.Unmarshal(run1.Bytes(), &report1); err != nil {
		t.Fatalf("run1 unmarshal failed: %v", err)
	}
	if err := json.Unmarshal(run2.Bytes(), &report2); err != nil {
		t.Fatalf("run2 unmarshal failed: %v", err)
	}

	if report1.Summary != report2.Summary {
		t.Errorf("summary mismatch across runs")
	}
	if len(report1.Findings) != len(report2.Findings) {
		t.Fatalf("findings count mismatch: %d vs %d", len(report1.Findings), len(report2.Findings))
	}
	for i := range report1.Findings {
		f1, _ := json.Marshal(report1.Findings[i])
		f2, _ := json.Marshal(report2.Findings[i])
		if !bytes.Equal(f1, f2) {
			t.Errorf("finding %d mismatch across runs:\n%s\nvs\n%s", i, f1, f2)
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
