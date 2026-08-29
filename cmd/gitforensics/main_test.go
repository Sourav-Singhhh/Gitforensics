package main

import (
	"bytes"
	"compress/zlib"
	"encoding/json"
	"fmt"
	"gitforensics/pkg/forensics"
	"gitforensics/pkg/object"
	"os"
	"path/filepath"
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

func TestCLIArgumentParsing(t *testing.T) {
	// 1. Version command
	cfg, err := parseCLIArgs([]string{"version"})
	if err != nil || cfg.command != "version" {
		t.Errorf("version parse failed: cfg=%+v, err=%v", cfg, err)
	}

	// 2. Scan with flags
	cfg, err = parseCLIArgs([]string{"scan", "/tmp/repo", "--json", "--min-confidence", "high", "--no-color", "--quiet"})
	if err != nil {
		t.Fatalf("scan parse failed: %v", err)
	}
	if cfg.command != "scan" || cfg.repoPath != "/tmp/repo" || !cfg.jsonOutput || !cfg.noColor || !cfg.quiet || cfg.minConfidence != "HIGH" {
		t.Errorf("unexpected scan cfg: %+v", cfg)
	}

	// 3. Scan with --repo flag
	cfg, err = parseCLIArgs([]string{"scan", "--repo", "/tmp/repo2"})
	if err != nil || cfg.repoPath != "/tmp/repo2" {
		t.Errorf("scan --repo parse failed: cfg=%+v, err=%v", cfg, err)
	}

	// 4. Explain with 16-hex ID
	cfg, err = parseCLIArgs([]string{"explain", "1234567890abcdef", "--repo", "/tmp/repo"})
	if err != nil || cfg.command != "explain" || cfg.findingID != "1234567890abcdef" || cfg.repoPath != "/tmp/repo" {
		t.Errorf("explain parse failed: cfg=%+v, err=%v", cfg, err)
	}

	// 5. Invalid command
	_, err = parseCLIArgs([]string{"unknown_cmd"})
	if err == nil {
		t.Errorf("expected error on unknown command")
	}

	// 6. Invalid flag
	_, err = parseCLIArgs([]string{"scan", "--invalid-flag"})
	if err == nil {
		t.Errorf("expected error on unknown flag")
	}
}

func TestCLIScanCleanRepo(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0755); err != nil {
		t.Fatalf("failed to create git dir: %v", err)
	}

	// Clean commit
	blobOID := writeLooseObject(t, gitDir, object.TypeBlob, []byte("clean content without any secrets\n"))
	b := [20]byte{}
	copy(b[:], blobOID)
	treeOID := writeLooseObject(t, gitDir, object.TypeTree, []byte("100644 hello.txt\x00"+string(b[:])))
	commitOID := writeLooseObject(t, gitDir, object.TypeCommit, []byte(fmt.Sprintf("tree %s\nauthor A <a@b.c> 100 +0000\ncommitter A <a@b.c> 100 +0000\n\nClean\n", treeOID)))

	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		t.Fatalf("failed to write HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(commitOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write main ref: %v", err)
	}

	report, err := forensics.RunScan(forensics.ScanOptions{
		RepoPath: tempDir,
	})
	if err != nil {
		t.Fatalf("RunScan on clean repo failed: %v", err)
	}

	if report.Summary.TotalFindingsCount != 0 {
		t.Errorf("expected 0 findings on clean repo, got %d", report.Summary.TotalFindingsCount)
	}

	jsonBytes, err := forensics.FormatJSON(report)
	if err != nil {
		t.Fatalf("FormatJSON failed: %v", err)
	}

	var parsed forensics.ScanReport
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}
	if len(parsed.Findings) != 0 {
		t.Errorf("expected empty findings array in JSON, got %d", len(parsed.Findings))
	}
	if parsed.CoverageGaps == nil || parsed.StructuralAnomalies == nil {
		t.Errorf("coverageGaps and structuralAnomalies must be non-nil arrays in JSON")
	}
}
