package repository

import (
	"errors"
	"gitforensics/pkg/object"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverRepository(t *testing.T) {
	// 1. Standard repository with .git directory
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("failed to create .git: %v", err)
	}

	subDir := filepath.Join(tempDir, "src", "pkg")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	repo, err := Discover(subDir)
	if err != nil {
		t.Fatalf("expected discovery from subdir, got error: %v", err)
	}
	if repo.WorktreeRoot != tempDir {
		t.Errorf("expected WorktreeRoot %s, got %s", tempDir, repo.WorktreeRoot)
	}
	if repo.GitDir != gitDir {
		t.Errorf("expected GitDir %s, got %s", gitDir, repo.GitDir)
	}
	if repo.CommonDir != gitDir {
		t.Errorf("expected CommonDir %s, got %s", gitDir, repo.CommonDir)
	}
	if repo.IsBare {
		t.Errorf("expected non-bare repository")
	}

	// 2. Linked worktree with .git file and commondir
	mainGitDir := filepath.Join(tempDir, "main_repo", ".git")
	wtAdminDir := filepath.Join(mainGitDir, "worktrees", "wt1")
	if err := os.MkdirAll(wtAdminDir, 0755); err != nil {
		t.Fatalf("failed to create worktree admin dir: %v", err)
	}
	// Write commondir file pointing back to main .git
	if err := os.WriteFile(filepath.Join(wtAdminDir, "commondir"), []byte("../..\n"), 0644); err != nil {
		t.Fatalf("failed to write commondir: %v", err)
	}

	wtDir := filepath.Join(tempDir, "linked_wt")
	if err := os.MkdirAll(wtDir, 0755); err != nil {
		t.Fatalf("failed to create linked wt dir: %v", err)
	}
	// Write .git file
	gitFileContent := "gitdir: " + wtAdminDir + "\n"
	if err := os.WriteFile(filepath.Join(wtDir, ".git"), []byte(gitFileContent), 0644); err != nil {
		t.Fatalf("failed to write .git file: %v", err)
	}

	wtRepo, err := Discover(wtDir)
	if err != nil {
		t.Fatalf("expected discovery of linked worktree, got: %v", err)
	}
	if wtRepo.GitDir != wtAdminDir {
		t.Errorf("expected GitDir %s, got %s", wtAdminDir, wtRepo.GitDir)
	}
	cleanMainGitDir := filepath.Clean(mainGitDir)
	if wtRepo.CommonDir != cleanMainGitDir {
		t.Errorf("expected CommonDir %s, got %s", cleanMainGitDir, wtRepo.CommonDir)
	}

	// 3. Non-Git directory -> ErrRepositoryNotFound
	isolatedDir := t.TempDir()
	_, err = Discover(isolatedDir)
	if !errors.Is(err, object.ErrRepositoryNotFound) {
		t.Fatalf("expected ErrRepositoryNotFound, got %v", err)
	}
}

func TestAllRefsLooseAndPacked(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("failed to create .git: %v", err)
	}

	repo := &Repository{
		WorktreeRoot: tempDir,
		GitDir:       gitDir,
		CommonDir:    gitDir,
		IsBare:       false,
	}

	// Write packed-refs with comments, tags, peeled tags
	packedContent := []byte(
		"# pack-refs with: sorted-keys\n" +
			"# comment line\n" +
			"1111111111111111111111111111111111111111 refs/heads/main\n" +
			"2222222222222222222222222222222222222222 refs/heads/feature\n" +
			"3333333333333333333333333333333333333333 refs/tags/v1.0\n" +
			"^4444444444444444444444444444444444444444\n",
	)
	if err := os.WriteFile(filepath.Join(gitDir, "packed-refs"), packedContent, 0644); err != nil {
		t.Fatalf("failed to write packed-refs: %v", err)
	}

	// Write a loose ref for refs/heads/main that overrides packed-refs
	looseMainDir := filepath.Join(gitDir, "refs", "heads")
	if err := os.MkdirAll(looseMainDir, 0755); err != nil {
		t.Fatalf("failed to create loose heads dir: %v", err)
	}
	looseMainOID := "5555555555555555555555555555555555555555"
	if err := os.WriteFile(filepath.Join(looseMainDir, "main"), []byte(looseMainOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write loose ref: %v", err)
	}

	// Write a nested loose ref (e.g. refs/remotes/origin/main)
	remoteDir := filepath.Join(gitDir, "refs", "remotes", "origin")
	if err := os.MkdirAll(remoteDir, 0755); err != nil {
		t.Fatalf("failed to create remotes dir: %v", err)
	}
	remoteOID := "6666666666666666666666666666666666666666"
	if err := os.WriteFile(filepath.Join(remoteDir, "main"), []byte(remoteOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write remote ref: %v", err)
	}

	refsMap, _, err := AllRefs(repo)
	if err != nil {
		t.Fatalf("AllRefs failed: %v", err)
	}

	// Assert loose ref overrides packed ref for refs/heads/main
	if refsMap["refs/heads/main"] != looseMainOID {
		t.Errorf("expected loose override %s, got %s", looseMainOID, refsMap["refs/heads/main"])
	}

	// Assert packed-only refs are present
	if refsMap["refs/heads/feature"] != "2222222222222222222222222222222222222222" {
		t.Errorf("feature ref mismatch: %s", refsMap["refs/heads/feature"])
	}
	if refsMap["refs/tags/v1.0"] != "3333333333333333333333333333333333333333" {
		t.Errorf("tag ref mismatch: %s", refsMap["refs/tags/v1.0"])
	}

	// Assert nested remote ref
	if refsMap["refs/remotes/origin/main"] != remoteOID {
		t.Errorf("remote ref mismatch: %s", refsMap["refs/remotes/origin/main"])
	}

	// Check deterministic sorting
	sorted := SortedRefNames(refsMap)
	expectedOrder := []string{"refs/heads/feature", "refs/heads/main", "refs/remotes/origin/main", "refs/tags/v1.0"}
	for i, exp := range expectedOrder {
		if sorted[i] != exp {
			t.Errorf("sort mismatch at %d: expected %s, got %s", i, exp, sorted[i])
		}
	}
}

func TestResolveHEAD(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	if err := os.MkdirAll(filepath.Join(gitDir, "refs", "heads"), 0755); err != nil {
		t.Fatalf("failed to setup git dir: %v", err)
	}

	repo := &Repository{
		WorktreeRoot: tempDir,
		GitDir:       gitDir,
		CommonDir:    gitDir,
		IsBare:       false,
	}

	// 1. Unborn branch (HEAD points to non-existent refs/heads/main)
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0644); err != nil {
		t.Fatalf("failed to write HEAD: %v", err)
	}
	oid, isUnborn, err := ResolveHEAD(repo)
	if err != nil {
		t.Fatalf("unexpected error on unborn HEAD: %v", err)
	}
	if !isUnborn {
		t.Errorf("expected isUnborn=true")
	}
	if oid != "" {
		t.Errorf("expected empty OID for unborn branch, got %s", oid)
	}

	// 2. Symbolic HEAD pointing to resolved loose ref
	mainOID := "1111111111111111111111111111111111111111"
	if err := os.WriteFile(filepath.Join(gitDir, "refs", "heads", "main"), []byte(mainOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write loose ref: %v", err)
	}
	oid, isUnborn, err = ResolveHEAD(repo)
	if err != nil {
		t.Fatalf("unexpected error on resolved HEAD: %v", err)
	}
	if isUnborn {
		t.Errorf("expected isUnborn=false")
	}
	if oid != mainOID {
		t.Errorf("expected OID %s, got %s", mainOID, oid)
	}

	// 3. Detached HEAD (direct 40-hex OID in HEAD file)
	detachedOID := "2222222222222222222222222222222222222222"
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte(detachedOID+"\n"), 0644); err != nil {
		t.Fatalf("failed to write detached HEAD: %v", err)
	}
	oid, isUnborn, err = ResolveHEAD(repo)
	if err != nil {
		t.Fatalf("unexpected error on detached HEAD: %v", err)
	}
	if isUnborn {
		t.Errorf("expected isUnborn=false for detached HEAD")
	}
	if oid != detachedOID {
		t.Errorf("expected OID %s, got %s", detachedOID, oid)
	}
}

func TestSymbolicRefCycle(t *testing.T) {
	tempDir := t.TempDir()
	gitDir := filepath.Join(tempDir, ".git")
	headsDir := filepath.Join(gitDir, "refs", "heads")
	if err := os.MkdirAll(headsDir, 0755); err != nil {
		t.Fatalf("failed to setup heads dir: %v", err)
	}

	repo := &Repository{
		WorktreeRoot: tempDir,
		GitDir:       gitDir,
		CommonDir:    gitDir,
		IsBare:       false,
	}

	// Create symbolic ref loop: a -> b -> a
	if err := os.WriteFile(filepath.Join(headsDir, "a"), []byte("ref: refs/heads/b\n"), 0644); err != nil {
		t.Fatalf("failed to write ref a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(headsDir, "b"), []byte("ref: refs/heads/a\n"), 0644); err != nil {
		t.Fatalf("failed to write ref b: %v", err)
	}

	_, err := ResolveSymbolicRef(repo, "refs/heads/a", 10)
	if !errors.Is(err, object.ErrSymbolicRefCycle) {
		t.Fatalf("expected ErrSymbolicRefCycle, got %v", err)
	}
}
