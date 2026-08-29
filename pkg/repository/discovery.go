package repository

import (
	"bytes"
	"gitforensics/pkg/object"
	"os"
	"path/filepath"
	"strings"
)

// Repository represents an open Git repository and its administrative paths.
type Repository struct {
	// WorktreeRoot is the root directory of the working tree (empty for bare repositories).
	WorktreeRoot string

	// GitDir is the per-worktree administrative directory containing HEAD, index, etc.
	GitDir string

	// CommonDir is the shared administrative directory containing objects, refs, packed-refs.
	CommonDir string

	// IsBare indicates whether the repository has no working tree.
	IsBare bool
}

// Discover walks upwards starting from startPath looking for a Git repository.
// Supports standard .git/ directories, linked worktree .git files (gitdir: ...),
// and bare repositories.
func Discover(startPath string) (*Repository, error) {
	absPath, err := filepath.Abs(startPath)
	if err != nil {
		return nil, err
	}

	curr := absPath
	for {
		gitPath := filepath.Join(curr, ".git")
		fi, err := os.Stat(gitPath)
		if err == nil {
			if fi.IsDir() {
				// Standard non-bare repository
				return &Repository{
					WorktreeRoot: curr,
					GitDir:       gitPath,
					CommonDir:    gitPath,
					IsBare:       false,
				}, nil
			}

			// Linked worktree .git file containing "gitdir: <path>"
			content, readErr := os.ReadFile(gitPath)
			if readErr == nil {
				gitDir := parseGitDirFile(curr, content)
				if gitDir != "" {
					commonDir := resolveCommonDir(gitDir)
					return &Repository{
						WorktreeRoot: curr,
						GitDir:       gitDir,
						CommonDir:    commonDir,
						IsBare:       false,
					}, nil
				}
			}
		}

		// Check if current directory itself is a bare repository (contains HEAD, objects, refs)
		if isBareRepo(curr) {
			return &Repository{
				WorktreeRoot: "",
				GitDir:       curr,
				CommonDir:    curr,
				IsBare:       true,
			}, nil
		}

		parent := filepath.Dir(curr)
		if parent == curr {
			// Reached root of filesystem
			break
		}
		curr = parent
	}

	return nil, object.ErrRepositoryNotFound
}

// parseGitDirFile parses a ".git" file containing "gitdir: <path>".
func parseGitDirFile(baseDir string, content []byte) string {
	trimmed := bytes.TrimSpace(content)
	prefix := []byte("gitdir:")
	if !bytes.HasPrefix(trimmed, prefix) {
		return ""
	}
	target := string(bytes.TrimSpace(trimmed[len(prefix):]))
	if len(target) == 0 {
		return ""
	}
	if filepath.IsAbs(target) {
		return filepath.Clean(target)
	}
	return filepath.Clean(filepath.Join(baseDir, target))
}

// resolveCommonDir checks for a "commondir" file inside a linked worktree gitdir.
func resolveCommonDir(gitDir string) string {
	commonFilePath := filepath.Join(gitDir, "commondir")
	content, err := os.ReadFile(commonFilePath)
	if err != nil {
		return gitDir
	}
	target := strings.TrimSpace(string(content))
	if len(target) == 0 {
		return gitDir
	}
	if filepath.IsAbs(target) {
		return filepath.Clean(target)
	}
	return filepath.Clean(filepath.Join(gitDir, target))
}

// isBareRepo checks if a directory contains HEAD, objects/, and refs/ directly.
func isBareRepo(dir string) bool {
	headPath := filepath.Join(dir, "HEAD")
	if _, err := os.Stat(headPath); err != nil {
		return false
	}
	objectsPath := filepath.Join(dir, "objects")
	if fi, err := os.Stat(objectsPath); err != nil || !fi.IsDir() {
		return false
	}
	refsPath := filepath.Join(dir, "refs")
	if fi, err := os.Stat(refsPath); err != nil || !fi.IsDir() {
		return false
	}
	return true
}
