package parser

import (
	"bytes"
	"errors"
	"gitforensics/pkg/object"
	"testing"
)

// 9. Minimal root commit (tree + author + committer + blank line + message, 0 parents)
func TestMinimalRootCommit(t *testing.T) {
	rawCommit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Alice Smith <alice@example.com> 1700000000 +0000\n" +
		"committer Bob Jones <bob@example.com> 1700000001 +0530\n" +
		"\n" +
		"Initial commit\n")

	commit, err := ParseCommit(rawCommit)
	if err != nil {
		t.Fatalf("unexpected error parsing root commit: %v", err)
	}

	if commit.TreeSHA != "4b825dc642cb6eb9a060e54bf8d69288fbee4904" {
		t.Errorf("expected tree SHA 4b825dc642cb6eb9a060e54bf8d69288fbee4904, got %s", commit.TreeSHA)
	}
	if commit.ParentSHAs == nil || len(commit.ParentSHAs) != 0 {
		t.Errorf("expected empty non-nil ParentSHAs slice, got %v", commit.ParentSHAs)
	}
	if commit.Author.Name != "Alice Smith" || commit.Author.Email != "alice@example.com" || commit.Author.Timestamp != 1700000000 || commit.Author.Timezone != "+0000" {
		t.Errorf("author mismatch: got %+v", commit.Author)
	}
	if commit.Committer.Name != "Bob Jones" || commit.Committer.Email != "bob@example.com" || commit.Committer.Timestamp != 1700000001 || commit.Committer.Timezone != "+0530" {
		t.Errorf("committer mismatch: got %+v", commit.Committer)
	}
	if !bytes.Equal(commit.Message, []byte("Initial commit\n")) {
		t.Errorf("message mismatch: got %q", commit.Message)
	}
}

// 10. Merge commit (2 parent lines in stored order)
func TestMergeCommit(t *testing.T) {
	parent1 := "1111111111111111111111111111111111111111"
	parent2 := "2222222222222222222222222222222222222222"
	rawCommit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"parent " + parent1 + "\n" +
		"parent " + parent2 + "\n" +
		"author Alice <alice@example.com> 1700000000 +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n" +
		"\n" +
		"Merge branch 'feature'\n")

	commit, err := ParseCommit(rawCommit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(commit.ParentSHAs) != 2 {
		t.Fatalf("expected 2 parents, got %d", len(commit.ParentSHAs))
	}
	if commit.ParentSHAs[0] != parent1 || commit.ParentSHAs[1] != parent2 {
		t.Errorf("parent ordering mismatch: got %v", commit.ParentSHAs)
	}
}

// 11. Commit missing tree header (starts with author)
func TestCommitMissingTree(t *testing.T) {
	rawCommit := []byte("author Alice <alice@example.com> 1700000000 +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n" +
		"\n" +
		"Broken commit\n")

	_, err := ParseCommit(rawCommit)
	if !errors.Is(err, object.ErrCommitMissingTree) {
		t.Fatalf("expected ErrCommitMissingTree, got %v", err)
	}
}

// 12. Multiline header continuation (gpgsig followed by normal author/committer)
func TestCommitHeaderContinuation(t *testing.T) {
	rawCommit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"parent 1111111111111111111111111111111111111111\n" +
		"author Alice <alice@example.com> 1700000000 +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n" +
		"gpgsig -----BEGIN PGP SIGNATURE-----\n" +
		" Version: GnuPG v2\n" +
		" \n" +
		" iQEcBAABCAAGBQJ...\n" +
		" -----END PGP SIGNATURE-----\n" +
		"\n" +
		"Signed commit message\n")

	commit, err := ParseCommit(rawCommit)
	if err != nil {
		t.Fatalf("unexpected error parsing commit with gpgsig: %v", err)
	}

	if len(commit.ExtraHeaders) != 1 {
		t.Fatalf("expected 1 extra header (gpgsig), got %d", len(commit.ExtraHeaders))
	}
	if commit.ExtraHeaders[0].Key != "gpgsig" {
		t.Errorf("expected key 'gpgsig', got %s", commit.ExtraHeaders[0].Key)
	}
	expectedGpgSig := "-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v2\n\niQEcBAABCAAGBQJ...\n-----END PGP SIGNATURE-----"
	if commit.ExtraHeaders[0].Value != expectedGpgSig {
		t.Errorf("gpgsig value mismatch:\nExpected:\n%s\nGot:\n%s", expectedGpgSig, commit.ExtraHeaders[0].Value)
	}
}

// 13. Headers present but missing blank-line message separator
func TestCommitMissingMessageSeparator(t *testing.T) {
	rawCommit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Alice <alice@example.com> 1700000000 +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n" +
		"Commit message directly attached without blank line")

	_, err := ParseCommit(rawCommit)
	if !errors.Is(err, object.ErrCommitMissingMessageSeparator) {
		t.Fatalf("expected ErrCommitMissingMessageSeparator, got %v", err)
	}
}

// 14. Malformed / non-numeric timestamp in author line -> ErrCommitMalformedTimestamp (hard fail)
func TestCommitMalformedTimestamp(t *testing.T) {
	rawCommit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Alice <alice@example.com> NOT_A_TIMESTAMP +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n" +
		"\n" +
		"Bad timestamp commit\n")

	_, err := ParseCommit(rawCommit)
	if !errors.Is(err, object.ErrCommitMalformedTimestamp) {
		t.Fatalf("expected ErrCommitMalformedTimestamp, got %v", err)
	}
}

// 15. Timestamp overflow (40 decimal digits) -> ErrCommitMalformedTimestamp (no panic)
func TestCommitTimestampOverflow(t *testing.T) {
	rawCommit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Alice <alice@example.com> 9999999999999999999999999999999999999999 +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n" +
		"\n" +
		"Overflow timestamp commit\n")

	_, err := ParseCommit(rawCommit)
	if !errors.Is(err, object.ErrCommitMalformedTimestamp) {
		t.Fatalf("expected ErrCommitMalformedTimestamp on overflow, got %v", err)
	}
}

// 16. Negative timestamp (valid pre-1970 date)
func TestCommitNegativeTimestamp(t *testing.T) {
	rawCommit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Ancient Developer <ancient@example.com> -12345678 +0000\n" +
		"committer Ancient Developer <ancient@example.com> -12345678 +0000\n" +
		"\n" +
		"Pre-1970 commit\n")

	commit, err := ParseCommit(rawCommit)
	if err != nil {
		t.Fatalf("unexpected error on negative timestamp: %v", err)
	}
	if commit.Author.Timestamp != -12345678 {
		t.Errorf("expected timestamp -12345678, got %d", commit.Author.Timestamp)
	}
}

// 17. Malformed timezone -> ErrCommitMalformedTimezone
func TestCommitMalformedTimezone(t *testing.T) {
	rawCommit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Alice <alice@example.com> 1700000000 INVALID_TZ\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n" +
		"\n" +
		"Bad timezone commit\n")

	_, err := ParseCommit(rawCommit)
	if !errors.Is(err, object.ErrCommitMalformedTimezone) {
		t.Fatalf("expected ErrCommitMalformedTimezone, got %v", err)
	}
}

// 18. Duplicate author and committer headers
func TestCommitDuplicateHeaders(t *testing.T) {
	dupAuthorCommit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Alice <alice@example.com> 1700000000 +0000\n" +
		"author Bob <bob@example.com> 1700000000 +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n" +
		"\n" +
		"Duplicate author\n")

	_, err := ParseCommit(dupAuthorCommit)
	if !errors.Is(err, object.ErrCommitDuplicateAuthor) {
		t.Fatalf("expected ErrCommitDuplicateAuthor, got %v", err)
	}

	dupCommitterCommit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Alice <alice@example.com> 1700000000 +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n" +
		"committer Bob <bob@example.com> 1700000000 +0000\n" +
		"\n" +
		"Duplicate committer\n")

	_, err = ParseCommit(dupCommitterCommit)
	if !errors.Is(err, object.ErrCommitDuplicateCommitter) {
		t.Fatalf("expected ErrCommitDuplicateCommitter, got %v", err)
	}
}

// 19. Empty commit message after separator (\n\n)
func TestCommitEmptyMessage(t *testing.T) {
	rawCommit := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n" +
		"author Alice <alice@example.com> 1700000000 +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n" +
		"\n")

	commit, err := ParseCommit(rawCommit)
	if err != nil {
		t.Fatalf("unexpected error for empty commit message: %v", err)
	}
	if len(commit.Message) != 0 {
		t.Errorf("expected 0-byte message, got %q", commit.Message)
	}
}
