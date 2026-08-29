package parser

import "testing"

// FuzzParseTree verifies that ParseTree never panics on arbitrary byte sequences.
func FuzzParseTree(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("100644 file.txt\x0012345678901234567890"))
	f.Add([]byte("40000 dir\x0012345678901234567890100644 a.txt\x0012345678901234567890"))
	f.Add([]byte("100644 bad/name.txt\x0012345678901234567890"))
	f.Add([]byte("invalid truncated tree payload"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseTree(data)
	})
}

// FuzzParseCommit verifies that ParseCommit never panics on arbitrary byte sequences.
func FuzzParseCommit(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@b.c> 123 +0000\ncommitter A <a@b.c> 123 +0000\n\nInitial commit\n"))
	f.Add([]byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nparent 1111111111111111111111111111111111111111\nauthor A <a@b.c> 123 +0000\ncommitter A <a@b.c> 123 +0000\ngpgsig sig\n sig\n\nSigned\n"))
	f.Add([]byte("corrupt header without separator"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseCommit(data)
	})
}
