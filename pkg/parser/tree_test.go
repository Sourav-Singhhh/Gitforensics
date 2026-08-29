package parser

import (
	"bytes"
	"encoding/hex"
	"errors"
	"gitforensics/pkg/object"
	"testing"
)

func hexTo20Bytes(h string) [20]byte {
	b, _ := hex.DecodeString(h)
	var arr [20]byte
	copy(arr[:], b)
	return arr
}

// 1. Single-entry tree (100644 mode)
func TestSingleEntryTree(t *testing.T) {
	oidHex := "d670460b4b4aece5915caf5c68d12f560a9fe3e4"
	oidBytes := hexTo20Bytes(oidHex)

	var payload []byte
	payload = append(payload, []byte("100644 hello.txt\x00")...)
	payload = append(payload, oidBytes[:]...)

	tree, err := ParseTree(payload)
	if err != nil {
		t.Fatalf("unexpected error parsing single entry tree: %v", err)
	}

	if len(tree.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(tree.Entries))
	}
	entry := tree.Entries[0]
	if entry.Mode != ModeRegular {
		t.Errorf("expected mode %v, got %v", ModeRegular, entry.Mode)
	}
	if !bytes.Equal(entry.Name, []byte("hello.txt")) {
		t.Errorf("expected name 'hello.txt', got %q", entry.Name)
	}
	if entry.OID != oidBytes {
		t.Errorf("expected OID %x, got %x", oidBytes, entry.OID)
	}
	if entry.OIDHex != oidHex {
		t.Errorf("expected OIDHex %s, got %s", oidHex, entry.OIDHex)
	}
	if entry.SafetyFlag != NameSafetyClean {
		t.Errorf("expected clean safety flag, got %v", entry.SafetyFlag)
	}
	if !tree.IsCanonicallySorted {
		t.Errorf("expected IsCanonicallySorted=true")
	}
}

// 2. Multi-type tree (100644, 100755, 40000, 120000, 160000)
func TestMultiTypeTree(t *testing.T) {
	oid1 := hexTo20Bytes("1111111111111111111111111111111111111111")
	oid2 := hexTo20Bytes("2222222222222222222222222222222222222222")
	oid3 := hexTo20Bytes("3333333333333333333333333333333333333333")
	oid4 := hexTo20Bytes("4444444444444444444444444444444444444444")
	oid5 := hexTo20Bytes("5555555555555555555555555555555555555555")

	var payload []byte
	// 40000 dir (compares as "dir/")
	payload = append(payload, []byte("40000 dir\x00")...)
	payload = append(payload, oid3[:]...)

	// 100644 file.txt
	payload = append(payload, []byte("100644 file.txt\x00")...)
	payload = append(payload, oid1[:]...)

	// 120000 link
	payload = append(payload, []byte("120000 link\x00")...)
	payload = append(payload, oid4[:]...)

	// 100755 script.sh
	payload = append(payload, []byte("100755 script.sh\x00")...)
	payload = append(payload, oid2[:]...)

	// 160000 submodule (gitlink) - zero fs/network calls
	payload = append(payload, []byte("160000 sub\x00")...)
	payload = append(payload, oid5[:]...)

	tree, err := ParseTree(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tree.Entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(tree.Entries))
	}

	expectedModes := []TreeMode{ModeTree, ModeRegular, ModeSymlink, ModeExecutable, ModeGitlink}
	for i, expMode := range expectedModes {
		if tree.Entries[i].Mode != expMode {
			t.Errorf("entry %d: expected mode %v, got %v", i, expMode, tree.Entries[i].Mode)
		}
	}
}

// 3. Truncated mid-name (no NUL before payload ends)
func TestTruncatedMidName(t *testing.T) {
	payload := []byte("100644 incomplete_name")
	_, err := ParseTree(payload)
	if !errors.Is(err, object.ErrTruncatedTreeEntry) {
		t.Fatalf("expected ErrTruncatedTreeEntry, got %v", err)
	}
}

// 4. Truncated with fewer than 20 raw OID bytes remaining
func TestTruncatedOIDBytes(t *testing.T) {
	payload := []byte("100644 file.txt\x0012345")
	_, err := ParseTree(payload)
	if !errors.Is(err, object.ErrTruncatedTreeEntry) {
		t.Fatalf("expected ErrTruncatedTreeEntry, got %v", err)
	}
}

// 5. Entry name containing '/' -> NameSafetyEmbeddedSlash (parse succeeds per §6)
func TestEntryNameWithSlash(t *testing.T) {
	oid := hexTo20Bytes("1111111111111111111111111111111111111111")
	var payload []byte
	payload = append(payload, []byte("100644 bad/name.txt\x00")...)
	payload = append(payload, oid[:]...)

	tree, err := ParseTree(payload)
	if err != nil {
		t.Fatalf("unexpected parse failure for unsafe name: %v", err)
	}
	if len(tree.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(tree.Entries))
	}
	if tree.Entries[0].SafetyFlag != NameSafetyEmbeddedSlash {
		t.Errorf("expected NameSafetyEmbeddedSlash, got %v", tree.Entries[0].SafetyFlag)
	}
}

// 6. Empty mode field (SP as first byte)
func TestEmptyModeField(t *testing.T) {
	payload := []byte(" file.txt\x0012345678901234567890")
	_, err := ParseTree(payload)
	if !errors.Is(err, object.ErrTreeEntryMalformedMode) {
		t.Fatalf("expected ErrTreeEntryMalformedMode, got %v", err)
	}
}

// 7. Canonical empty tree (0-length payload) -> SHA-1 4b825dc642cb6eb9a060e54bf8d69288fbee4904
func TestCanonicalEmptyTree(t *testing.T) {
	tree, err := ParseTree([]byte{})
	if err != nil {
		t.Fatalf("unexpected error for empty tree: %v", err)
	}
	if len(tree.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(tree.Entries))
	}
	if !tree.IsCanonicallySorted {
		t.Errorf("expected IsCanonicallySorted=true")
	}

	computedSHA := object.ComputeEnvelopeSHA1(object.TypeTree, 0, []byte{})
	expectedSHA := "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	if computedSHA != expectedSHA {
		t.Errorf("expected SHA %s, got %s", expectedSHA, computedSHA)
	}
}

// 8. Deliberately out-of-order entries -> parse succeeds, IsCanonicallySorted == false
func TestOutOfOrderTreeEntries(t *testing.T) {
	oid1 := hexTo20Bytes("1111111111111111111111111111111111111111")
	oid2 := hexTo20Bytes("2222222222222222222222222222222222222222")

	var payload []byte
	// 'z_file.txt' before 'a_file.txt'
	payload = append(payload, []byte("100644 z_file.txt\x00")...)
	payload = append(payload, oid1[:]...)
	payload = append(payload, []byte("100644 a_file.txt\x00")...)
	payload = append(payload, oid2[:]...)

	tree, err := ParseTree(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tree.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(tree.Entries))
	}
	if tree.IsCanonicallySorted {
		t.Errorf("expected IsCanonicallySorted=false for out-of-order entries")
	}
}

// 9. Unsafe names: '.', '..', and empty name
func TestNameSafetyFlags(t *testing.T) {
	oid := hexTo20Bytes("1111111111111111111111111111111111111111")

	var payload []byte
	payload = append(payload, []byte("100644 .\x00")...)
	payload = append(payload, oid[:]...)
	payload = append(payload, []byte("100644 ..\x00")...)
	payload = append(payload, oid[:]...)
	payload = append(payload, []byte("100644 \x00")...)
	payload = append(payload, oid[:]...)

	tree, err := ParseTree(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tree.Entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(tree.Entries))
	}
	if tree.Entries[0].SafetyFlag != NameSafetyDot {
		t.Errorf("expected NameSafetyDot, got %v", tree.Entries[0].SafetyFlag)
	}
	if tree.Entries[1].SafetyFlag != NameSafetyDotDot {
		t.Errorf("expected NameSafetyDotDot, got %v", tree.Entries[1].SafetyFlag)
	}
	if tree.Entries[2].SafetyFlag != NameSafetyEmpty {
		t.Errorf("expected NameSafetyEmpty, got %v", tree.Entries[2].SafetyFlag)
	}
}

// 10. Unknown octal mode marked as UnknownMode
func TestUnknownTreeMode(t *testing.T) {
	oid := hexTo20Bytes("1111111111111111111111111111111111111111")
	var payload []byte
	payload = append(payload, []byte("100664 custom.txt\x00")...)
	payload = append(payload, oid[:]...)

	tree, err := ParseTree(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !tree.Entries[0].UnknownMode {
		t.Errorf("expected UnknownMode=true for mode 100664")
	}
}
