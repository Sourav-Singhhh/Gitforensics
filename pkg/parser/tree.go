package parser

import (
	"bytes"
	"encoding/hex"
	"gitforensics/pkg/object"
)

// TreeMode represents the file mode in a Git tree entry.
type TreeMode string

const (
	ModeTree       TreeMode = "40000"  // Subtree (5 characters, no leading zero per Git format)
	ModeRegular    TreeMode = "100644" // Regular non-executable file
	ModeExecutable TreeMode = "100755" // Executable file
	ModeSymlink    TreeMode = "120000" // Symbolic link
	ModeGitlink    TreeMode = "160000" // Submodule / gitlink
)

// IsStandardMode returns true if the mode is one of the standard Git tree modes.
func (m TreeMode) IsStandardMode() bool {
	switch m {
	case ModeTree, ModeRegular, ModeExecutable, ModeSymlink, ModeGitlink:
		return true
	default:
		return false
	}
}

// NameSafetyFlag indicates whether a tree entry name is safe for filesystem path construction.
type NameSafetyFlag int

const (
	NameSafetyClean         NameSafetyFlag = 0
	NameSafetyEmpty         NameSafetyFlag = 1 // Empty name
	NameSafetyDot           NameSafetyFlag = 2 // "."
	NameSafetyDotDot        NameSafetyFlag = 3 // ".."
	NameSafetyEmbeddedSlash NameSafetyFlag = 4 // Contains '/'
)

// EvaluateNameSafety checks the raw name bytes for path safety anomalies (§6).
func EvaluateNameSafety(name []byte) NameSafetyFlag {
	if len(name) == 0 {
		return NameSafetyEmpty
	}
	if bytes.Equal(name, []byte(".")) {
		return NameSafetyDot
	}
	if bytes.Equal(name, []byte("..")) {
		return NameSafetyDotDot
	}
	if bytes.IndexByte(name, '/') != -1 {
		return NameSafetyEmbeddedSlash
	}
	return NameSafetyClean
}

// TreeEntry represents a single entry within a parsed Git tree object.
type TreeEntry struct {
	// Mode is the entry mode string (e.g., "100644", "40000").
	Mode TreeMode

	// Name is the raw, opaque byte slice of the entry filename (do not assume UTF-8).
	// It is a subslice of the underlying tree payload provided to ParseTree.
	// Callers retaining TreeEntry beyond the lifetime of the payload buffer must
	// copy Name if the underlying buffer is reused.
	Name []byte

	// OID is the raw 20-byte binary hash following the entry's NUL terminator.
	OID [20]byte

	// OIDHex is the cached 40-character lowercase hexadecimal representation of OID.
	OIDHex string

	// SafetyFlag indicates if the entry name contains path traversal or formatting anomalies.
	SafetyFlag NameSafetyFlag

	// UnknownMode indicates whether the entry mode is valid octal digits but not a standard Git mode.
	UnknownMode bool
}

// Tree represents a parsed Git tree object containing its list of entries.
type Tree struct {
	// Entries is the list of tree entries in the stored order.
	Entries []TreeEntry

	// IsCanonicallySorted records whether the stored entries adhere to Git's canonical sort order.
	IsCanonicallySorted bool
}

// compareTreeNames compares two tree entry names per Git's canonical ordering rule (§6, §17),
// which compares subtrees (mode 40000) as if they had a trailing '/' appended.
func compareTreeNames(aName []byte, aMode TreeMode, bName []byte, bMode TreeMode) int {
	aSuffix := ""
	if aMode == ModeTree {
		aSuffix = "/"
	}
	bSuffix := ""
	if bMode == ModeTree {
		bSuffix = "/"
	}

	aComp := aName
	if aSuffix != "" {
		aComp = append(append([]byte(nil), aName...), '/')
	}
	bComp := bName
	if bSuffix != "" {
		bComp = append(append([]byte(nil), bName...), '/')
	}

	return bytes.Compare(aComp, bComp)
}

// ParseTree parses the uncompressed binary payload of a Git tree object.
// Format: <mode-ascii> SP <name-bytes> NUL <20 raw OID bytes> repeated until payload exhaustion.
//
// Invariants enforced (§6):
// 1. Raw 20-byte OIDs: The 20 bytes following NUL are treated as raw binary, never parsed as text.
// 2. 5-character mode 40000: Supported as standard subtree mode without leading zero.
// 3. Name safety: Unsafe names (empty, '.', '..', embedded '/') receive NameSafetyFlag but are preserved.
// 4. Non-fatal sorting: Out-of-order entries do not cause parse errors; IsCanonicallySorted is recorded.
func ParseTree(payload []byte) (*Tree, error) {
	if len(payload) == 0 {
		return &Tree{
			Entries:             []TreeEntry{},
			IsCanonicallySorted: true,
		}, nil
	}

	var entries []TreeEntry
	isCanonicallySorted := true
	pos := 0
	totalLen := len(payload)

	for pos < totalLen {
		// Find space separator between mode and name
		spIdx := bytes.IndexByte(payload[pos:], ' ')
		if spIdx == -1 {
			return nil, object.ErrTreeEntryMissingSeparator
		}
		modeBytes := payload[pos : pos+spIdx]
		if len(modeBytes) == 0 {
			return nil, object.ErrTreeEntryMalformedMode
		}

		// Validate mode contains only ASCII digits
		for i := 0; i < len(modeBytes); i++ {
			c := modeBytes[i]
			if c < '0' || c > '9' {
				return nil, object.ErrTreeEntryMalformedMode
			}
		}

		mode := TreeMode(string(modeBytes))
		unknownMode := !mode.IsStandardMode()

		// Advance past mode and space
		pos += spIdx + 1
		if pos >= totalLen {
			return nil, object.ErrTruncatedTreeEntry
		}

		// Find NUL separator terminating the name
		nulIdx := bytes.IndexByte(payload[pos:], 0)
		if nulIdx == -1 {
			return nil, object.ErrTruncatedTreeEntry
		}

		nameBytes := payload[pos : pos+nulIdx]
		safetyFlag := EvaluateNameSafety(nameBytes)

		// Advance past name and NUL
		pos += nulIdx + 1

		// Verify 20 raw bytes remaining for the object ID
		if totalLen-pos < 20 {
			return nil, object.ErrTruncatedTreeEntry
		}

		var rawOID [20]byte
		copy(rawOID[:], payload[pos:pos+20])
		oidHex := hex.EncodeToString(rawOID[:])

		pos += 20

		entry := TreeEntry{
			Mode:        mode,
			Name:        nameBytes,
			OID:         rawOID,
			OIDHex:      oidHex,
			SafetyFlag:  safetyFlag,
			UnknownMode: unknownMode,
		}

		// Check canonical sort order
		if len(entries) > 0 {
			prev := entries[len(entries)-1]
			if compareTreeNames(prev.Name, prev.Mode, entry.Name, entry.Mode) >= 0 {
				isCanonicallySorted = false
			}
		}

		entries = append(entries, entry)
	}

	return &Tree{
		Entries:             entries,
		IsCanonicallySorted: isCanonicallySorted,
	}, nil
}
