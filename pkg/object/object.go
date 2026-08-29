package object

// ObjectType represents the type of a Git object envelope.
type ObjectType string

const (
	TypeBlob   ObjectType = "blob"
	TypeTree   ObjectType = "tree"
	TypeCommit ObjectType = "commit"
	TypeTag    ObjectType = "tag"
)

// IsValid returns true if the object type is one of the four supported Git types.
func (t ObjectType) IsValid() bool {
	switch t {
	case TypeBlob, TypeTree, TypeCommit, TypeTag:
		return true
	default:
		return false
	}
}

// Object is the canonical, storage-agnostic representation of a Git object.
// Traversal, classification, detection, and reporting interact strictly with
// this abstraction without knowledge of underlying loose or pack storage.
type Object struct {
	// Type is the Git object type (blob, tree, commit, tag).
	Type ObjectType

	// Size is the canonical payload size in bytes as declared by the object envelope.
	Size int64

	// Payload is the uncompressed, raw content of the object.
	// Callers and consumers should treat this byte slice as owned by the Object
	// and avoid modifying its contents in place.
	Payload []byte

	// ID is the 40-character lowercase hexadecimal OID (expected or path-derived).
	ID string

	// ComputedID is the 40-character lowercase hexadecimal SHA-1 calculated from the full envelope.
	ComputedID string

	// IntegrityMismatch indicates whether the computed hash differs from the expected/path-derived ID.
	IntegrityMismatch bool

	// TrailingBytesCount records the number of extra bytes present in the loose file after the valid zlib stream EOF.
	TrailingBytesCount int64
}
