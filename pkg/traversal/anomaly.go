package traversal

// AnomalyType represents the category of a non-fatal structural issue in a Git repository.
type AnomalyType string

const (
	AnomalyMalformedRef            AnomalyType = "MALFORMED_REF"
	AnomalySymbolicRefCycle        AnomalyType = "SYMBOLIC_REF_CYCLE"
	AnomalyMalformedPackedRef      AnomalyType = "MALFORMED_PACKED_REF"
	AnomalyMalformedTree           AnomalyType = "MALFORMED_TREE"
	AnomalyMalformedCommit         AnomalyType = "MALFORMED_COMMIT"
	AnomalyUnsafeTreeName          AnomalyType = "UNSAFE_TREE_NAME"
	AnomalyUnknownTreeMode         AnomalyType = "UNKNOWN_TREE_MODE"
	AnomalyTreeTypeMismatch        AnomalyType = "TREE_TYPE_MISMATCH"
	AnomalyRecursionDepthExceeded  AnomalyType = "RECURSION_DEPTH_EXCEEDED"
	AnomalyMissingReferencedObject AnomalyType = "MISSING_REFERENCED_OBJECT"
	AnomalyCorruptedLooseObject    AnomalyType = "CORRUPTED_LOOSE_OBJECT"
	AnomalyLooseIntegrityMismatch  AnomalyType = "LOOSE_INTEGRITY_MISMATCH"
)

// StructuralAnomaly represents a recorded structural, path, or formatting irregularity
// that is preserved for forensic reporting without aborting the overall scan.
type StructuralAnomaly struct {
	Type        AnomalyType
	Location    string // Ref name, loose file path, or OID
	Description string
}
