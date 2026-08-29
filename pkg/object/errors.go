package object

import "errors"

// Named errors defined by the GitForensics specification (§5, §6, §7).
var (
	// Envelope / Loose Object errors (§5)
	ErrInvalidZlibStream       = errors.New("invalid zlib stream")
	ErrTruncatedZlibStream     = errors.New("truncated zlib stream")
	ErrZlibChecksumFailed      = errors.New("zlib checksum failed")
	ErrMissingHeaderTerminator = errors.New("missing header terminator")
	ErrUnknownObjectType       = errors.New("unknown object type")
	ErrMalformedSize           = errors.New("malformed object size")
	ErrTruncatedPayload        = errors.New("truncated payload")
	ErrTrailingPayloadData     = errors.New("trailing payload data")
	ErrObjectTooLarge          = errors.New("object exceeds maximum allowed size")
	ErrInvalidOID              = errors.New("invalid object ID")

	// Tree parsing errors (§6)
	ErrTreeEntryMissingSeparator = errors.New("tree entry missing separator")
	ErrTruncatedTreeEntry        = errors.New("truncated tree entry")
	ErrTreeEntryMalformedMode    = errors.New("malformed tree entry mode")

	// Commit parsing errors (§7)
	ErrCommitMissingTree             = errors.New("commit missing tree header")
	ErrCommitMalformedTreeRef        = errors.New("commit malformed tree ref")
	ErrCommitMalformedParentRef      = errors.New("commit malformed parent ref")
	ErrCommitMissingAuthor           = errors.New("commit missing author")
	ErrCommitMissingCommitter        = errors.New("commit missing committer")
	ErrCommitDuplicateAuthor         = errors.New("commit duplicate author")
	ErrCommitDuplicateCommitter      = errors.New("commit duplicate committer")
	ErrCommitMalformedAuthorLine     = errors.New("commit malformed author line")
	ErrCommitMalformedCommitterLine  = errors.New("commit malformed committer line")
	ErrCommitMalformedTimestamp      = errors.New("commit malformed timestamp")
	ErrCommitMalformedTimezone       = errors.New("commit malformed timezone")
	ErrCommitMissingMessageSeparator = errors.New("commit missing message separator")
	ErrCommitMalformedHeaderLine     = errors.New("commit malformed header line")

	// Repository and Reference errors (§4)
	ErrRepositoryNotFound   = errors.New("git repository not found")
	ErrSymbolicRefCycle     = errors.New("symbolic ref cycle detected")
	ErrMaxPeelDepthExceeded = errors.New("maximum tag peel depth exceeded")
	ErrMaxTreeDepthExceeded = errors.New("maximum tree recursion depth exceeded")
	ErrObjectNotFound       = errors.New("object not found")
)
