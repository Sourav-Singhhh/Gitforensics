package object

import "errors"

// Named errors defined by the GitForensics specification (§5).
var (
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
)
