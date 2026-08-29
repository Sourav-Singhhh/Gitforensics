package object

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// DefaultMaxObjectSize defines the default safety ceiling for decompressed objects (64 MiB).
const DefaultMaxObjectSize int64 = 64 * 1024 * 1024

// ValidateOID checks that an OID string is exactly 40 lowercase hexadecimal characters.
func ValidateOID(oid string) error {
	if len(oid) != 40 {
		return ErrInvalidOID
	}
	for i := 0; i < 40; i++ {
		c := oid[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return ErrInvalidOID
		}
	}
	return nil
}

// LooseObjectPath returns the on-disk path for a loose object within a git directory.
// Validates that the OID is a valid 40-character lowercase hexadecimal string.
func LooseObjectPath(gitDir string, oid string) (string, error) {
	if err := ValidateOID(oid); err != nil {
		return "", err
	}
	return filepath.Join(gitDir, "objects", oid[:2], oid[2:]), nil
}

// CountingByteReader implements both io.Reader and io.ByteReader while tracking the
// exact number of bytes consumed from the underlying buffer.
//
// Design note:
// In Go's standard library compress/flate and compress/zlib, when the underlying reader
// implements io.ByteReader, the decompressor reads bytes directly via ReadByte() without
// wrapping the input in an internal bufio.Reader read-ahead buffer.
// This allows exact consumed-byte accounting at the logical end of the zlib stream,
// correctly determining trailing bytes for both compressed and uncompressed/stored
// DEFLATE blocks. Trailing bytes are measured from the exact underlying position
// (len(rawBytes) - countingReader.BytesRead()), protected by regression tests.
type CountingByteReader struct {
	buf []byte
	pos int
}

// NewCountingByteReader creates a new CountingByteReader over the provided byte slice.
func NewCountingByteReader(buf []byte) *CountingByteReader {
	return &CountingByteReader{buf: buf, pos: 0}
}

// Read implements io.Reader and records consumed bytes.
func (r *CountingByteReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.buf) {
		return 0, io.EOF
	}
	n := copy(p, r.buf[r.pos:])
	r.pos += n
	return n, nil
}

// ReadByte implements io.ByteReader and records single-byte reads.
func (r *CountingByteReader) ReadByte() (byte, error) {
	if r.pos >= len(r.buf) {
		return 0, io.EOF
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

// BytesRead returns the total number of bytes read so far.
func (r *CountingByteReader) BytesRead() int64 {
	return int64(r.pos)
}

// ParseEnvelope parses an uncompressed Git object envelope formatted as:
// <type> SP <ascii-decimal-size> NUL <payload>
// Enforces strict decimal size rules, canonical "0", no leading zeros, no signs,
// and exact payload length matches per §5 of the master specification.
func ParseEnvelope(decompressed []byte, maxObjectSize int64) (ObjectType, int64, []byte, error) {
	if len(decompressed) == 0 {
		return "", 0, nil, ErrMissingHeaderTerminator
	}

	nulIdx := bytes.IndexByte(decompressed, 0)
	if nulIdx == -1 {
		return "", 0, nil, ErrMissingHeaderTerminator
	}

	header := decompressed[:nulIdx]
	spIdx := bytes.IndexByte(header, ' ')
	if spIdx == -1 {
		return "", 0, nil, ErrUnknownObjectType
	}

	typeStr := string(header[:spIdx])
	objType := ObjectType(typeStr)
	if !objType.IsValid() {
		return "", 0, nil, ErrUnknownObjectType
	}

	sizeBytes := header[spIdx+1:]
	if len(sizeBytes) == 0 {
		return "", 0, nil, ErrMalformedSize
	}

	// Size validation: ASCII decimal digits only (no sign, no +, no -)
	for i := 0; i < len(sizeBytes); i++ {
		c := sizeBytes[i]
		if c < '0' || c > '9' {
			return "", 0, nil, ErrMalformedSize
		}
	}

	// Canonical "0": no leading zeros permitted (e.g. "00", "01" are malformed)
	if len(sizeBytes) > 1 && sizeBytes[0] == '0' {
		return "", 0, nil, ErrMalformedSize
	}

	// Bounded integer parsing with overflow check
	sizeStr := string(sizeBytes)
	declaredSize, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil || declaredSize < 0 {
		return "", 0, nil, ErrMalformedSize
	}

	// Enforce safety ceiling if configured
	if maxObjectSize > 0 && declaredSize > maxObjectSize {
		return "", 0, nil, ErrObjectTooLarge
	}

	payload := decompressed[nulIdx+1:]
	actualPayloadLen := int64(len(payload))

	if actualPayloadLen < declaredSize {
		return "", 0, nil, ErrTruncatedPayload
	}
	if actualPayloadLen > declaredSize {
		return "", 0, nil, ErrTrailingPayloadData
	}

	return objType, declaredSize, payload, nil
}

// ComputeEnvelopeSHA1 calculates the full-envelope SHA-1 hash for a Git object:
// SHA1("<type> <canonical decimal size>\0" + payload)
func ComputeEnvelopeSHA1(objType ObjectType, size int64, payload []byte) string {
	h := sha1.New()
	header := []byte(fmt.Sprintf("%s %d\x00", objType, size))
	h.Write(header)
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// DecodeLooseObjectBytes decodes and validates a raw loose object file from its compressed zlib bytes.
// If expectedOID is non-empty, it is checked against the computed SHA-1. On mismatch,
// the object is returned with IntegrityMismatch = true without raising a fatal error.
// Trailing file bytes after zlib EOF are recorded in TrailingBytesCount (lenient + recorded policy).
func DecodeLooseObjectBytes(rawBytes []byte, expectedOID string, maxObjectSize int64) (*Object, error) {
	if expectedOID != "" {
		if err := ValidateOID(expectedOID); err != nil {
			return nil, err
		}
	}

	if maxObjectSize <= 0 {
		maxObjectSize = DefaultMaxObjectSize
	}

	countingReader := NewCountingByteReader(rawBytes)
	zr, err := zlib.NewReader(countingReader)
	if err != nil {
		if errors.Is(err, zlib.ErrChecksum) {
			return nil, ErrZlibChecksumFailed
		}
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			return nil, ErrTruncatedZlibStream
		}
		return nil, ErrInvalidZlibStream
	}

	var decompressed bytes.Buffer
	// Limit decompression up to maxObjectSize + 1024 header margin
	safetyLimit := maxObjectSize + 1024
	limitedReader := io.LimitReader(zr, safetyLimit+1)
	n, readErr := io.Copy(&decompressed, limitedReader)
	closeErr := zr.Close()

	if readErr != nil {
		if errors.Is(readErr, zlib.ErrChecksum) {
			return nil, ErrZlibChecksumFailed
		}
		if errors.Is(readErr, io.ErrUnexpectedEOF) || errors.Is(readErr, io.EOF) {
			return nil, ErrTruncatedZlibStream
		}
		return nil, ErrInvalidZlibStream
	}

	if closeErr != nil {
		if errors.Is(closeErr, zlib.ErrChecksum) {
			return nil, ErrZlibChecksumFailed
		}
		if errors.Is(closeErr, io.ErrUnexpectedEOF) || errors.Is(closeErr, io.EOF) {
			return nil, ErrTruncatedZlibStream
		}
		return nil, ErrInvalidZlibStream
	}

	if n > safetyLimit {
		return nil, ErrObjectTooLarge
	}

	bytesConsumed := countingReader.BytesRead()
	trailingBytes := int64(len(rawBytes)) - bytesConsumed
	if trailingBytes < 0 {
		trailingBytes = 0
	}

	objType, declaredSize, payload, err := ParseEnvelope(decompressed.Bytes(), maxObjectSize)
	if err != nil {
		return nil, err
	}

	computedOID := ComputeEnvelopeSHA1(objType, declaredSize, payload)
	integrityMismatch := false
	oid := expectedOID
	if oid == "" {
		oid = computedOID
	} else if expectedOID != computedOID {
		integrityMismatch = true
	}

	return &Object{
		Type:               objType,
		Size:               declaredSize,
		Payload:            payload,
		ID:                 oid,
		ComputedID:         computedOID,
		IntegrityMismatch:  integrityMismatch,
		TrailingBytesCount: trailingBytes,
	}, nil
}

// ReadLooseObject reads, decompresses, and parses a loose object from disk.
func ReadLooseObject(gitDir string, oid string, maxObjectSize int64) (*Object, error) {
	path, err := LooseObjectPath(gitDir, oid)
	if err != nil {
		return nil, err
	}
	rawBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecodeLooseObjectBytes(rawBytes, oid, maxObjectSize)
}
