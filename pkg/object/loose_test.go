package object

import (
	"bytes"
	"compress/zlib"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// helper to compress bytes with standard zlib
func compressZlib(data []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// 1. Canonical empty blob ("blob 0\0")
func TestCanonicalEmptyBlob(t *testing.T) {
	rawEnvelope := []byte("blob 0\x00")
	compressed := compressZlib(rawEnvelope)

	expectedSHA := "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
	obj, err := DecodeLooseObjectBytes(compressed, expectedSHA, 0)
	if err != nil {
		t.Fatalf("unexpected error decoding empty blob: %v", err)
	}

	if obj.Type != TypeBlob {
		t.Errorf("expected type %v, got %v", TypeBlob, obj.Type)
	}
	if obj.Size != 0 {
		t.Errorf("expected size 0, got %d", obj.Size)
	}
	if len(obj.Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(obj.Payload))
	}
	if obj.ComputedID != expectedSHA {
		t.Errorf("expected computed SHA %s, got %s", expectedSHA, obj.ComputedID)
	}
	if obj.IntegrityMismatch {
		t.Errorf("expected IntegrityMismatch=false, got true")
	}
	if obj.TrailingBytesCount != 0 {
		t.Errorf("expected TrailingBytesCount=0, got %d", obj.TrailingBytesCount)
	}
}

// 2. Known non-empty blob ("blob 13\0test content\n")
func TestKnownNonEmptyBlob(t *testing.T) {
	payload := []byte("test content\n")
	rawEnvelope := append([]byte("blob 13\x00"), payload...)
	compressed := compressZlib(rawEnvelope)

	expectedSHA := "d670460b4b4aece5915caf5c68d12f560a9fe3e4"
	obj, err := DecodeLooseObjectBytes(compressed, expectedSHA, 0)
	if err != nil {
		t.Fatalf("unexpected error decoding non-empty blob: %v", err)
	}

	if obj.Type != TypeBlob {
		t.Errorf("expected type %v, got %v", TypeBlob, obj.Type)
	}
	if obj.Size != 13 {
		t.Errorf("expected size 13, got %d", obj.Size)
	}
	if !bytes.Equal(obj.Payload, payload) {
		t.Errorf("payload mismatch: expected %q, got %q", payload, obj.Payload)
	}
	if obj.ComputedID != expectedSHA {
		t.Errorf("expected computed SHA %s, got %s", expectedSHA, obj.ComputedID)
	}
	if obj.IntegrityMismatch {
		t.Errorf("expected IntegrityMismatch=false, got true")
	}
}

// 3. Missing NUL terminator
func TestMissingNULTerminator(t *testing.T) {
	rawEnvelope := []byte("blob 5hello")
	compressed := compressZlib(rawEnvelope)

	_, err := DecodeLooseObjectBytes(compressed, "", 0)
	if !errors.Is(err, ErrMissingHeaderTerminator) {
		t.Fatalf("expected ErrMissingHeaderTerminator, got %v", err)
	}
}

// 4. Non-numeric size field ("blob abc\0hello")
func TestNonNumericSize(t *testing.T) {
	rawEnvelope := []byte("blob abc\x00hello")
	compressed := compressZlib(rawEnvelope)

	_, err := DecodeLooseObjectBytes(compressed, "", 0)
	if !errors.Is(err, ErrMalformedSize) {
		t.Fatalf("expected ErrMalformedSize, got %v", err)
	}
}

// 5. Declared size larger than payload ("blob 10\0hello")
func TestDeclaredSizeLargerThanPayload(t *testing.T) {
	rawEnvelope := []byte("blob 10\x00hello")
	compressed := compressZlib(rawEnvelope)

	_, err := DecodeLooseObjectBytes(compressed, "", 0)
	if !errors.Is(err, ErrTruncatedPayload) {
		t.Fatalf("expected ErrTruncatedPayload, got %v", err)
	}
}

// 6. Declared size smaller than payload ("blob 3\0hello")
func TestDeclaredSizeSmallerThanPayload(t *testing.T) {
	rawEnvelope := []byte("blob 3\x00hello")
	compressed := compressZlib(rawEnvelope)

	_, err := DecodeLooseObjectBytes(compressed, "", 0)
	if !errors.Is(err, ErrTrailingPayloadData) {
		t.Fatalf("expected ErrTrailingPayloadData, got %v", err)
	}
}

// 7. Unknown object type ("widget 4\0data")
func TestUnknownObjectType(t *testing.T) {
	rawEnvelope := []byte("widget 4\x00data")
	compressed := compressZlib(rawEnvelope)

	_, err := DecodeLooseObjectBytes(compressed, "", 0)
	if !errors.Is(err, ErrUnknownObjectType) {
		t.Fatalf("expected ErrUnknownObjectType, got %v", err)
	}
}

// 8. Near-miss type ("blobb 4\0data")
func TestNearMissObjectType(t *testing.T) {
	rawEnvelope := []byte("blobb 4\x00data")
	compressed := compressZlib(rawEnvelope)

	_, err := DecodeLooseObjectBytes(compressed, "", 0)
	if !errors.Is(err, ErrUnknownObjectType) {
		t.Fatalf("expected ErrUnknownObjectType, got %v", err)
	}
}

// 9a. Corrupted zlib header -> ErrInvalidZlibStream
func TestCorruptedZlibHeader(t *testing.T) {
	rawEnvelope := []byte("blob 13\x00test content\n")
	compressed := compressZlib(rawEnvelope)

	// Flip bits in the 2-byte zlib header (CMF/FLG)
	corrupted := make([]byte, len(compressed))
	copy(corrupted, compressed)
	corrupted[0] ^= 0xFF

	_, err := DecodeLooseObjectBytes(corrupted, "", 0)
	if !errors.Is(err, ErrInvalidZlibStream) {
		t.Fatalf("expected ErrInvalidZlibStream for corrupted header, got %v", err)
	}
}

// 9b. Corrupted zlib DEFLATE payload -> ErrInvalidZlibStream
func TestCorruptedZlibDeflateStream(t *testing.T) {
	rawEnvelope := []byte("blob 13\x00test content\n")
	compressed := compressZlib(rawEnvelope)

	// In a valid zlib stream: [2 bytes header (0, 1)] [deflate body (2...)] [4 bytes adler32]
	// Setting byte 2 to 0x07 (BFINAL=1, BTYPE=11 reserved) triggers flate.CorruptInputError
	corrupted := make([]byte, len(compressed))
	copy(corrupted, compressed)
	corrupted[2] = 0x07

	_, err := DecodeLooseObjectBytes(corrupted, "", 0)
	if !errors.Is(err, ErrInvalidZlibStream) {
		t.Fatalf("expected ErrInvalidZlibStream for corrupted deflate stream, got %v", err)
	}
}

// 9c. Corrupted zlib Adler-32 checksum -> ErrZlibChecksumFailed
func TestCorruptedZlibChecksum(t *testing.T) {
	rawEnvelope := []byte("blob 13\x00test content\n")
	compressed := compressZlib(rawEnvelope)

	// Flip bits in the 4-byte Adler32 checksum at the very end of the zlib stream
	corrupted := make([]byte, len(compressed))
	copy(corrupted, compressed)
	corrupted[len(corrupted)-1] ^= 0xFF

	_, err := DecodeLooseObjectBytes(corrupted, "", 0)
	if !errors.Is(err, ErrZlibChecksumFailed) {
		t.Fatalf("expected ErrZlibChecksumFailed for corrupted adler32 checksum, got %v", err)
	}
}

// 10. Truncated zlib stream -> ErrTruncatedZlibStream
func TestTruncatedZlibStream(t *testing.T) {
	rawEnvelope := []byte("blob 13\x00test content\n")
	compressed := compressZlib(rawEnvelope)

	// Truncate compressed stream mid-deflate
	truncated := compressed[:len(compressed)/2]

	_, err := DecodeLooseObjectBytes(truncated, "", 0)
	if !errors.Is(err, ErrTruncatedZlibStream) {
		t.Fatalf("expected ErrTruncatedZlibStream for truncated stream, got %v", err)
	}
}

// 11. Path / hash mismatch
func TestPathHashMismatch(t *testing.T) {
	rawEnvelope := []byte("blob 13\x00test content\n")
	compressed := compressZlib(rawEnvelope)

	expectedPathOID := "0000000000000000000000000000000000000000"
	computedSHA := "d670460b4b4aece5915caf5c68d12f560a9fe3e4"

	obj, err := DecodeLooseObjectBytes(compressed, expectedPathOID, 0)
	if err != nil {
		t.Fatalf("unexpected error on path mismatch: %v", err)
	}
	if !obj.IntegrityMismatch {
		t.Errorf("expected IntegrityMismatch=true, got false")
	}
	if obj.ID != expectedPathOID {
		t.Errorf("expected ID %s, got %s", expectedPathOID, obj.ID)
	}
	if obj.ComputedID != computedSHA {
		t.Errorf("expected ComputedID %s, got %s", computedSHA, obj.ComputedID)
	}
}

// 12. 40-digit size overflow (assert no panic)
func TestSizeOverflowNoPanic(t *testing.T) {
	rawEnvelope := []byte("blob 9999999999999999999999999999999999999999\x00data")
	compressed := compressZlib(rawEnvelope)

	_, err := DecodeLooseObjectBytes(compressed, "", 0)
	if !errors.Is(err, ErrMalformedSize) {
		t.Fatalf("expected ErrMalformedSize on overflow, got %v", err)
	}
}

// 13. Valid object followed by trailing bytes (lenient + recorded policy)
func TestTrailingBytesRecorded(t *testing.T) {
	rawEnvelope := []byte("blob 13\x00test content\n")
	compressed := compressZlib(rawEnvelope)

	trailingJunk := []byte("EXTRA_TRAILING_BYTES_JUNK_DATA!!")
	withTrailing := append(compressed, trailingJunk...)

	expectedSHA := "d670460b4b4aece5915caf5c68d12f560a9fe3e4"
	obj, err := DecodeLooseObjectBytes(withTrailing, expectedSHA, 0)
	if err != nil {
		t.Fatalf("unexpected error with trailing bytes: %v", err)
	}

	if obj.TrailingBytesCount != int64(len(trailingJunk)) {
		t.Errorf("expected TrailingBytesCount=%d, got %d", len(trailingJunk), obj.TrailingBytesCount)
	}
	if obj.ComputedID != expectedSHA {
		t.Errorf("expected ComputedID %s, got %s", expectedSHA, obj.ComputedID)
	}
}

// 14. "blob 00\0" malformed leading zero
func TestMalformedLeadingZeroSize(t *testing.T) {
	rawEnvelope := []byte("blob 00\x00")
	compressed := compressZlib(rawEnvelope)

	_, err := DecodeLooseObjectBytes(compressed, "", 0)
	if !errors.Is(err, ErrMalformedSize) {
		t.Fatalf("expected ErrMalformedSize for '00', got %v", err)
	}
}

// 15. "blob 0\0x" trailing payload data
func TestTrailingPayloadData(t *testing.T) {
	rawEnvelope := []byte("blob 0\x00x")
	compressed := compressZlib(rawEnvelope)

	_, err := DecodeLooseObjectBytes(compressed, "", 0)
	if !errors.Is(err, ErrTrailingPayloadData) {
		t.Fatalf("expected ErrTrailingPayloadData, got %v", err)
	}
}

// 16. "blob 1\0" truncated payload
func TestTruncatedPayload(t *testing.T) {
	rawEnvelope := []byte("blob 1\x00")
	compressed := compressZlib(rawEnvelope)

	_, err := DecodeLooseObjectBytes(compressed, "", 0)
	if !errors.Is(err, ErrTruncatedPayload) {
		t.Fatalf("expected ErrTruncatedPayload, got %v", err)
	}
}

// 17. Valid tree envelope recognition
func TestCanonicalEmptyTreeEnvelope(t *testing.T) {
	rawEnvelope := []byte("tree 0\x00")
	compressed := compressZlib(rawEnvelope)

	expectedSHA := "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
	obj, err := DecodeLooseObjectBytes(compressed, expectedSHA, 0)
	if err != nil {
		t.Fatalf("unexpected error decoding empty tree: %v", err)
	}
	if obj.Type != TypeTree {
		t.Errorf("expected type %v, got %v", TypeTree, obj.Type)
	}
	if obj.ComputedID != expectedSHA {
		t.Errorf("expected computed SHA %s, got %s", expectedSHA, obj.ComputedID)
	}
}

// 18. Valid commit and tag envelope recognition
func TestCommitAndTagEnvelopes(t *testing.T) {
	commitEnvelope := []byte("commit 0\x00")
	cObj, err := DecodeLooseObjectBytes(compressZlib(commitEnvelope), "", 0)
	if err != nil {
		t.Fatalf("unexpected error for commit: %v", err)
	}
	if cObj.Type != TypeCommit {
		t.Errorf("expected type %v, got %v", TypeCommit, cObj.Type)
	}

	tagEnvelope := []byte("tag 0\x00")
	tObj, err := DecodeLooseObjectBytes(compressZlib(tagEnvelope), "", 0)
	if err != nil {
		t.Fatalf("unexpected error for tag: %v", err)
	}
	if tObj.Type != TypeTag {
		t.Errorf("expected type %v, got %v", TypeTag, tObj.Type)
	}
}

// 19. OID validation tests
func TestValidateOID(t *testing.T) {
	// Valid
	if err := ValidateOID("e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"); err != nil {
		t.Errorf("expected valid OID, got %v", err)
	}

	// Uppercase
	if err := ValidateOID("E69DE29BB2D1D6434B8B29AE775AD8C2E48C5391"); !errors.Is(err, ErrInvalidOID) {
		t.Errorf("expected ErrInvalidOID on uppercase, got %v", err)
	}

	// Wrong length (short)
	if err := ValidateOID("e69de29bb2d1d6434b8b29ae775ad8c2e48c539"); !errors.Is(err, ErrInvalidOID) {
		t.Errorf("expected ErrInvalidOID on short length, got %v", err)
	}

	// Wrong length (long)
	if err := ValidateOID("e69de29bb2d1d6434b8b29ae775ad8c2e48c539100"); !errors.Is(err, ErrInvalidOID) {
		t.Errorf("expected ErrInvalidOID on long length, got %v", err)
	}

	// Invalid non-hex characters
	if err := ValidateOID("g69de29bb2d1d6434b8b29ae775ad8c2e48c5391"); !errors.Is(err, ErrInvalidOID) {
		t.Errorf("expected ErrInvalidOID on non-hex, got %v", err)
	}
}

// 20. ReadLooseObject on-disk integration
func TestReadLooseObjectOnDisk(t *testing.T) {
	tempDir := t.TempDir()
	oid := "d670460b4b4aece5915caf5c68d12f560a9fe3e4"
	objDir := filepath.Join(tempDir, "objects", oid[:2])
	if err := os.MkdirAll(objDir, 0755); err != nil {
		t.Fatalf("failed to create object dir: %v", err)
	}

	payload := []byte("test content\n")
	rawEnvelope := append([]byte("blob 13\x00"), payload...)
	compressed := compressZlib(rawEnvelope)

	objPath := filepath.Join(objDir, oid[2:])
	if err := os.WriteFile(objPath, compressed, 0644); err != nil {
		t.Fatalf("failed to write object file: %v", err)
	}

	obj, err := ReadLooseObject(tempDir, oid, 0)
	if err != nil {
		t.Fatalf("ReadLooseObject failed: %v", err)
	}

	if obj.ID != oid {
		t.Errorf("expected ID %s, got %s", oid, obj.ID)
	}
	if obj.ComputedID != oid {
		t.Errorf("expected ComputedID %s, got %s", oid, obj.ComputedID)
	}
	if obj.IntegrityMismatch {
		t.Errorf("expected IntegrityMismatch=false, got true")
	}
	if !bytes.Equal(obj.Payload, payload) {
		t.Errorf("payload mismatch: expected %q, got %q", payload, obj.Payload)
	}
}

// 21. MaxObjectSize safety ceiling enforcement
func TestMaxObjectSizeEnforcement(t *testing.T) {
	payload := []byte("large content exceeding ceiling")
	rawEnvelope := append([]byte("blob 31\x00"), payload...)
	compressed := compressZlib(rawEnvelope)

	// Ceiling set to 10 bytes -> should error ErrObjectTooLarge
	_, err := DecodeLooseObjectBytes(compressed, "", 10)
	if !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("expected ErrObjectTooLarge, got %v", err)
	}
}

// 22. Stored/uncompressed DEFLATE blocks followed by trailing bytes
func TestStoredBlockTrailingBytes(t *testing.T) {
	payload := []byte("uncompressed stored block test payload\n")
	rawEnvelope := append([]byte("blob 39\x00"), payload...)

	// Compress using zlib with NoCompression (stored blocks)
	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.NoCompression)
	if err != nil {
		t.Fatalf("failed to create uncompressed zlib writer: %v", err)
	}
	_, _ = w.Write(rawEnvelope)
	_ = w.Close()
	compressed := buf.Bytes()

	trailingJunk := []byte("EXTRA_GARBAGE_AFTER_STORED_BLOCKS_1234567890")
	withTrailing := append(compressed, trailingJunk...)

	expectedSHA := ComputeEnvelopeSHA1(TypeBlob, 39, payload)
	obj, err := DecodeLooseObjectBytes(withTrailing, expectedSHA, 0)
	if err != nil {
		t.Fatalf("unexpected error on stored block with trailing bytes: %v", err)
	}

	if obj.TrailingBytesCount != int64(len(trailingJunk)) {
		t.Errorf("expected TrailingBytesCount=%d, got %d", len(trailingJunk), obj.TrailingBytesCount)
	}
	if !bytes.Equal(obj.Payload, payload) {
		t.Errorf("payload mismatch: expected %q, got %q", payload, obj.Payload)
	}
	if obj.ComputedID != expectedSHA {
		t.Errorf("computed SHA mismatch: expected %s, got %s", expectedSHA, obj.ComputedID)
	}
	if obj.IntegrityMismatch {
		t.Errorf("expected IntegrityMismatch=false, got true")
	}
}

// 23. Decompression bomb bounded execution (high compression ratio, small maxObjectSize)
func TestDecompressionBombBounded(t *testing.T) {
	// Create repetitive 100 KB payload that compresses to ~100 bytes
	repetitivePayload := bytes.Repeat([]byte("A"), 100*1024)
	rawEnvelope := append([]byte("blob 102400\x00"), repetitivePayload...)

	var buf bytes.Buffer
	w, err := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	if err != nil {
		t.Fatalf("failed to create zlib writer: %v", err)
	}
	_, _ = w.Write(rawEnvelope)
	_ = w.Close()
	compressed := buf.Bytes()

	// With maxObjectSize = 1024, decompression must terminate early with ErrObjectTooLarge
	_, err = DecodeLooseObjectBytes(compressed, "", 1024)
	if !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("expected ErrObjectTooLarge on decompression bomb, got %v", err)
	}
}
