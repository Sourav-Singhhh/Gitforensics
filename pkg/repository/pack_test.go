package repository

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"gitforensics/pkg/object"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Helper: compress data with zlib
func compressZlibData(data []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// Helper: encode pack entry header
func encodePackEntryHeader(objType int, size int64) []byte {
	var out []byte
	b := byte((objType&0x07)<<4) | byte(size&0x0F)
	size >>= 4
	for size > 0 {
		b |= 0x80
		out = append(out, b)
		b = byte(size & 0x7F)
		size >>= 7
	}
	out = append(out, b)
	return out
}

// Helper: encode OFS_DELTA base offset using Git's exact +1 continuation rule (§16)
func encodeOfsOffset(offset int64) []byte {
	var buf [16]byte
	pos := len(buf) - 1
	buf[pos] = byte(offset & 0x7F)
	for {
		offset = (offset >> 7) - 1
		if offset < 0 {
			break
		}
		pos--
		buf[pos] = byte((offset & 0x7F) | 0x80)
	}
	return buf[pos:]
}

// Helper: encode standard LEB128 varint for delta sizes
func encodeLEB128(size int64) []byte {
	var out []byte
	for {
		b := byte(size & 0x7F)
		size >>= 7
		if size > 0 {
			b |= 0x80
			out = append(out, b)
		} else {
			out = append(out, b)
			break
		}
	}
	return out
}

// Helper: finalize pack by appending trailing 20-byte SHA-1 checksum
func finalizePack(packData []byte) []byte {
	h := sha1.New()
	h.Write(packData)
	checksum := h.Sum(nil)
	return append(packData, checksum...)
}

func TestPackHeaderValidation(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Invalid Magic
	badMagicPack := make([]byte, 32)
	copy(badMagicPack[0:4], "NOPE")
	binary.BigEndian.PutUint32(badMagicPack[4:8], 2)
	badMagicFile := filepath.Join(tempDir, "bad_magic.pack")
	_ = os.WriteFile(badMagicFile, finalizePack(badMagicPack[:12]), 0644)

	_, err := ParsePackFile(badMagicFile, 0, 0)
	if !errors.Is(err, object.ErrNotAPackFile) {
		t.Errorf("expected ErrNotAPackFile for bad magic, got %v", err)
	}

	// 2. Unsupported Version (v3)
	unsupportedVerPack := make([]byte, 12)
	copy(unsupportedVerPack[0:4], "PACK")
	binary.BigEndian.PutUint32(unsupportedVerPack[4:8], 3)
	binary.BigEndian.PutUint32(unsupportedVerPack[8:12], 0)
	badVerFile := filepath.Join(tempDir, "bad_ver.pack")
	_ = os.WriteFile(badVerFile, finalizePack(unsupportedVerPack), 0644)

	_, err = ParsePackFile(badVerFile, 0, 0)
	if !errors.Is(err, object.ErrUnsupportedPackVersion) {
		t.Errorf("expected ErrUnsupportedPackVersion for v3, got %v", err)
	}

	// 3. Truncated container (<32 bytes)
	truncFile := filepath.Join(tempDir, "trunc.pack")
	_ = os.WriteFile(truncFile, []byte("PACK\x00\x00\x00\x02"), 0644)
	_, err = ParsePackFile(truncFile, 0, 0)
	if !errors.Is(err, object.ErrNotAPackFile) {
		t.Errorf("expected ErrNotAPackFile for truncated container, got %v", err)
	}
}

func TestPackNonDeltaObjects(t *testing.T) {
	tempDir := t.TempDir()

	// Build a pack with 4 non-delta objects: commit, tree, blob, tag
	blobPayload := []byte("Hello, GitForensics packed object storage!")
	treePayload := []byte("100644 file.txt\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14")
	commitPayload := []byte("tree 0102030405060708090a0b0c0d0e0f1011121314\nauthor A <a@b.c> 1000 +0000\ncommitter A <a@b.c> 1000 +0000\n\nCommit\n")
	tagPayload := []byte("object 0102030405060708090a0b0c0d0e0f1011121314\ntype commit\ntag v1.0\ntagger A <a@b.c> 1000 +0000\n\nTag\n")

	var packBuf bytes.Buffer
	packBuf.WriteString("PACK")
	_ = binary.Write(&packBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(&packBuf, binary.BigEndian, uint32(4))

	// Write entries
	entries := []struct {
		objType int
		payload []byte
	}{
		{PackTypeBlob, blobPayload},
		{PackTypeTree, treePayload},
		{PackTypeCommit, commitPayload},
		{PackTypeTag, tagPayload},
	}

	for _, e := range entries {
		hdr := encodePackEntryHeader(e.objType, int64(len(e.payload)))
		comp := compressZlibData(e.payload)
		packBuf.Write(hdr)
		packBuf.Write(comp)
	}

	packFile := filepath.Join(tempDir, "valid_nondelta.pack")
	_ = os.WriteFile(packFile, finalizePack(packBuf.Bytes()), 0644)

	res, err := ParsePackFile(packFile, 0, 0)
	if err != nil {
		t.Fatalf("ParsePackFile failed: %v", err)
	}

	if res.DeclaredCount != 4 || res.DecodedCount != 4 {
		t.Errorf("expected 4 decoded objects, got declared=%d, decoded=%d", res.DeclaredCount, res.DecodedCount)
	}
	if res.ChecksumMismatch {
		t.Errorf("expected valid checksum")
	}

	// Verify all 4 objects
	expectedBlobOID := object.ComputeEnvelopeSHA1(object.TypeBlob, int64(len(blobPayload)), blobPayload)
	expectedTreeOID := object.ComputeEnvelopeSHA1(object.TypeTree, int64(len(treePayload)), treePayload)
	expectedCommitOID := object.ComputeEnvelopeSHA1(object.TypeCommit, int64(len(commitPayload)), commitPayload)
	expectedTagOID := object.ComputeEnvelopeSHA1(object.TypeTag, int64(len(tagPayload)), tagPayload)

	if res.Objects[expectedBlobOID] == nil || res.Objects[expectedBlobOID].Type != object.TypeBlob {
		t.Errorf("missing or invalid blob object: %s", expectedBlobOID)
	}
	if res.Objects[expectedTreeOID] == nil || res.Objects[expectedTreeOID].Type != object.TypeTree {
		t.Errorf("missing or invalid tree object: %s", expectedTreeOID)
	}
	if res.Objects[expectedCommitOID] == nil || res.Objects[expectedCommitOID].Type != object.TypeCommit {
		t.Errorf("missing or invalid commit object: %s", expectedCommitOID)
	}
	if res.Objects[expectedTagOID] == nil || res.Objects[expectedTagOID].Type != object.TypeTag {
		t.Errorf("missing or invalid tag object: %s", expectedTagOID)
	}
}

func TestPackChecksumMismatchRetention(t *testing.T) {
	tempDir := t.TempDir()

	blobPayload := []byte("Checksum mismatch test blob content")
	var packBuf bytes.Buffer
	packBuf.WriteString("PACK")
	_ = binary.Write(&packBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(&packBuf, binary.BigEndian, uint32(1))

	hdr := encodePackEntryHeader(PackTypeBlob, int64(len(blobPayload)))
	comp := compressZlibData(blobPayload)
	packBuf.Write(hdr)
	packBuf.Write(comp)

	// Append a corrupted 20-byte checksum (all 0xFF)
	packBytes := packBuf.Bytes()
	corruptedPack := append(packBytes, bytes.Repeat([]byte{0xFF}, 20)...)

	packFile := filepath.Join(tempDir, "corrupt_checksum.pack")
	_ = os.WriteFile(packFile, corruptedPack, 0644)

	res, err := ParsePackFile(packFile, 0, 0)
	if err != nil {
		t.Fatalf("ParsePackFile must not fail on checksum mismatch: %v", err)
	}

	if !res.ChecksumMismatch {
		t.Errorf("expected ChecksumMismatch to be true")
	}

	// Crucial Invariant (§16): Valid objects MUST be retained despite checksum failure
	blobOID := object.ComputeEnvelopeSHA1(object.TypeBlob, int64(len(blobPayload)), blobPayload)
	if res.Objects[blobOID] == nil {
		t.Fatalf("valid decoded object %s was improperly discarded due to checksum mismatch", blobOID)
	}

	// Verify anomaly recorded
	foundAnomaly := false
	for _, a := range res.Anomalies {
		if a.Type == "PACK_CHECKSUM_MISMATCH" {
			foundAnomaly = true
			break
		}
	}
	if !foundAnomaly {
		t.Errorf("expected PACK_CHECKSUM_MISMATCH anomaly recorded")
	}
}

func TestOfsDeltaPlusOneEncoding(t *testing.T) {
	// Verify the +1 continuation rule for multi-byte offsets independently
	testOffsets := []int64{1, 10, 127, 128, 130, 300, 16384, 65536, 1000000}

	for _, offset := range testOffsets {
		encoded := encodeOfsOffset(offset)

		// Decode using the exact Git OFS algorithm (§16)
		b := encoded[0]
		decoded := int64(b & 0x7F)
		idx := 1
		for (b & 0x80) != 0 {
			decoded++
			b = encoded[idx]
			idx++
			decoded = (decoded << 7) | int64(b&0x7F)
		}

		if decoded != offset {
			t.Errorf("OFS +1 encoding mismatch for %d: got %d (bytes: %x)", offset, decoded, encoded)
		}
	}
}

func TestOfsDeltaChainsAndMemoization(t *testing.T) {
	tempDir := t.TempDir()

	// Base Blob: "Base content line 1\nBase content line 2\n"
	basePayload := []byte("Base content line 1\nBase content line 2\n")

	// Delta 1: Insert "Header\n" (7 bytes) + Copy 40 bytes of Base
	// Delta instruction: sourceSize=40, targetSize=47
	var delta1Instructions []byte
	delta1Instructions = append(delta1Instructions, encodeLEB128(int64(len(basePayload)))...)
	delta1Instructions = append(delta1Instructions, encodeLEB128(47)...)
	// INSERT 7 bytes: "Header\n"
	delta1Instructions = append(delta1Instructions, 0x07)
	delta1Instructions = append(delta1Instructions, []byte("Header\n")...)
	// COPY offset=0, size=40: cmd = 0x80 | 0x01 | 0x10 = 0x91
	delta1Instructions = append(delta1Instructions, 0x91, 0x00, 40)

	expectedDelta1Payload := append([]byte("Header\n"), basePayload...)

	// Delta 2 (Chained on Delta 1): Copy 47 bytes from Delta 1 + Insert "Footer\n" (7 bytes) -> total 54 bytes
	var delta2Instructions []byte
	delta2Instructions = append(delta2Instructions, encodeLEB128(47)...)
	delta2Instructions = append(delta2Instructions, encodeLEB128(54)...)
	// COPY offset=0, size=47: cmd = 0x91
	delta2Instructions = append(delta2Instructions, 0x91, 0x00, 47)
	// INSERT 7 bytes: "Footer\n"
	delta2Instructions = append(delta2Instructions, 0x07)
	delta2Instructions = append(delta2Instructions, []byte("Footer\n")...)

	expectedDelta2Payload := append(append([]byte{}, expectedDelta1Payload...), []byte("Footer\n")...)

	// Build Pack
	var packBuf bytes.Buffer
	packBuf.WriteString("PACK")
	_ = binary.Write(&packBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(&packBuf, binary.BigEndian, uint32(3))

	// Entry 1: Base Blob at offset 12
	baseOffset := packBuf.Len()
	baseHdr := encodePackEntryHeader(PackTypeBlob, int64(len(basePayload)))
	baseComp := compressZlibData(basePayload)
	packBuf.Write(baseHdr)
	packBuf.Write(baseComp)

	// Entry 2: OFS_DELTA 1
	delta1EntryOffset := packBuf.Len()
	delta1NegativeOffset := int64(delta1EntryOffset - baseOffset)
	delta1Hdr := encodePackEntryHeader(PackTypeOfsDelta, int64(len(delta1Instructions)))
	delta1OfsBytes := encodeOfsOffset(delta1NegativeOffset)
	delta1Comp := compressZlibData(delta1Instructions)
	packBuf.Write(delta1Hdr)
	packBuf.Write(delta1OfsBytes)
	packBuf.Write(delta1Comp)

	// Entry 3: OFS_DELTA 2 (chained on Entry 2)
	delta2EntryOffset := packBuf.Len()
	delta2NegativeOffset := int64(delta2EntryOffset - delta1EntryOffset)
	delta2Hdr := encodePackEntryHeader(PackTypeOfsDelta, int64(len(delta2Instructions)))
	delta2OfsBytes := encodeOfsOffset(delta2NegativeOffset)
	delta2Comp := compressZlibData(delta2Instructions)
	packBuf.Write(delta2Hdr)
	packBuf.Write(delta2OfsBytes)
	packBuf.Write(delta2Comp)

	packFile := filepath.Join(tempDir, "ofs_chained.pack")
	_ = os.WriteFile(packFile, finalizePack(packBuf.Bytes()), 0644)

	res, err := ParsePackFile(packFile, 0, 0)
	if err != nil {
		t.Fatalf("ParsePackFile on OFS chained pack failed: %v", err)
	}

	if len(res.Objects) != 3 {
		t.Fatalf("expected 3 resolved objects, got %d", len(res.Objects))
	}

	baseOID := object.ComputeEnvelopeSHA1(object.TypeBlob, int64(len(basePayload)), basePayload)
	d1OID := object.ComputeEnvelopeSHA1(object.TypeBlob, int64(len(expectedDelta1Payload)), expectedDelta1Payload)
	d2OID := object.ComputeEnvelopeSHA1(object.TypeBlob, int64(len(expectedDelta2Payload)), expectedDelta2Payload)

	if res.Objects[baseOID] == nil || string(res.Objects[baseOID].Payload) != string(basePayload) {
		t.Errorf("base blob resolution failed")
	}
	if res.Objects[d1OID] == nil || string(res.Objects[d1OID].Payload) != string(expectedDelta1Payload) {
		t.Errorf("delta 1 reconstruction failed: got %q, expected %q", res.Objects[d1OID].Payload, expectedDelta1Payload)
	}
	if res.Objects[d2OID] == nil || string(res.Objects[d2OID].Payload) != string(expectedDelta2Payload) {
		t.Errorf("chained delta 2 reconstruction failed: got %q, expected %q", res.Objects[d2OID].Payload, expectedDelta2Payload)
	}
}

func TestDeltaCopySizeZeroExpansion(t *testing.T) {
	// Mandatory Special Rule (§17): When size == 0 in COPY instruction, size is exactly 65536
	base := bytes.Repeat([]byte("A"), 70000)

	var instructions []byte
	instructions = append(instructions, encodeLEB128(int64(len(base)))...)
	instructions = append(instructions, encodeLEB128(65536)...)
	// COPY offset=0, size=0 (no size bytes encoded, cmd=0x80 | 0x01 = 0x81)
	instructions = append(instructions, 0x81, 0x00)

	reconstructed, err := ApplyDelta(base, instructions)
	if err != nil {
		t.Fatalf("ApplyDelta failed on copy size zero rule: %v", err)
	}

	if len(reconstructed) != 65536 {
		t.Errorf("expected 65536 reconstructed bytes, got %d", len(reconstructed))
	}
	if !bytes.Equal(reconstructed, base[:65536]) {
		t.Errorf("reconstructed content mismatch")
	}
}

func TestDeltaAdversarialCases(t *testing.T) {
	base := []byte("0123456789ABCDEF")

	// 1. Invalid instruction 0x00
	var inst0 []byte
	inst0 = append(inst0, encodeLEB128(int64(len(base)))...)
	inst0 = append(inst0, encodeLEB128(10)...)
	inst0 = append(inst0, 0x00)
	_, err := ApplyDelta(base, inst0)
	if !errors.Is(err, object.ErrInvalidDeltaInstruction) {
		t.Errorf("expected ErrInvalidDeltaInstruction for 0x00 cmd, got %v", err)
	}

	// 2. Copy Out of Bounds
	var instOOB []byte
	instOOB = append(instOOB, encodeLEB128(int64(len(base)))...)
	instOOB = append(instOOB, encodeLEB128(10)...)
	// COPY off=10, size=10 (len(base)=16, 10+10=20 > 16)
	instOOB = append(instOOB, 0x91, 10, 10)
	_, err = ApplyDelta(base, instOOB)
	if !errors.Is(err, object.ErrDeltaCopyOutOfBounds) {
		t.Errorf("expected ErrDeltaCopyOutOfBounds, got %v", err)
	}

	// 3. Base size mismatch
	var instSizeMismatch []byte
	instSizeMismatch = append(instSizeMismatch, encodeLEB128(999)...)
	instSizeMismatch = append(instSizeMismatch, encodeLEB128(10)...)
	_, err = ApplyDelta(base, instSizeMismatch)
	if !errors.Is(err, object.ErrDeltaBaseSizeMismatch) {
		t.Errorf("expected ErrDeltaBaseSizeMismatch, got %v", err)
	}

	// 4. Trailing instruction data
	var instTrailing []byte
	instTrailing = append(instTrailing, encodeLEB128(int64(len(base)))...)
	instTrailing = append(instTrailing, encodeLEB128(5)...)
	instTrailing = append(instTrailing, 0x05, '1', '2', '3', '4', '5')
	instTrailing = append(instTrailing, 0x01, 'X') // trailing
	_, err = ApplyDelta(base, instTrailing)
	if !errors.Is(err, object.ErrDeltaTrailingInstructionData) {
		t.Errorf("expected ErrDeltaTrailingInstructionData, got %v", err)
	}

	// 5. Insert size 1 and size 127 boundaries
	var instBoundaries []byte
	instBoundaries = append(instBoundaries, encodeLEB128(int64(len(base)))...)
	instBoundaries = append(instBoundaries, encodeLEB128(1+127)...)
	// Insert 1
	instBoundaries = append(instBoundaries, 0x01, 'Z')
	// Insert 127
	instBoundaries = append(instBoundaries, 0x7F)
	instBoundaries = append(instBoundaries, bytes.Repeat([]byte{'W'}, 127)...)
	res, err := ApplyDelta(base, instBoundaries)
	if err != nil {
		t.Fatalf("boundary test failed: %v", err)
	}
	if len(res) != 128 || res[0] != 'Z' || res[1] != 'W' {
		t.Errorf("unexpected boundary result")
	}
}

func TestDeltaCycleAndDepthLimit(t *testing.T) {
	// Create cyclic entries: Entry A (offset 100, Base 200), Entry B (offset 200, Base 100)
	rawEntries := []RawPackEntry{
		{
			Offset:          100,
			Type:            PackTypeOfsDelta,
			BaseOffset:      200,
			InflatedPayload: append(append(encodeLEB128(10), encodeLEB128(10)...), 0x01, 'A'),
		},
		{
			Offset:          200,
			Type:            PackTypeOfsDelta,
			BaseOffset:      100,
			InflatedPayload: append(append(encodeLEB128(10), encodeLEB128(10)...), 0x01, 'B'),
		},
	}

	resolved, _, anomalies := ResolveDeltaChains(rawEntries, 50)
	if len(resolved) != 0 {
		t.Errorf("expected 0 resolved objects for cyclic delta chain")
	}
	foundCycleAnomaly := false
	for _, a := range anomalies {
		if strings.Contains(a.Description, "cycle") {
			foundCycleAnomaly = true
			break
		}
	}
	if !foundCycleAnomaly {
		t.Errorf("expected delta cycle anomaly to be recorded")
	}
}

func TestUnsupportedRefDeltaCoverageGap(t *testing.T) {
	tempDir := t.TempDir()

	var packBuf bytes.Buffer
	packBuf.WriteString("PACK")
	_ = binary.Write(&packBuf, binary.BigEndian, uint32(2))
	_ = binary.Write(&packBuf, binary.BigEndian, uint32(1))

	// REF_DELTA entry with arbitrary 20-byte base OID
	refBaseOIDBytes := bytes.Repeat([]byte{0xAB}, 20)
	hdr := encodePackEntryHeader(PackTypeRefDelta, 10)
	comp := compressZlibData([]byte("delta payload"))

	packBuf.Write(hdr)
	packBuf.Write(refBaseOIDBytes)
	packBuf.Write(comp)

	packFile := filepath.Join(tempDir, "ref_delta.pack")
	_ = os.WriteFile(packFile, finalizePack(packBuf.Bytes()), 0644)

	res, err := ParsePackFile(packFile, 0, 0)
	if err != nil {
		t.Fatalf("ParsePackFile failed: %v", err)
	}

	// Invariant (§18): REF_DELTA must be recorded as coverage gap and NOT resolved as an object
	if len(res.Objects) != 0 {
		t.Errorf("expected 0 resolved objects for REF_DELTA, got %d", len(res.Objects))
	}
	if len(res.CoverageGaps) != 1 {
		t.Fatalf("expected 1 coverage gap for REF_DELTA, got %d", len(res.CoverageGaps))
	}
	if res.CoverageGaps[0].Type != "unresolvedPackOnly" {
		t.Errorf("expected coverage gap type unresolvedPackOnly, got %s", res.CoverageGaps[0].Type)
	}
}
