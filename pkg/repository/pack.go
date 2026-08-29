package repository

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"gitforensics/pkg/object"
	"io"
	"os"
)

// Pack constants (§16, §17, §19)
const (
	PackMagic                  = "PACK"
	SupportedPackVersion       = 2
	DefaultMaxDeltaDepth       = 50
	DefaultMaxPackFileSize     = 512 * 1024 * 1024 // 512 MiB safety ceiling (§19)
	MaxEntryHeaderContinuation = 9                 // Max continuation bytes for entry header size
	MaxOfsOffsetContinuation   = 10                // Max continuation bytes for OFS_DELTA base offset
	MaxCopyInstructionSize     = 65536

	// Pack Object Types (§16)
	PackTypeCommit   = 1
	PackTypeTree     = 2
	PackTypeBlob     = 3
	PackTypeTag      = 4
	PackTypeOfsDelta = 6
	PackTypeRefDelta = 7
)

// PackAnomaly represents a non-fatal integrity or formatting issue encountered in a packfile.
type PackAnomaly struct {
	Type        string
	Location    string
	Description string
}

// PackCoverageGap represents an uninspected area or unsupported pack feature.
type PackCoverageGap struct {
	Type        string
	Location    string
	Description string
}

// RawPackEntry represents a parsed pack entry prior to delta chain resolution (§16).
type RawPackEntry struct {
	Offset            int64
	Type              int
	DeclaredSize      int64
	BaseOffset        int64  // Valid when Type == PackTypeOfsDelta
	RefBaseOID        string // Valid when Type == PackTypeRefDelta
	InflatedPayload   []byte // Non-delta payload or delta instruction stream
	ResolvedObject    *object.Object
	ResolutionError   error
	HeaderError       error
	SizeMismatchError error
}

// PackFileResult holds the complete result of parsing and resolving a packfile (§16).
type PackFileResult struct {
	Path             string
	Version          uint32
	DeclaredCount    uint32
	DecodedCount     int
	Checksum         [20]byte
	ComputedChecksum [20]byte
	ChecksumMismatch bool
	Objects          map[string]*object.Object
	ObjectList       []*object.Object
	CoverageGaps     []PackCoverageGap
	Anomalies        []PackAnomaly
}

// CountingByteReader wraps an io.Reader and counts exact bytes read.
type countingByteReader struct {
	r     *bytes.Reader
	count int
}

func (c *countingByteReader) ReadByte() (byte, error) {
	b, err := c.r.ReadByte()
	if err == nil {
		c.count++
	}
	return b, err
}

func (c *countingByteReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.count += n
	return n, err
}

// ParsePackFile parses a Git PACK version 2 container, extracts non-delta and OFS_DELTA objects,
// verifies pack checksums, and resolves delta chains (§16, §17, §18, §19).
func ParsePackFile(path string, maxObjectSize int64, maxDeltaDepth int) (*PackFileResult, error) {
	if maxObjectSize <= 0 {
		maxObjectSize = object.DefaultMaxObjectSize
	}
	if maxDeltaDepth <= 0 {
		maxDeltaDepth = DefaultMaxDeltaDepth
	}

	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > DefaultMaxPackFileSize {
		return &PackFileResult{
			Path:         path,
			Objects:      make(map[string]*object.Object),
			ObjectList:   make([]*object.Object, 0),
			CoverageGaps: []PackCoverageGap{},
			Anomalies: []PackAnomaly{
				{
					Type:        "PACK_TOO_LARGE",
					Location:    path,
					Description: fmt.Sprintf("pack file size (%d bytes) exceeds safety ceiling (%d bytes)", fi.Size(), DefaultMaxPackFileSize),
				},
			},
		}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	// 1. Pack Container Size & Header Validation
	if len(data) < 32 { // 12 bytes header + 20 bytes checksum
		return nil, object.ErrNotAPackFile
	}

	if string(data[0:4]) != PackMagic {
		return nil, object.ErrNotAPackFile
	}

	version := binary.BigEndian.Uint32(data[4:8])
	if version != SupportedPackVersion {
		return nil, object.ErrUnsupportedPackVersion
	}

	declaredCount := binary.BigEndian.Uint32(data[8:12])

	// 2. Pack Checksum Verification
	var storedChecksum [20]byte
	copy(storedChecksum[:], data[len(data)-20:])

	hasher := sha1.New()
	hasher.Write(data[:len(data)-20])
	var computedChecksum [20]byte
	copy(computedChecksum[:], hasher.Sum(nil))

	checksumMismatch := !bytes.Equal(storedChecksum[:], computedChecksum[:])

	result := &PackFileResult{
		Path:             path,
		Version:          version,
		DeclaredCount:    declaredCount,
		Checksum:         storedChecksum,
		ComputedChecksum: computedChecksum,
		ChecksumMismatch: checksumMismatch,
		Objects:          make(map[string]*object.Object),
		ObjectList:       make([]*object.Object, 0),
		CoverageGaps:     make([]PackCoverageGap, 0),
		Anomalies:        make([]PackAnomaly, 0),
	}

	if checksumMismatch {
		result.Anomalies = append(result.Anomalies, PackAnomaly{
			Type:        "PACK_CHECKSUM_MISMATCH",
			Location:    path,
			Description: fmt.Sprintf("pack checksum mismatch: stored %s, computed %s", hex.EncodeToString(storedChecksum[:]), hex.EncodeToString(computedChecksum[:])),
		})
	}

	// 3. Sequentially Parse Entries
	packDataEnd := len(data) - 20
	currentOffset := 12
	var rawEntries []RawPackEntry

	for currentOffset < packDataEnd && uint32(len(rawEntries)) < declaredCount {
		entryStartOffset := int64(currentOffset)

		// Decode Entry Header
		b := data[currentOffset]
		currentOffset++

		continuation := (b & 0x80) != 0
		rawType := int((b >> 4) & 0x07)
		size := int64(b & 0x0F)
		shift := 4
		continuationCount := 0

		var headerErr error
		for continuation {
			continuationCount++
			if continuationCount > MaxEntryHeaderContinuation {
				headerErr = object.ErrPackEntrySizeTooLarge
				break
			}
			if currentOffset >= packDataEnd {
				headerErr = object.ErrTruncatedPackEntry
				break
			}

			b = data[currentOffset]
			currentOffset++
			continuation = (b & 0x80) != 0
			size |= int64(b&0x7F) << shift
			shift += 7
			if size < 0 {
				headerErr = object.ErrPackEntrySizeTooLarge
				break
			}
		}

		if headerErr != nil {
			result.Anomalies = append(result.Anomalies, PackAnomaly{
				Type:        "PACK_TRUNCATED_OR_CORRUPTED",
				Location:    fmt.Sprintf("%s:%d", path, entryStartOffset),
				Description: fmt.Sprintf("pack entry header error at offset %d: %v", entryStartOffset, headerErr),
			})
			break
		}

		// Validate raw type
		if rawType == 0 || rawType == 5 || rawType > 7 {
			result.Anomalies = append(result.Anomalies, PackAnomaly{
				Type:        "PACK_TRUNCATED_OR_CORRUPTED",
				Location:    fmt.Sprintf("%s:%d", path, entryStartOffset),
				Description: fmt.Sprintf("invalid pack entry type %d at offset %d", rawType, entryStartOffset),
			})
			break
		}

		entry := RawPackEntry{
			Offset:       entryStartOffset,
			Type:         rawType,
			DeclaredSize: size,
		}

		// Handle OFS_DELTA base offset
		if rawType == PackTypeOfsDelta {
			if currentOffset >= packDataEnd {
				entry.ResolutionError = object.ErrTruncatedOfsDeltaOffset
				result.Anomalies = append(result.Anomalies, PackAnomaly{
					Type:        "PACK_TRUNCATED_OR_CORRUPTED",
					Location:    fmt.Sprintf("%s:%d", path, entryStartOffset),
					Description: "truncated OFS_DELTA offset",
				})
				rawEntries = append(rawEntries, entry)
				break
			}

			bOfs := data[currentOffset]
			currentOffset++
			ofs := int64(bOfs & 0x7F)
			ofsShiftCount := 0
			ofsTruncated := false

			for (bOfs & 0x80) != 0 {
				ofsShiftCount++
				if ofsShiftCount > MaxOfsOffsetContinuation {
					entry.ResolutionError = object.ErrInvalidOfsDeltaOffset
					break
				}
				if currentOffset >= packDataEnd {
					ofsTruncated = true
					break
				}
				ofs++
				if ofs <= 0 {
					entry.ResolutionError = object.ErrInvalidOfsDeltaOffset
					break
				}
				bOfs = data[currentOffset]
				currentOffset++
				ofs = (ofs << 7) | int64(bOfs&0x7F)
				if ofs <= 0 {
					entry.ResolutionError = object.ErrInvalidOfsDeltaOffset
					break
				}
			}

			if ofsTruncated {
				entry.ResolutionError = object.ErrTruncatedOfsDeltaOffset
				result.Anomalies = append(result.Anomalies, PackAnomaly{
					Type:        "PACK_TRUNCATED_OR_CORRUPTED",
					Location:    fmt.Sprintf("%s:%d", path, entryStartOffset),
					Description: "truncated OFS_DELTA offset",
				})
				rawEntries = append(rawEntries, entry)
				break
			}

			baseOffset := entryStartOffset - ofs
			if ofs <= 0 || baseOffset >= entryStartOffset || baseOffset < 12 {
				entry.ResolutionError = object.ErrInvalidOfsDeltaOffset
			}
			entry.BaseOffset = baseOffset
		} else if rawType == PackTypeRefDelta {
			// Read 20-byte base OID
			if currentOffset+20 > packDataEnd {
				result.Anomalies = append(result.Anomalies, PackAnomaly{
					Type:        "PACK_TRUNCATED_OR_CORRUPTED",
					Location:    fmt.Sprintf("%s:%d", path, entryStartOffset),
					Description: "truncated REF_DELTA base OID",
				})
				break
			}
			entry.RefBaseOID = hex.EncodeToString(data[currentOffset : currentOffset+20])
			currentOffset += 20
		}

		// Decompress payload via zlib with exact boundary accounting
		byteReader := &countingByteReader{
			r: bytes.NewReader(data[currentOffset:packDataEnd]),
		}

		zlibReader, zErr := zlib.NewReader(byteReader)
		if zErr != nil {
			result.Anomalies = append(result.Anomalies, PackAnomaly{
				Type:        "PACK_TRUNCATED_OR_CORRUPTED",
				Location:    fmt.Sprintf("%s:%d", path, entryStartOffset),
				Description: fmt.Sprintf("failed to initialize zlib reader at offset %d: %v", entryStartOffset, zErr),
			})
			break
		}

		// Read decompressed payload bounded by maxObjectSize
		limitReader := io.LimitReader(zlibReader, maxObjectSize+1)
		var inflatedBuf bytes.Buffer
		_, readErr := io.Copy(&inflatedBuf, limitReader)
		_ = zlibReader.Close()

		if readErr != nil {
			result.Anomalies = append(result.Anomalies, PackAnomaly{
				Type:        "PACK_TRUNCATED_OR_CORRUPTED",
				Location:    fmt.Sprintf("%s:%d", path, entryStartOffset),
				Description: fmt.Sprintf("zlib inflate failed at offset %d: %v", entryStartOffset, readErr),
			})
			break
		}

		if int64(inflatedBuf.Len()) > maxObjectSize {
			result.Anomalies = append(result.Anomalies, PackAnomaly{
				Type:        "PACK_TRUNCATED_OR_CORRUPTED",
				Location:    fmt.Sprintf("%s:%d", path, entryStartOffset),
				Description: fmt.Sprintf("decompressed size %d exceeds safety limit %d", inflatedBuf.Len(), maxObjectSize),
			})
			break
		}

		compressedBytesConsumed := byteReader.count
		currentOffset += compressedBytesConsumed

		inflated := inflatedBuf.Bytes()
		entry.InflatedPayload = inflated

		// Verify non-delta inflated size
		if rawType >= 1 && rawType <= 4 {
			if int64(len(inflated)) != size {
				entry.SizeMismatchError = object.ErrPackObjectSizeMismatch
			}
		}

		rawEntries = append(rawEntries, entry)
	}

	result.DecodedCount = len(rawEntries)
	if uint32(len(rawEntries)) != declaredCount {
		result.Anomalies = append(result.Anomalies, PackAnomaly{
			Type:        "PACK_COUNT_MISMATCH",
			Location:    path,
			Description: fmt.Sprintf("pack entry count mismatch: declared %d, successfully parsed %d", declaredCount, len(rawEntries)),
		})
	}

	// 4. Resolve Non-Delta and Chained OFS_DELTA objects
	resolvedMap, coverageGaps, deltaAnomalies := ResolveDeltaChains(rawEntries, maxDeltaDepth)
	result.CoverageGaps = append(result.CoverageGaps, coverageGaps...)
	result.Anomalies = append(result.Anomalies, deltaAnomalies...)
	result.Objects = resolvedMap

	// Maintain deterministic list ordered by pack offset
	for _, entry := range rawEntries {
		if entry.ResolvedObject != nil {
			result.ObjectList = append(result.ObjectList, entry.ResolvedObject)
		}
	}

	return result, nil
}

// decodeLEB128Size reads a standard 7-bit continuation size from a byte slice.
func decodeLEB128Size(data []byte) (int64, int, error) {
	if len(data) == 0 {
		return 0, 0, object.ErrTruncatedDeltaInstruction
	}
	var size int64
	var shift uint
	for i, b := range data {
		if shift >= 64 {
			return 0, 0, object.ErrPackEntrySizeTooLarge
		}
		size |= int64(b&0x7F) << shift
		shift += 7
		if (b & 0x80) == 0 {
			return size, i + 1, nil
		}
	}
	return 0, 0, object.ErrTruncatedDeltaInstruction
}

// ApplyDelta reconstructs a target payload from base payload and delta instructions (§17).
func ApplyDelta(basePayload, deltaInstructions []byte) ([]byte, error) {
	if len(deltaInstructions) == 0 {
		return nil, object.ErrTruncatedDeltaInstruction
	}

	// 1. Decode source size
	sourceSize, n1, err := decodeLEB128Size(deltaInstructions)
	if err != nil {
		return nil, err
	}
	if sourceSize != int64(len(basePayload)) {
		return nil, object.ErrDeltaBaseSizeMismatch
	}

	// 2. Decode target size
	targetSize, n2, err := decodeLEB128Size(deltaInstructions[n1:])
	if err != nil {
		return nil, err
	}
	if targetSize < 0 {
		return nil, object.ErrPackEntrySizeTooLarge
	}

	result := make([]byte, 0, targetSize)
	idx := n1 + n2

	// 3. Execute instruction stream
	for idx < len(deltaInstructions) && int64(len(result)) < targetSize {
		cmd := deltaInstructions[idx]
		idx++

		if (cmd & 0x80) != 0 {
			// COPY instruction
			var off int64
			var size int64

			if (cmd & 0x01) != 0 {
				if idx >= len(deltaInstructions) {
					return nil, object.ErrTruncatedDeltaInstruction
				}
				off |= int64(deltaInstructions[idx])
				idx++
			}
			if (cmd & 0x02) != 0 {
				if idx >= len(deltaInstructions) {
					return nil, object.ErrTruncatedDeltaInstruction
				}
				off |= int64(deltaInstructions[idx]) << 8
				idx++
			}
			if (cmd & 0x04) != 0 {
				if idx >= len(deltaInstructions) {
					return nil, object.ErrTruncatedDeltaInstruction
				}
				off |= int64(deltaInstructions[idx]) << 16
				idx++
			}
			if (cmd & 0x08) != 0 {
				if idx >= len(deltaInstructions) {
					return nil, object.ErrTruncatedDeltaInstruction
				}
				off |= int64(deltaInstructions[idx]) << 24
				idx++
			}

			if (cmd & 0x10) != 0 {
				if idx >= len(deltaInstructions) {
					return nil, object.ErrTruncatedDeltaInstruction
				}
				size |= int64(deltaInstructions[idx])
				idx++
			}
			if (cmd & 0x20) != 0 {
				if idx >= len(deltaInstructions) {
					return nil, object.ErrTruncatedDeltaInstruction
				}
				size |= int64(deltaInstructions[idx]) << 8
				idx++
			}
			if (cmd & 0x40) != 0 {
				if idx >= len(deltaInstructions) {
					return nil, object.ErrTruncatedDeltaInstruction
				}
				size |= int64(deltaInstructions[idx]) << 16
				idx++
			}

			// Mandatory Special Rule (§17): size == 0 means 65536
			if size == 0 {
				size = MaxCopyInstructionSize
			}

			// Validate bounds
			if off < 0 || size <= 0 || off > int64(len(basePayload)) || (off+size) > int64(len(basePayload)) || (off+size) < 0 {
				return nil, object.ErrDeltaCopyOutOfBounds
			}

			if int64(len(result))+size > targetSize {
				return nil, object.ErrDeltaReconstructionSizeMismatch
			}

			result = append(result, basePayload[off:off+size]...)
		} else if cmd > 0 {
			// INSERT instruction (1..127 bytes)
			size := int64(cmd)
			if int64(idx)+size > int64(len(deltaInstructions)) {
				return nil, object.ErrTruncatedDeltaInstruction
			}
			if int64(len(result))+size > targetSize {
				return nil, object.ErrDeltaReconstructionSizeMismatch
			}
			result = append(result, deltaInstructions[idx:idx+int(size)]...)
			idx += int(size)
		} else {
			// cmd == 0x00 is invalid / reserved
			return nil, object.ErrInvalidDeltaInstruction
		}
	}

	if int64(len(result)) != targetSize {
		return nil, object.ErrDeltaReconstructionSizeMismatch
	}

	if idx < len(deltaInstructions) {
		return nil, object.ErrDeltaTrailingInstructionData
	}

	return result, nil
}

// packTypeToObjectType maps pack entry type numbers to canonical ObjectType.
func packTypeToObjectType(t int) (object.ObjectType, bool) {
	switch t {
	case PackTypeCommit:
		return object.TypeCommit, true
	case PackTypeTree:
		return object.TypeTree, true
	case PackTypeBlob:
		return object.TypeBlob, true
	case PackTypeTag:
		return object.TypeTag, true
	default:
		return "", false
	}
}

// createCanonicalObject reconstructs canonical Git envelope and computes object ID.
func createCanonicalObject(objType object.ObjectType, payload []byte) *object.Object {
	oid := object.ComputeEnvelopeSHA1(objType, int64(len(payload)), payload)
	return &object.Object{
		ID:                 oid,
		Type:               objType,
		Size:               int64(len(payload)),
		Payload:            payload,
		ComputedID:         oid,
		IntegrityMismatch:  false,
		TrailingBytesCount: 0,
	}
}

type resolvedPayload struct {
	payload []byte
	objType object.ObjectType
	err     error
}

// ResolveDeltaChains resolves non-delta and chained OFS_DELTA objects with memoization,
// cycle detection, and configurable depth limit (§17).
func ResolveDeltaChains(
	entries []RawPackEntry,
	maxDeltaDepth int,
) (map[string]*object.Object, []PackCoverageGap, []PackAnomaly) {
	if maxDeltaDepth <= 0 {
		maxDeltaDepth = DefaultMaxDeltaDepth
	}

	entriesByOffset := make(map[int64]*RawPackEntry, len(entries))
	for i := range entries {
		entriesByOffset[entries[i].Offset] = &entries[i]
	}

	memo := make(map[int64]*resolvedPayload, len(entries))
	resolvedObjects := make(map[string]*object.Object)
	var coverageGaps []PackCoverageGap
	var anomalies []PackAnomaly

	var resolveEntry func(entry *RawPackEntry, depth int, resolving map[int64]bool) ([]byte, object.ObjectType, error)

	resolveEntry = func(entry *RawPackEntry, depth int, resolving map[int64]bool) ([]byte, object.ObjectType, error) {
		if entry == nil {
			return nil, "", object.ErrInvalidOfsDeltaOffset
		}

		if entry.HeaderError != nil {
			return nil, "", entry.HeaderError
		}

		if memoized, exists := memo[entry.Offset]; exists {
			return memoized.payload, memoized.objType, memoized.err
		}

		// Non-delta entry (1..4)
		if entry.Type >= 1 && entry.Type <= 4 {
			if entry.SizeMismatchError != nil {
				memo[entry.Offset] = &resolvedPayload{err: entry.SizeMismatchError}
				return nil, "", entry.SizeMismatchError
			}
			objType, ok := packTypeToObjectType(entry.Type)
			if !ok {
				err := object.ErrInvalidPackEntryType
				memo[entry.Offset] = &resolvedPayload{err: err}
				return nil, "", err
			}
			memo[entry.Offset] = &resolvedPayload{
				payload: entry.InflatedPayload,
				objType: objType,
			}
			return entry.InflatedPayload, objType, nil
		}

		// REF_DELTA (unsupported)
		if entry.Type == PackTypeRefDelta {
			err := object.ErrUnsupportedRefDelta
			memo[entry.Offset] = &resolvedPayload{err: err}
			return nil, "", err
		}

		// OFS_DELTA
		if entry.Type == PackTypeOfsDelta {
			if entry.ResolutionError != nil {
				memo[entry.Offset] = &resolvedPayload{err: entry.ResolutionError}
				return nil, "", entry.ResolutionError
			}

			if depth > maxDeltaDepth {
				err := object.ErrMaxDeltaDepthExceeded
				memo[entry.Offset] = &resolvedPayload{err: err}
				return nil, "", err
			}

			if resolving[entry.Offset] {
				err := object.ErrDeltaChainCycleDetected
				memo[entry.Offset] = &resolvedPayload{err: err}
				return nil, "", err
			}

			resolving[entry.Offset] = true
			defer delete(resolving, entry.Offset)

			baseEntry := entriesByOffset[entry.BaseOffset]
			if baseEntry == nil {
				err := object.ErrInvalidOfsDeltaOffset
				memo[entry.Offset] = &resolvedPayload{err: err}
				return nil, "", err
			}

			basePayload, baseType, err := resolveEntry(baseEntry, depth+1, resolving)
			if err != nil {
				memo[entry.Offset] = &resolvedPayload{err: err}
				return nil, "", err
			}

			reconstructed, deltaErr := ApplyDelta(basePayload, entry.InflatedPayload)
			if deltaErr != nil {
				memo[entry.Offset] = &resolvedPayload{err: deltaErr}
				return nil, "", deltaErr
			}

			memo[entry.Offset] = &resolvedPayload{
				payload: reconstructed,
				objType: baseType,
			}
			return reconstructed, baseType, nil
		}

		err := object.ErrInvalidPackEntryType
		memo[entry.Offset] = &resolvedPayload{err: err}
		return nil, "", err
	}

	for i := range entries {
		entry := &entries[i]

		if entry.Type == PackTypeRefDelta {
			coverageGaps = append(coverageGaps, PackCoverageGap{
				Type:        "unresolvedPackOnly",
				Location:    fmt.Sprintf("pack_offset:%d", entry.Offset),
				Description: fmt.Sprintf("unsupported REF_DELTA targeting base %s", entry.RefBaseOID),
			})
			continue
		}

		payload, objType, err := resolveEntry(entry, 0, make(map[int64]bool))
		if err != nil {
			entry.ResolutionError = err
			anomalies = append(anomalies, PackAnomaly{
				Type:        "CORRUPTED_PACK_ENTRY",
				Location:    fmt.Sprintf("pack_offset:%d", entry.Offset),
				Description: fmt.Sprintf("failed to resolve pack entry at offset %d: %v", entry.Offset, err),
			})
			continue
		}

		obj := createCanonicalObject(objType, payload)
		entry.ResolvedObject = obj
		resolvedObjects[obj.ID] = obj
	}

	return resolvedObjects, coverageGaps, anomalies
}
