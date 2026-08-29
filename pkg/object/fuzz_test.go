package object

import "testing"

// FuzzParseEnvelope verifies that ParseEnvelope never panics on arbitrary byte sequences.
func FuzzParseEnvelope(f *testing.F) {
	f.Add([]byte("blob 0\x00"))
	f.Add([]byte("blob 13\x00test content\n"))
	f.Add([]byte("tree 0\x00"))
	f.Add([]byte("commit 0\x00"))
	f.Add([]byte("tag 0\x00"))
	f.Add([]byte("blob 9999999999999999999999999999999999999999\x00data"))
	f.Add([]byte("invalid envelope header without null"))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = ParseEnvelope(data, DefaultMaxObjectSize)
	})
}

// FuzzDecodeLooseObjectBytes verifies that DecodeLooseObjectBytes never panics on arbitrary byte sequences.
func FuzzDecodeLooseObjectBytes(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not valid zlib data"))
	f.Add(compressZlib([]byte("blob 0\x00")))
	f.Add(compressZlib([]byte("blob 13\x00test content\n")))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeLooseObjectBytes(data, "", DefaultMaxObjectSize)
	})
}
