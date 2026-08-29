package repository

import (
	"gitforensics/pkg/object"
	"os"
)

// ObjectStore is the storage-agnostic interface for retrieving Git objects by OID.
// Traversal and classification layers interact strictly with this abstraction,
// allowing future packfile storage implementations without modifying graph algorithms.
type ObjectStore interface {
	// Get retrieves a canonical Git object by its 40-character hexadecimal OID.
	// Returns object.ErrObjectNotFound if the object does not exist in storage.
	Get(oid string) (*object.Object, error)

	// Exists returns true if the object exists in storage without fully decompressing it.
	Exists(oid string) bool
}

// LooseStore provides an ObjectStore implementation backed by on-disk loose Git objects.
type LooseStore struct {
	gitDir  string
	maxSize int64
}

// NewLooseStore creates a new LooseStore rooted at the given git administrative directory.
func NewLooseStore(gitDir string, maxSize int64) *LooseStore {
	if maxSize <= 0 {
		maxSize = object.DefaultMaxObjectSize
	}
	return &LooseStore{
		gitDir:  gitDir,
		maxSize: maxSize,
	}
}

// Get reads and decodes a loose object from disk.
func (s *LooseStore) Get(oid string) (*object.Object, error) {
	obj, err := object.ReadLooseObject(s.gitDir, oid, s.maxSize)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, object.ErrObjectNotFound
		}
		return nil, err
	}
	return obj, nil
}

// Exists checks whether a loose object file exists on disk.
func (s *LooseStore) Exists(oid string) bool {
	path, err := object.LooseObjectPath(s.gitDir, oid)
	if err != nil {
		return false
	}
	_, statErr := os.Stat(path)
	return statErr == nil
}
