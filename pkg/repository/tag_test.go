package repository

import (
	"errors"
	"fmt"
	"gitforensics/pkg/object"
	"testing"
)

// mockStore provides an in-memory ObjectStore for testing tag peeling.
type mockStore struct {
	objects map[string]*object.Object
}

func (m *mockStore) Get(oid string) (*object.Object, error) {
	obj, exists := m.objects[oid]
	if !exists {
		return nil, object.ErrObjectNotFound
	}
	return obj, nil
}

func (m *mockStore) Exists(oid string) bool {
	_, exists := m.objects[oid]
	return exists
}

func TestMinimalTagPeeling(t *testing.T) {
	commitOID := "1111111111111111111111111111111111111111"
	tagOID := "2222222222222222222222222222222222222222"

	store := &mockStore{
		objects: map[string]*object.Object{
			commitOID: {
				Type:    object.TypeCommit,
				ID:      commitOID,
				Payload: []byte("tree ...\n"),
			},
			tagOID: {
				Type:    object.TypeTag,
				ID:      tagOID,
				Payload: []byte("object " + commitOID + "\ntype commit\ntag v1.0\n"),
			},
		},
	}

	targetOID, targetType, err := PeelTag(store, tagOID, 10)
	if err != nil {
		t.Fatalf("PeelTag failed: %v", err)
	}
	if targetOID != commitOID {
		t.Errorf("expected target OID %s, got %s", commitOID, targetOID)
	}
	if targetType != object.TypeCommit {
		t.Errorf("expected target type %v, got %v", object.TypeCommit, targetType)
	}
}

func TestNestedTagPeeling(t *testing.T) {
	blobOID := "1111111111111111111111111111111111111111"
	tag1 := "2222222222222222222222222222222222222222"
	tag2 := "3333333333333333333333333333333333333333"

	store := &mockStore{
		objects: map[string]*object.Object{
			blobOID: {
				Type:    object.TypeBlob,
				ID:      blobOID,
				Payload: []byte("blob content"),
			},
			tag1: {
				Type:    object.TypeTag,
				ID:      tag1,
				Payload: []byte("object " + blobOID + "\ntype blob\ntag inner\n"),
			},
			tag2: {
				Type:    object.TypeTag,
				ID:      tag2,
				Payload: []byte("object " + tag1 + "\ntype tag\ntag outer\n"),
			},
		},
	}

	targetOID, targetType, err := PeelTag(store, tag2, 10)
	if err != nil {
		t.Fatalf("nested PeelTag failed: %v", err)
	}
	if targetOID != blobOID {
		t.Errorf("expected target OID %s, got %s", blobOID, targetOID)
	}
	if targetType != object.TypeBlob {
		t.Errorf("expected target type %v, got %v", object.TypeBlob, targetType)
	}
}

func TestTagPeelCycle(t *testing.T) {
	tag1 := "1111111111111111111111111111111111111111"
	tag2 := "2222222222222222222222222222222222222222"

	store := &mockStore{
		objects: map[string]*object.Object{
			tag1: {
				Type:    object.TypeTag,
				ID:      tag1,
				Payload: []byte("object " + tag2 + "\ntype tag\ntag t1\n"),
			},
			tag2: {
				Type:    object.TypeTag,
				ID:      tag2,
				Payload: []byte("object " + tag1 + "\ntype tag\ntag t2\n"),
			},
		},
	}

	_, _, err := PeelTag(store, tag1, 10)
	if !errors.Is(err, object.ErrSymbolicRefCycle) {
		t.Fatalf("expected ErrSymbolicRefCycle, got %v", err)
	}
}

func TestTagPeelDepthLimit(t *testing.T) {
	// Chain of 15 tags pointing to each other
	store := &mockStore{objects: make(map[string]*object.Object)}
	for i := 0; i < 15; i++ {
		currOID := fmt.Sprintf("%040d", i)
		nextOID := fmt.Sprintf("%040d", i+1)
		store.objects[currOID] = &object.Object{
			Type:    object.TypeTag,
			ID:      currOID,
			Payload: []byte("object " + nextOID + "\ntype tag\n"),
		}
	}

	startOID := fmt.Sprintf("%040d", 0)
	_, _, err := PeelTag(store, startOID, 10)
	if !errors.Is(err, object.ErrMaxPeelDepthExceeded) {
		t.Fatalf("expected ErrMaxPeelDepthExceeded, got %v", err)
	}
}
