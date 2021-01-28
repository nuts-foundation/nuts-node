package vdr

import (
	"testing"

	"github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

type didStoreMock struct {
	err error
}

func (d didStoreMock) Resolve(id did.DID, metadata *types.ResolveMetadata) (*did.Document, *types.DocumentMetadata, error) {
	if d.err != nil {
		return nil, nil, d.err
	}
	return &did.Document{ID: id}, &types.DocumentMetadata{}, nil
}

func (d didStoreMock) Write(document did.Document, metadata types.DocumentMetadata) error {
	panic("implement me")
}

func (d didStoreMock) Update(id did.DID, current hash.SHA256Hash, next did.Document, metadata *types.DocumentMetadata) error {
	panic("implement me")
}

func Test_ambassador_resolveDIDControllers(t *testing.T) {
	n := ambassador{
		didStore: didStoreMock{},
	}
	t.Run("ok - document has no controllers, it should return the doc", func(t *testing.T) {
		id, err := did.ParseDID("did:nuts:123")
		if !assert.NoError(t, err) {
			return
		}
		nextDoc := &did.Document{ID: *id}
		got, err := n.resolveDIDControllers(nextDoc)
		assert.Len(t, got, 1)
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:123", got[0].ID.String())
	})

	t.Run("ok - document has controllers, it should return the controllers", func(t *testing.T) {
		id, _ := did.ParseDID("did:nuts:123")
		ctrlID1, _ := did.ParseDID("did:nuts:abc")
		ctrlID2, _ := did.ParseDID("did:nuts:456")
		nextDoc := &did.Document{ID: *id, Controller: []did.DID{*ctrlID1, *ctrlID2}}

		got, err := n.resolveDIDControllers(nextDoc)
		assert.Len(t, got, 2)
		assert.NoError(t, err)
		assert.Equal(t, "did:nuts:abc", got[0].ID.String())
		assert.Equal(t, "did:nuts:456", got[1].ID.String())
	})

	t.Run("nok - document has unknown controllers, it should return an error", func(t *testing.T) {
		am := ambassador{
			didStore: didStoreMock{ err: types.ErrNotFound},
		}
		id, _ := did.ParseDID("did:nuts:123")
		ctrlID1, _ := did.ParseDID("did:nuts:abc")
		ctrlID2, _ := did.ParseDID("did:nuts:456")
		nextDoc := &did.Document{ID: *id, Controller: []did.DID{*ctrlID1, *ctrlID2}}
		got, err := am.resolveDIDControllers(nextDoc)
		assert.Empty(t, got)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unable to resolve document controller: unable to find the did document")
	})
}
