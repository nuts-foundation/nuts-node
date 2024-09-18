package orm

import (
	"github.com/nuts-foundation/go-did/did"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	alice = did.MustParseDID("did:web:example.com:iam:alice")
	bob   = did.MustParseDID("did:web:example.com:iam:bob")
)

func TestDIDDocument_ToDIDDocument(t *testing.T) {
	vmData := `{"id":"#1"}`
	serviceData := `{"id":"#2"}`
	keyUsageFlag := VerificationMethodKeyType(31)
	vm := VerificationMethod{
		ID:       "#1",
		Data:     []byte(vmData),
		KeyTypes: keyUsageFlag,
	}
	service := Service{
		ID:   "#2",
		Data: []byte(serviceData),
	}
	document := DidDocument{
		ID:                  "id",
		DID:                 DID{ID: alice.String()},
		Version:             1,
		VerificationMethods: []VerificationMethod{vm},
		Services:            []Service{service},
	}

	didDoc, err := document.ToDIDDocument()
	require.NoError(t, err)

	assert.Len(t, didDoc.Context, 2)
	assert.Equal(t, alice, didDoc.ID)
	require.Len(t, didDoc.VerificationMethod, 1)
	require.Len(t, didDoc.Service, 1)
	assert.Equal(t, "#1", didDoc.VerificationMethod[0].ID.String())
	assert.Equal(t, "#2", didDoc.Service[0].ID.String())
}
