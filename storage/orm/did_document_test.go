package orm

import (
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
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

func TestDIDDocument_FromDIDDocument(t *testing.T) {
	created := time.Now()
	updated := created.Add(time.Second)
	version := 4
	vms := []VerificationMethod{
		{
			ID:       "#1",
			Data:     []byte(`{"id":"#1"}`),
			KeyTypes: VerificationMethodKeyType(AssertionMethodUsage | KeyAgreementUsage),
		}, {
			ID:       "#2",
			Data:     []byte(`{"id":"#2"}`),
			KeyTypes: VerificationMethodKeyType(KeyAgreementUsage),
		},
	}
	service := Service{
		ID:   "#service",
		Data: []byte(`{"id":"#service"}`),
	}
	didDoc, err := DidDocument{
		DID:                 DID{ID: alice.String()},
		VerificationMethods: vms,
		Services:            []Service{service},
		CreatedAt:           created.Unix(),
		UpdatedAt:           updated.Unix(),
	}.ToDIDDocument()
	require.NoError(t, err)
	docRaw, err := json.Marshal(didDoc)
	require.NoError(t, err)

	result, err := MigrationDocument{
		Version: version,
		Created: created,
		Updated: updated,
		Raw:     docRaw,
	}.ToORMDocument("test-subject")
	require.NoError(t, err)

	assert.NotEmpty(t, result.ID)
	assert.Equal(t, alice.String(), result.DidID)
	assert.Equal(t, created.Unix(), result.CreatedAt)
	assert.Equal(t, updated.Unix(), result.UpdatedAt)
	assert.Equal(t, version, result.Version)

	// DID
	assert.Equal(t, DID{
		ID:      alice.String(),
		Subject: "test-subject",
	}, result.DID)

	// Services
	require.Len(t, result.Services, 1)
	assert.Equal(t, service, result.Services[0])

	// VerificationMethods
	require.Len(t, result.VerificationMethods, 2)
	assert.Equal(t, "#1", result.VerificationMethods[0].ID)
	assert.Equal(t, VerificationMethodKeyType(AssertionMethodUsage|KeyAgreementUsage), result.VerificationMethods[0].KeyTypes)
	assert.Equal(t, "#2", result.VerificationMethods[1].ID)
	assert.Equal(t, VerificationMethodKeyType(KeyAgreementUsage), result.VerificationMethods[1].KeyTypes)
}
