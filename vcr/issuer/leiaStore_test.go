package issuer

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewLeiaStore(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		sut, err := NewLeiaStore(testDir)

		assert.NoError(t, err)
		assert.IsType(t, &leiaStore{}, sut)
	})

	t.Run("error", func(t *testing.T) {
		// the forward slash is the only invalid dirname and seems the simplest way of causing an error.
		sut, err := NewLeiaStore("/")

		assert.Contains(t, err.Error(), "failed to create leiaStore: mkdir")
		assert.Nil(t, sut)
	})
}

func Test_leiaStore_StoreAndSearchCredential(t *testing.T) {
	vcToStore := vc.VerifiableCredential{}
	_ = json.Unmarshal([]byte(concept.TestCredential), &vcToStore)

	t.Run("store", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		sut, err := NewLeiaStore(testDir)
		if !assert.NoError(t, err) {
			return
		}

		err = sut.StoreCredential(vcToStore)
		assert.NoError(t, err)

		t.Run("and search", func(t *testing.T) {
			issuerDID, _ := did.ParseDID(vcToStore.Issuer.String())
			subjectID, _ := ssi.ParseURI("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")

			t.Run("for all issued credentials for a issuer", func(t *testing.T) {
				res, err := sut.SearchCredential(vcToStore.Context[1], vcToStore.Type[0], *issuerDID, nil)
				assert.NoError(t, err)
				if !assert.Len(t, res, 1) {
					return
				}

				foundVC := res[0]
				assert.Equal(t, vcToStore, foundVC)
			})

			t.Run("for all issued credentials for a issuer and subject", func(t *testing.T) {
				res, err := sut.SearchCredential(vcToStore.Context[0], vcToStore.Type[0], *issuerDID, subjectID)
				assert.NoError(t, err)
				if !assert.Len(t, res, 1) {
					return
				}

				foundVC := res[0]
				assert.Equal(t, vcToStore, foundVC)
			})

			t.Run("no results", func(t *testing.T) {

				t.Run("unknown issuer", func(t *testing.T) {
					unknownIssuerDID, _ := did.ParseDID("did:nuts:123")
					res, err := sut.SearchCredential(vcToStore.Context[0], vcToStore.Type[0], *unknownIssuerDID, nil)
					assert.NoError(t, err)
					if !assert.Len(t, res, 0) {
						return
					}
				})

				t.Run("unknown credentialType", func(t *testing.T) {
					unknownType, _ := ssi.ParseURI("unknownType")
					res, err := sut.SearchCredential(vcToStore.Context[0], *unknownType, *issuerDID, nil)
					assert.NoError(t, err)
					if !assert.Len(t, res, 0) {
						return
					}
				})

				t.Run("unknown subject", func(t *testing.T) {
					unknownSubject, _ := ssi.ParseURI("did:nuts:unknown")
					res, err := sut.SearchCredential(vcToStore.Context[0], vcToStore.Type[0], *issuerDID, unknownSubject)
					assert.NoError(t, err)
					if !assert.Len(t, res, 0) {
						return
					}

				})
			})

		})
	})

}
