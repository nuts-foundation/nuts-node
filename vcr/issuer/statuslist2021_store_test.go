package issuer

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/credential/statuslist2021"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func Test_InMemoryStore(t *testing.T) {
	issuerURL, _ := url.Parse("https://example.com/iam/issuer/")
	issuerDID, _ := didweb.URLToDID(*issuerURL)
	page1 := 1
	t.Run("ok", func(t *testing.T) {
		store := newStatusListMemoryStore()
		statusListCredential := issuerURL.JoinPath("statuslist", "1")

		// add a revocation to the store
		entry, err := store.Create(nil, *issuerDID, StatusPurposeRevocation)
		require.NoError(t, err)
		require.NoError(t, store.Revoke(nil, ssi.MustParseURI("credential id"), *entry))
		bs := statuslist2021.NewBitstring()
		require.NoError(t, bs.SetBit(0, true))
		expectedList, err := statuslist2021.Compress(*bs)
		require.NoError(t, err)

		cs, err := store.CredentialSubject(nil, *issuerDID, page1)

		require.NoError(t, err)
		assert.Equal(t, statusListCredential.String(), cs.Id)
		assert.Equal(t, credential.StatusList2021CredentialSubjectType, cs.Type)
		assert.Equal(t, StatusPurposeRevocation, cs.StatusPurpose)
		assert.Equal(t, expectedList, cs.EncodedList)
	})

	t.Run(" ok - not revoked", func(t *testing.T) {
		store := newStatusListMemoryStore()
		_, err := store.Create(nil, *issuerDID, StatusPurposeRevocation)
		require.NoError(t, err)
		expectedList, err := statuslist2021.Compress(*statuslist2021.NewBitstring())
		require.NoError(t, err)

		cs, err := store.CredentialSubject(nil, *issuerDID, page1)

		require.NoError(t, err)
		assert.Equal(t, expectedList, cs.EncodedList)
	})

	t.Run("unknown statuslist", func(t *testing.T) {
		nonExistingPage := 5
		cs, err := newStatusListMemoryStore().CredentialSubject(nil, *issuerDID, nonExistingPage)
		assert.ErrorIs(t, err, errNotFound)
		assert.Nil(t, cs)
	})
}
