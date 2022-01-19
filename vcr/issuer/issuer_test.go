package issuer

import (
	"github.com/golang/mock/gomock"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_issuer_buildVC(t *testing.T) {
	credentialType, _ := ssi.ParseURI("TestCredential")
	issuerDID, _ := ssi.ParseURI("did:nuts:123")

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		kid := "did:nuts:123#abc"

		keyResolverMock := NewMockkeyResolver(ctrl)
		keyResolverMock.EXPECT().ResolveAssertionKey(gomock.Any()).Return(crypto.NewTestKey(kid), nil)
		sut := issuer{keyResolver: keyResolverMock}
		schemaOrgContext, _ := ssi.ParseURI("http://schema.org")

		credentialOptions := vc.VerifiableCredential{
			Context: []ssi.URI{*schemaOrgContext},
			Type:    []ssi.URI{*credentialType},
			Issuer:  *issuerDID,
			CredentialSubject: []interface{}{map[string]interface{}{
				"id": "did:nuts:456",
			}},
		}
		result, err := sut.buildVC(credentialOptions)
		assert.NoError(t, err)
		assert.Contains(t, result.Type, *credentialType, "expected vc to be of right type")
		proofs, _ := result.Proofs()
		assert.Equal(t, kid, proofs[0].VerificationMethod.String(), "expected to be signed with the kid")
		assert.Equal(t, issuerDID.String(), result.Issuer.String(), "expected correct issuer")
		assert.Contains(t, result.Context, *schemaOrgContext)
		assert.Contains(t, result.Context, vc.VCContextV1URI())
	})

	t.Run("error - missing issuer", func(t *testing.T) {
		sut := issuer{}

		credentialOptions := vc.VerifiableCredential{
			Type: []ssi.URI{*credentialType},
		}
		result, err := sut.buildVC(credentialOptions)

		assert.EqualError(t, err, "failed to parse issuer: invalid DID: input length is less than 7")
		assert.Nil(t, result)
	})
}
