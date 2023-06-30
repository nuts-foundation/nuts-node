package oidc4vci

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_credentialTypesMatchOffer(t *testing.T) {
	credentialDefinition := map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/2018/credentials/v1",
			"http://example.org/credentials/V1",
		},
		"type": []string{"VerifiableCredential", "HumanCredential"},
	}
	credential := vc.VerifiableCredential{
		Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"), ssi.MustParseURI("http://example.org/credentials/V1")},
		Type:    []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("HumanCredential")},
	}
	jsonldReader := jsonld.Reader{DocumentLoader: jsonld.NewTestJSONLDManager(t).DocumentLoader()}

	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, CredentialTypesMatchDefinition(jsonldReader, credential, credentialDefinition))
	})
	t.Run("error - invalid credential_definition", func(t *testing.T) {
		err := CredentialTypesMatchDefinition(jsonldReader, credential,
			map[string]interface{}{"type": []string{"VerifiableCredential", "HumanCredential"}})
		assert.EqualError(t, err, "invalid credential_definition: invalid property: Dropping property that did not expand into an absolute IRI or keyword.")
	})
	t.Run("error - invalid credential", func(t *testing.T) {
		err := CredentialTypesMatchDefinition(jsonldReader, vc.VerifiableCredential{}, credentialDefinition)
		assert.EqualError(t, err, "invalid credential: invalid property: Dropping property that did not expand into an absolute IRI or keyword.")
	})
	t.Run("error - types do not match", func(t *testing.T) {
		c := credential
		c.Type[0], c.Type[1] = c.Type[1], c.Type[0]
		defer func() { c.Type[0], c.Type[1] = c.Type[1], c.Type[0] }()
		err := CredentialTypesMatchDefinition(jsonldReader, credential, credentialDefinition)
		assert.EqualError(t, err, "credential Type do not match")
	})
}
