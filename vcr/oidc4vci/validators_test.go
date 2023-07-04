package oidc4vci

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_ValidateCredentialDefinition(t *testing.T) {
	t.Run("definition is nil", func(t *testing.T) {
		err := ValidateCredentialDefinition(nil, true)

		assert.EqualError(t, err, "invalid credential_definition: missing")
	})
	t.Run("missing context", func(t *testing.T) {
		definition := &CredentialDefinition{}

		err := ValidateCredentialDefinition(definition, true)

		assert.EqualError(t, err, "invalid credential_definition: missing @context field")
	})
	t.Run("missing type", func(t *testing.T) {
		definition := &CredentialDefinition{Context: []ssi.URI{ssi.MustParseURI("http://example.com")}}

		err := ValidateCredentialDefinition(definition, true)

		assert.EqualError(t, err, "invalid credential_definition: missing type field")
	})
	t.Run("credentialSubject not allowed in offer", func(t *testing.T) {
		definition := &CredentialDefinition{
			Context:           []ssi.URI{ssi.MustParseURI("http://example.com")},
			Type:              []ssi.URI{ssi.MustParseURI("SomeCredentialType")},
			CredentialSubject: new(map[string]any),
		}
		err := ValidateCredentialDefinition(definition, true)

		assert.EqualError(t, err, "invalid credential_definition: credentialSubject not allowed in offer")
	})
}
