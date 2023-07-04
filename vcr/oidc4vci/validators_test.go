package oidc4vci

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
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

func Test_ValidateDefinitionWithCredential(t *testing.T) {
	makeDefinition := func() CredentialDefinition {
		return CredentialDefinition{
			Context: []ssi.URI{
				ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
				ssi.MustParseURI("http://example.org/credentials/V1"),
			},
			Type: []ssi.URI{
				ssi.MustParseURI("VerifiableCredential"),
				ssi.MustParseURI("HumanCredential"),
			},
		}
	}

	credential := func() vc.VerifiableCredential {
		return vc.VerifiableCredential{
			Context: []ssi.URI{
				ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
				ssi.MustParseURI("http://example.org/credentials/V1"),
			},
			Type: []ssi.URI{
				ssi.MustParseURI("VerifiableCredential"),
				ssi.MustParseURI("HumanCredential"),
			},
		}
	}

	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, ValidateDefinitionWithCredential(credential(), makeDefinition()))
	})
	t.Run("error - definition contains more contexts", func(t *testing.T) {
		err := ValidateDefinitionWithCredential(vc.VerifiableCredential{}, makeDefinition())
		assert.EqualError(t, err, "credential does not match credential_definition: context mismatch")
	})
	t.Run("error - different contexts", func(t *testing.T) {
		definition := makeDefinition()
		definition.Context = []ssi.URI{
			ssi.MustParseURI("different context"),
		}
		err := ValidateDefinitionWithCredential(credential(), definition)
		assert.EqualError(t, err, "credential does not match credential_definition: context mismatch")
	})
	t.Run("error - number of types do not match", func(t *testing.T) {
		definition := makeDefinition()
		definition.Type = []ssi.URI{
			ssi.MustParseURI("VerifiableCredential"),
		}
		err := ValidateDefinitionWithCredential(credential(), definition)
		assert.EqualError(t, err, "credential does not match credential_definition: type mismatch")
	})
	t.Run("error - types do not match", func(t *testing.T) {
		definition := makeDefinition()
		definition.Type = []ssi.URI{
			ssi.MustParseURI("VerifiableCredential"),
			ssi.MustParseURI("OtherType"),
		}
		err := ValidateDefinitionWithCredential(credential(), definition)
		assert.EqualError(t, err, "credential does not match credential_definition: type mismatch")
	})
}
