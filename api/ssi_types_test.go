package ssiTypes

import (
	"encoding/json"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
)

func TestSsiTypes_VerifiableCredential(t *testing.T) {
	t.Run("required fields only", func(t *testing.T) {
		remarshallTest(t, createVerifiableCredential(), VerifiableCredential{})
	})

	t.Run("all fields", func(t *testing.T) {
		vc := createVerifiableCredential()
		id := ssi.MustParseURI("did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey#c4199b74-0c0a-4e09-a463-6927553e65f5")
		vc.ID = &id
		expirationDate := time.Now().Add(time.Hour)
		vc.ExpirationDate = &expirationDate

		remarshallTest(t, vc, VerifiableCredential{})
	})
}

func TestSsiTypes_VerifiablePresentation(t *testing.T) {
	t.Run("required fields only", func(t *testing.T) {
		remarshallTest(t, createVerifiablePresentation(), VerifiableCredential{})
	})

	t.Run("all fields", func(t *testing.T) {
		id := ssi.MustParseURI("did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey#c4199b74-0c0a-4e09-a463-6927553e65f5")
		holder := ssi.MustParseURI("did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey")

		vp := createVerifiablePresentation()
		vp.ID = &id
		vp.Holder = &holder
		vp.VerifiableCredential = []vc.VerifiableCredential{createVerifiableCredential()}
		vp.Proof = []interface{}{"because"}

		remarshallTest(t, vp, VerifiablePresentation{})
	})
}

func createVerifiableCredential() vc.VerifiableCredential {
	return vc.VerifiableCredential{
		Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
		Type: []ssi.URI{
			ssi.MustParseURI("NutsOrganizationCredential"),
			ssi.MustParseURI("VerifiableCredential"),
		},
		Issuer:            ssi.MustParseURI("did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey"),
		IssuanceDate:      time.Now(),
		CredentialSubject: []interface{}{"subject"},
		Proof:             []interface{}{"because"},
	}
}

func createVerifiablePresentation() vc.VerifiablePresentation {
	return vc.VerifiablePresentation{
		Context: []ssi.URI{
			ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
			ssi.MustParseURI("https://nuts.nl/credentials/v1")},
		Type: []ssi.URI{ssi.MustParseURI("VerifiablePresentation")},
	}
}

func remarshallTest(t *testing.T, source, target any) {
	jsonSource, err := json.Marshal(source)
	if !assert.NoError(t, err) {
		return
	}

	err = json.Unmarshal(jsonSource, &target)
	if !assert.NoError(t, err) {
		return
	}

	jsonTarget, err := json.Marshal(target)
	if !assert.NoError(t, err) {
		return
	}

	assert.JSONEq(t, string(jsonSource), string(jsonTarget))
}
