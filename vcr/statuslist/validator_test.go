package statuslist

import (
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStatusList2021CredentialValidator_Validate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		err := statusList2021CredentialValidator{}.Validate(cred)
		assert.NoError(t, err)
	})
	t.Run("error - wraps defaultCredentialValidator", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.Context = []ssi.URI{statusList2021CredentialTypeURI}
		err := statusList2021CredentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "validation failed: default context is required")
	})
	t.Run("error - missing status list context", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.Context = []ssi.URI{vc.VCContextV1URI()}
		err := statusList2021CredentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "validation failed: context 'https://w3id.org/vc/status-list/2021/v1' is required")
	})
	t.Run("error - missing StatusList credential type", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}
		err := statusList2021CredentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "validation failed: type 'StatusList2021Credential' is required")
	})
	t.Run("error - invalid credential subject", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject = []any{"{"}
		err := statusList2021CredentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "validation failed: json: cannot unmarshal string into Go value of type credential.StatusList2021CredentialSubject")
	})
	t.Run("error - wrong credential subject", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject = []any{credential.NutsAuthorizationCredentialSubject{}}
		err := statusList2021CredentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "validation failed: credentialSubject.type 'StatusList2021' is required")
	})
	t.Run("error - multiple credentialSubject", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject = []any{StatusList2021CredentialSubject{}, StatusList2021CredentialSubject{}}
		err := statusList2021CredentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "validation failed: single CredentialSubject expected")
	})
	t.Run("error - missing credentialSubject.type", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(*StatusList2021CredentialSubject).Type = ""
		err := statusList2021CredentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "validation failed: credentialSubject.type 'StatusList2021' is required")
	})
	t.Run("error - missing statusPurpose", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(*StatusList2021CredentialSubject).StatusPurpose = ""
		err := statusList2021CredentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "validation failed: credentialSubject.statusPurpose is required")
	})
	t.Run("error - missing encodedList", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(*StatusList2021CredentialSubject).EncodedList = ""
		err := statusList2021CredentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "validation failed: credentialSubject.encodedList is required")
	})
}
