/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package credential

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func init() {
	// Input/expected VC fields are logged on debug
	logrus.SetLevel(logrus.DebugLevel)
}

func TestNutsOrganizationCredentialValidator_Validate(t *testing.T) {
	validator := nutsOrganizationCredentialValidator{}

	t.Run("ok", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)

		err := validator.Validate(v)

		assert.NoError(t, err)
	})

	t.Run("failed - missing custom type", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: type 'NutsOrganizationCredential' is required")
	})

	t.Run("failed - missing credential subject", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.CredentialSubject = []interface{}{}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: single CredentialSubject expected")
	})

	t.Run("failed - missing organization", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.organization' is empty")
	})

	t.Run("failed - missing organization name", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		credentialSubject["organization"] = map[string]interface{}{
			"city": "EIbergen",
		}
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.name' is empty")
	})

	t.Run("failed - missing organization city", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		credentialSubject["organization"] = map[string]interface{}{
			"name": "Because we care B.V.",
		}
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.city' is empty")
	})

	t.Run("failed - empty organization city", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		credentialSubject["organization"] = map[string]interface{}{
			"name": "Because we care B.V.",
			"city": " ",
		}
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.city' is empty")
	})

	t.Run("failed - empty organization name", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		credentialSubject["organization"] = map[string]interface{}{
			"name": " ",
			"city": "EIbergen",
		}
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.name' is empty")
	})

	t.Run("failed - missing credentialSubject.ID", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		var credentialSubject = make(map[string]interface{})
		credentialSubject["organization"] = map[string]interface{}{
			"name": "Because we care B.V.",
			"city": "EIbergen",
		}
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.ID' is nil")
	})

	t.Run("failed - invalid credentialSubject.ID", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = "invalid"
		credentialSubject["organization"] = map[string]interface{}{
			"name": "Because we care B.V.",
			"city": "EIbergen",
		}
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: invalid 'credentialSubject.id': invalid DID")
	})

	t.Run("failed - invalid ID", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		otherID := vdr.TestDIDB.URI()
		v.ID = &otherID

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: credential ID must start with issuer")
	})

	t.Run("failed - missing nuts context", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.Context = []ssi.URI{stringToURI("https://www.w3.org/2018/credentials/v1")}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: context 'https://nuts.nl/credentials/v1' is required")
	})
}

func TestNutsAuthorizationCredentialValidator_Validate(t *testing.T) {
	validator := nutsAuthorizationCredentialValidator{}

	t.Run("ok", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()

		err := validator.Validate(*v)

		assert.NoError(t, err)
	})

	t.Run("ok - multiple resources", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		subject := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		subject.Resources = []Resource{
			{
				Path:        "/Task/1",
				UserContext: false,
				Operations:  []string{"read"},
			},
			{
				Path:        "/Task/2",
				UserContext: true,
				Operations:  []string{"read"},
			},
			{
				Path:       "/Task/3",
				Operations: []string{"read", "update"},
			},
		}
		v.CredentialSubject[0] = subject

		err := validator.Validate(*v)

		assert.NoError(t, err)
	})

	t.Run("ok - multiple resources", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		subject := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		subject.Resources = []Resource{
			{
				Path:        "/Task/1",
				UserContext: false,
				Operations:  []string{"read"},
			},
			{
				Path:        "/Task/2",
				UserContext: true,
				Operations:  []string{"read"},
			},
			{
				Path:       "/Task/3",
				Operations: []string{"read", "update"},
			},
		}
		v.CredentialSubject[0] = subject

		err := validator.Validate(*v)

		assert.NoError(t, err)
	})

	t.Run("ok - empty resources array", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		subject := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		subject.Resources = []Resource{}
		v.CredentialSubject[0] = subject

		err := validator.Validate(*v)

		assert.NoError(t, err)
	})

	t.Run("failed - invalid ID", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		otherID := vdr.TestDIDB.URI()
		v.ID = &otherID

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: credential ID must start with issuer")
	})

	t.Run("failed - missing Nuts context", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		v.Context = []ssi.URI{vc.VCContextV1URI()}

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: context 'https://nuts.nl/credentials/v1' is required")
	})

	t.Run("failed - missing authorization VC type", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		v.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: type 'NutsAuthorizationCredential' is required")
	})

	t.Run("failed - missing credentialSubject", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		v.CredentialSubject = []interface{}{}

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: single CredentialSubject expected")
	})

	t.Run("failed - missing credentialSubject.ID", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.ID = ""
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.ID' is nil")
	})

	t.Run("failed - invalid credentialSubject.ID", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.ID = "unknown"
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: invalid 'credentialSubject.id': invalid DID")
	})

	t.Run("failed - missing purposeOfUse", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.PurposeOfUse = ""
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.PurposeOfUse' is nil")
	})

	t.Run("failed - resources: missing path", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.Resources[0].Path = ""
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.Resources[].Path' is required'")
	})

	t.Run("failed - resources: missing operation", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.Resources[0].Operations = []string{}
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.Resources[].Operations[]' requires at least one value")
	})

	t.Run("failed - resources: invalid operation", func(t *testing.T) {
		v := ValidNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.Resources[0].Operations = []string{"unknown"}
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.Resources[].Operations[]' contains an invalid operation 'unknown'")
	})
}

func TestAllFieldsDefinedValidator(t *testing.T) {
	validator := AllFieldsDefinedValidator{jsonld.NewTestJSONLDManager(t).DocumentLoader()}
	t.Run("ok", func(t *testing.T) {
		inputVC := ValidNutsOrganizationCredential(t)

		err := validator.Validate(inputVC)

		assert.NoError(t, err)
	})
	t.Run("failed - invalid fields", func(t *testing.T) {
		var invalidCredentialSubject = make(map[string]interface{})
		invalidCredentialSubject["id"] = vdr.TestDIDB.String()
		invalidCredentialSubject["organizationButIncorrectFieldName"] = map[string]interface{}{
			"name": "Because we care B.V.",
			"city": "EIbergen",
		}

		inputVC := ValidNutsOrganizationCredential(t)
		inputVC.CredentialSubject[0] = invalidCredentialSubject

		err := validator.Validate(inputVC)

		assert.EqualError(t, err, "validation failed: invalid property: Dropping property that did not expand into an absolute IRI or keyword.")
	})
}

func TestDefaultCredentialValidator(t *testing.T) {
	validator := defaultCredentialValidator{}

	t.Run("ok - NutsOrganizationCredential", func(t *testing.T) {
		err := validator.Validate(ValidNutsOrganizationCredential(t))

		assert.NoError(t, err)
	})

	t.Run("ok - credential with just ID in credentialSubject", func(t *testing.T) {
		// compaction replaces credentialSubject map with ID, with just the ID as string
		credential := *ValidNutsAuthorizationCredential()
		credential.CredentialSubject = []interface{}{
			map[string]interface{}{
				"id": "did:nuts:1234",
			},
		}

		err := validator.Validate(credential)

		assert.NoError(t, err)
	})

	t.Run("ok - ValidFrom instead of IssuanceDate", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.IssuanceDate, v.ValidFrom = v.ValidFrom, v.IssuanceDate

		err := validator.Validate(v)

		assert.Nil(t, v.IssuanceDate)
		assert.NotEmpty(t, v.ValidFrom)
		assert.NoError(t, err)
	})

	t.Run("ok - unknown credentialStatus.type is ignored", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.CredentialStatus = []any{
			vc.CredentialStatus{
				ID:   ssi.MustParseURI("test"),
				Type: "UnknownType",
			},
		}

		err := validator.Validate(v)

		assert.NoError(t, err)
	})

	t.Run("failed - missing ID", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.ID = nil

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'ID' is required")
	})

	t.Run("failed - missing proof", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.Proof = nil

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'proof' is required for JSON-LD credentials")
	})

	t.Run("failed - missing default context", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.Context = []ssi.URI{stringToURI(NutsV1Context)}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: default context is required")
	})

	t.Run("failed - missing default type", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.Type = []ssi.URI{stringToURI(NutsOrganizationCredentialType)}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: type 'VerifiableCredential' is required")
	})

	t.Run("failed - issuanceDate and validFrom both missing", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.IssuanceDate = nil

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'issuanceDate' is required")
	})

	t.Run("failed - issuanceDate is zero", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.IssuanceDate = new(time.Time)

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'issuanceDate' is required")
	})

	t.Run("failed - invalid credentialStatus", func(t *testing.T) {
		v := ValidNutsOrganizationCredential(t)
		v.CredentialStatus = []any{"{"}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: invalid credentialStatus: json: cannot unmarshal string into Go value of type vc.CredentialStatus")
	})
}

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
		cred.CredentialSubject = []any{NutsAuthorizationCredentialSubject{}}
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

func Test_validateCredentialStatus(t *testing.T) {
	t.Run("ok - no credentialStatus", func(t *testing.T) {
		assert.NoError(t, validateCredentialStatus(vc.VerifiableCredential{}))
	})
	t.Run("error - invalid credentialStatus content", func(t *testing.T) {
		cred := vc.VerifiableCredential{CredentialStatus: []any{"{"}}
		err := validateCredentialStatus(cred)
		assert.EqualError(t, err, "json: cannot unmarshal string into Go value of type vc.CredentialStatus")
	})
	t.Run("error - missing id", func(t *testing.T) {
		cred := vc.VerifiableCredential{CredentialStatus: []any{vc.CredentialStatus{Type: "type"}}}
		err := validateCredentialStatus(cred)
		assert.EqualError(t, err, "credentialStatus.id is required")
	})
	t.Run("error - missing type", func(t *testing.T) {
		cred := vc.VerifiableCredential{CredentialStatus: []any{vc.CredentialStatus{ID: ssi.MustParseURI("id")}}}
		err := validateCredentialStatus(cred)
		assert.EqualError(t, err, "credentialStatus.type is required")
	})

	t.Run(StatusList2021EntryType, func(t *testing.T) {
		makeValidCSEntry := func() vc.VerifiableCredential {
			return vc.VerifiableCredential{
				Context: []ssi.URI{statusList2021ContextURI},
				CredentialStatus: []any{&StatusList2021Entry{
					ID:                   "https://example-com/credentials/status/3#94567",
					Type:                 StatusList2021EntryType,
					StatusPurpose:        "revocation",
					StatusListIndex:      "94567",
					StatusListCredential: "https://example-com/credentials/status/3",
				}},
			}
		}
		t.Run("ok", func(t *testing.T) {
			assert.NoError(t, validateCredentialStatus(makeValidCSEntry()))
		})
		t.Run("error - missing context", func(t *testing.T) {
			cred := makeValidCSEntry()
			cred.Context = []ssi.URI{vc.VCContextV1URI()}
			err := validateCredentialStatus(cred)
			assert.EqualError(t, err, "StatusList2021 context is required")
		})
		t.Run("error - unmarshal fails", func(t *testing.T) {
			cred := makeValidCSEntry()
			cred.CredentialStatus = []any{"{"}
			err := validateCredentialStatus(cred)
			assert.EqualError(t, err, "json: cannot unmarshal string into Go value of type vc.CredentialStatus")
		})
		t.Run("error - id == statusListCredential", func(t *testing.T) {
			cred := makeValidCSEntry()
			cred.CredentialStatus[0].(*StatusList2021Entry).ID = cred.CredentialStatus[0].(*StatusList2021Entry).StatusListCredential
			err := validateCredentialStatus(cred)
			assert.EqualError(t, err, "StatusList2021Entry.id is the same as the StatusList2021Entry.statusListCredential")
		})
		t.Run("error - missing statusPurpose", func(t *testing.T) {
			cred := makeValidCSEntry()
			cred.CredentialStatus[0].(*StatusList2021Entry).StatusPurpose = ""
			err := validateCredentialStatus(cred)
			assert.EqualError(t, err, "StatusList2021Entry.statusPurpose is required")
		})
		t.Run("error - statusListIndex is negative", func(t *testing.T) {
			cred := makeValidCSEntry()
			cred.CredentialStatus[0].(*StatusList2021Entry).StatusListIndex = "-1"
			err := validateCredentialStatus(cred)
			assert.EqualError(t, err, "invalid StatusList2021Entry.statusListIndex")
		})
		t.Run("error - statusListIndex is not a number", func(t *testing.T) {
			cred := makeValidCSEntry()
			cred.CredentialStatus[0].(*StatusList2021Entry).StatusListIndex = "one"
			err := validateCredentialStatus(cred)
			assert.EqualError(t, err, "invalid StatusList2021Entry.statusListIndex")
		})
		t.Run("error - statusListCredential is not a valid URL", func(t *testing.T) {
			cred := makeValidCSEntry()
			cred.CredentialStatus[0].(*StatusList2021Entry).StatusListCredential = "not a URL"
			err := validateCredentialStatus(cred)
			assert.EqualError(t, err, "parse StatusList2021Entry.statusListCredential URL: url must contain scheme and host")
		})
	})
}
