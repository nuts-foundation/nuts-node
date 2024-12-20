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
	"github.com/nuts-foundation/nuts-node/pki"
	"go.uber.org/mock/gomock"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/revocation"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func init() {
	// Input/expected VC fields are logged on debug
	logrus.SetLevel(logrus.DebugLevel)
}

func TestNutsOrganizationCredentialValidator_Validate(t *testing.T) {
	validator := nutsOrganizationCredentialValidator{}

	t.Run("ok", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)

		err := validator.Validate(v)

		assert.NoError(t, err)
	})

	t.Run("failed - missing custom type", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)
		v.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: type 'NutsOrganizationCredential' is required")
	})

	t.Run("failed - missing credential subject", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)
		v.CredentialSubject = []interface{}{}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: single CredentialSubject expected")
	})

	t.Run("failed - missing organization", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.organization' is empty")
	})

	t.Run("failed - missing organization name", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)
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
		v := test.ValidNutsOrganizationCredential(t)
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
		v := test.ValidNutsOrganizationCredential(t)
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
		v := test.ValidNutsOrganizationCredential(t)
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
		v := test.ValidNutsOrganizationCredential(t)
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
		v := test.ValidNutsOrganizationCredential(t)
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
		v := test.ValidNutsOrganizationCredential(t)
		otherID := vdr.TestDIDB.URI()
		v.ID = &otherID

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: credential ID must start with issuer")
	})

	t.Run("failed - missing nuts context", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)
		v.Context = []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: context 'https://nuts.nl/credentials/v1' is required")
	})
}

func TestNutsAuthorizationCredentialValidator_Validate(t *testing.T) {
	validator := nutsAuthorizationCredentialValidator{}

	t.Run("ok", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)

		err := validator.Validate(v)

		assert.NoError(t, err)
	})

	t.Run("ok - multiple resources", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		v.CredentialSubject[0].(map[string]any)["resources"] = []Resource{
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

		err := validator.Validate(v)

		assert.NoError(t, err)
	})

	t.Run("ok - empty resources array", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		v.CredentialSubject[0].(map[string]any)["resources"] = []Resource{}

		err := validator.Validate(v)

		assert.NoError(t, err)
	})

	t.Run("failed - invalid ID", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		otherID := vdr.TestDIDB.URI()
		v.ID = &otherID

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: credential ID must start with issuer")
	})

	t.Run("failed - missing Nuts context", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		v.Context = []ssi.URI{vc.VCContextV1URI()}

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: context 'https://nuts.nl/credentials/v1' is required")
	})

	t.Run("failed - missing authorization VC type", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		v.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: type 'NutsAuthorizationCredential' is required")
	})

	t.Run("failed - missing credentialSubject", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		v.CredentialSubject = []interface{}{}

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: single CredentialSubject expected")
	})

	t.Run("failed - missing credentialSubject.ID", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		v.CredentialSubject[0].(map[string]any)["id"] = ""

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.ID' is nil")
	})

	t.Run("failed - invalid credentialSubject.ID", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		v.CredentialSubject[0].(map[string]any)["id"] = "unknown"

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: invalid 'credentialSubject.id': invalid DID")
	})

	t.Run("failed - missing purposeOfUse", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		v.CredentialSubject[0].(map[string]any)["purposeOfUse"] = ""

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.PurposeOfUse' is nil")
	})

	t.Run("failed - resources: missing path", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		v.CredentialSubject[0].(map[string]any)["resources"] = []Resource{{
			Operations: []string{"read"},
		}}

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.Resources[].Path' is required'")
	})

	t.Run("failed - resources: missing operation", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		v.CredentialSubject[0].(map[string]any)["resources"] = []Resource{{
			Path: "/composition/1",
		}}

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.Resources[].Operations[]' requires at least one value")
	})

	t.Run("failed - resources: invalid operation", func(t *testing.T) {
		v := test.ValidNutsAuthorizationCredential(t)
		v.CredentialSubject[0].(map[string]any)["resources"] = []Resource{{
			Path:       "/composition/1",
			Operations: []string{"unknown"},
		}}

		err := validator.Validate(v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.Resources[].Operations[]' contains an invalid operation 'unknown'")
	})
}

func TestDefaultCredentialValidator(t *testing.T) {
	validator := defaultCredentialValidator{}

	t.Run("ok - NutsOrganizationCredential", func(t *testing.T) {
		err := validator.Validate(test.ValidNutsOrganizationCredential(t))

		assert.NoError(t, err)
	})

	t.Run("ok - credential with just ID in credentialSubject", func(t *testing.T) {
		// compaction replaces credentialSubject map with ID, with just the ID as string
		credential := test.ValidNutsAuthorizationCredential(t)
		credential.CredentialSubject = []interface{}{
			map[string]interface{}{
				"id": "did:nuts:1234",
			},
		}

		err := validator.Validate(credential)

		assert.NoError(t, err)
	})

	t.Run("ok - unknown credentialStatus.type is ignored", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)
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
		v := test.ValidNutsOrganizationCredential(t)
		v.ID = nil

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'ID' is required")
	})

	t.Run("failed - missing issuer", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)
		v.Issuer = ssi.MustParseURI("")

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'issuer' is required")
	})

	t.Run("failed - missing default context", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)
		v.Context = []ssi.URI{ssi.MustParseURI(NutsV1Context)}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: default context is required")
	})

	t.Run("failed - missing default type", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)
		v.Type = []ssi.URI{ssi.MustParseURI(NutsOrganizationCredentialType)}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: type 'VerifiableCredential' is required")
	})

	t.Run("failed - issuanceDate is zero", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)
		v.IssuanceDate = time.Time{}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: 'issuanceDate' is required")
	})

	t.Run("failed - invalid credentialStatus", func(t *testing.T) {
		v := test.ValidNutsOrganizationCredential(t)
		v.CredentialStatus = []any{"{"}

		err := validator.Validate(v)

		assert.EqualError(t, err, "validation failed: invalid credentialStatus: json: cannot unmarshal string into Go value of type vc.CredentialStatus")
	})
}

func Test_validateCredentialStatus(t *testing.T) {
	t.Run("ok - no credentialStatus", func(t *testing.T) {
		assert.NoError(t, validateCredentialStatus(vc.VerifiableCredential{}))
	})
	t.Run("ok - ignores unknown type", func(t *testing.T) {
		assert.NoError(t, validateCredentialStatus(vc.VerifiableCredential{CredentialStatus: []any{
			vc.CredentialStatus{
				ID:   ssi.MustParseURI("1"),
				Type: "UnkownType",
			}}}))
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

	t.Run(revocation.StatusList2021EntryType, func(t *testing.T) {
		makeValidCSEntry := func() vc.VerifiableCredential {
			return vc.VerifiableCredential{
				Context: []ssi.URI{ssi.MustParseURI(jsonld.W3cStatusList2021Context)},
				CredentialStatus: []any{&revocation.StatusList2021Entry{
					ID:                   "https://example-com/credentials/status/3#94567",
					Type:                 revocation.StatusList2021EntryType,
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
		t.Run("error - credentialStatus validation is called", func(t *testing.T) {
			cred := makeValidCSEntry()
			cred.CredentialStatus[0].(*revocation.StatusList2021Entry).StatusListCredential = "make sure validator is called"
			err := validateCredentialStatus(cred)
			assert.EqualError(t, err, "parse StatusList2021Entry.statusListCredential URL: parse \"make sure validator is called\": invalid URI for request")
		})
	})
}

func TestX509CredentialValidator_Validate(t *testing.T) {
	ctx := createTestContext(t)

	t.Run("ok", func(t *testing.T) {
		x509credential := test.ValidX509Credential(t)
		ctx := createTestContext(t)
		ctx.pkiValidator.EXPECT().CheckCRL(gomock.Any()).Return(nil)

		err := ctx.validator.Validate(x509credential)

		assert.NoError(t, err)
	})
	t.Run("CRL check failed", func(t *testing.T) {
		x509credential := test.ValidX509Credential(t)
		ctx := createTestContext(t)
		ctx.pkiValidator.EXPECT().CheckCRL(gomock.Any()).Return(assert.AnError)

		err := ctx.validator.Validate(x509credential)

		assert.ErrorIs(t, err, errValidation)
		assert.ErrorIs(t, err, assert.AnError)
	})
	t.Run("invalid did", func(t *testing.T) {
		x509credential := vc.VerifiableCredential{Issuer: ssi.MustParseURI("not_a_did")}

		err := ctx.validator.Validate(x509credential)

		assert.ErrorIs(t, err, errValidation)
		assert.ErrorIs(t, err, did.ErrInvalidDID)
	})

	t.Run("failed validation", func(t *testing.T) {

		testCases := []struct {
			name          string
			claim         map[string]interface{}
			expectedError string
		}{
			{
				name: "invalid assertion value",
				claim: map[string]interface{}{
					"san:otherName": "A_BIG_STRIN",
				},
				expectedError: "invalid assertion value 'A_BIG_STRIN' for 'san:otherName' did:x509 policy",
			},
			{
				name: "unknown assertion",
				claim: map[string]interface{}{
					"san:ip": "10.0.0.1",
				},
				expectedError: "assertion 'san:ip' not found in did:x509 policy",
			},
			{
				name: "unknown policy",
				claim: map[string]interface{}{
					"stan:ip": "10.0.0.1",
				},
				expectedError: "policy 'stan' not found in did:x509 policy",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				x509credential := test.ValidX509Credential(t, func(builder *jwt.Builder) *jwt.Builder {
					builder.Claim("vc", map[string]interface{}{
						"credentialSubject": tc.claim,
					})
					return builder
				})

				err := ctx.validator.Validate(x509credential)

				assert.ErrorIs(t, err, errValidation)
				assert.ErrorContains(t, err, tc.expectedError)
			})
		}
	})
}

type testContext struct {
	ctrl         *gomock.Controller
	validator    x509CredentialValidator
	pkiValidator *pki.MockValidator
}

func createTestContext(t *testing.T) testContext {
	ctrl := gomock.NewController(t)
	pkiValidator := pki.NewMockValidator(ctrl)
	return testContext{
		ctrl:         ctrl,
		validator:    x509CredentialValidator{pkiValidator: pkiValidator},
		pkiValidator: pkiValidator,
	}
}
