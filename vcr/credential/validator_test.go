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
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/sirupsen/logrus"
	"os"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
)

func TestNutsOrganizationCredentialValidator_Validate(t *testing.T) {
	jsonldInstance := jsonld.NewJSONLDInstance()
	_ = jsonldInstance.(core.Configurable).Configure(core.ServerConfig{})
	validator := nutsOrganizationCredentialValidator{jsonldInstance.DocumentLoader()}

	t.Run("ok", func(t *testing.T) {
		v := validNutsOrganizationCredential()

		err := validator.Validate(*v)

		assert.NoError(t, err)
	})

	t.Run("failed - missing custom type", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: type 'NutsOrganizationCredential' is required")
	})

	t.Run("failed - missing default type", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.Type = []ssi.URI{stringToURI(NutsOrganizationCredentialType)}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: type 'VerifiableCredential' is required")
	})

	t.Run("failed - missing credential subject", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.CredentialSubject = []interface{}{}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: single CredentialSubject expected")
	})

	t.Run("failed - missing organization", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.organization' is empty")
	})

	t.Run("failed - missing organization name", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		credentialSubject["organization"] = map[string]interface{}{
			"city": "EIbergen",
		}
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.name' is empty")
	})

	t.Run("failed - missing organization city", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		credentialSubject["organization"] = map[string]interface{}{
			"name": "Because we care B.V.",
		}
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.city' is empty")
	})

	t.Run("failed - empty organization city", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		credentialSubject["organization"] = map[string]interface{}{
			"name": "Because we care B.V.",
			"city": " ",
		}
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.city' is empty")
	})

	t.Run("failed - empty organization name", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		credentialSubject["organization"] = map[string]interface{}{
			"name": " ",
			"city": "EIbergen",
		}
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.name' is empty")
	})

	t.Run("failed - missing credentialSubject.ID", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["organization"] = map[string]interface{}{
			"name": "Because we care B.V.",
			"city": "EIbergen",
		}
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: 'credentialSubject.ID' is nil")
	})

	t.Run("failed - invalid ID", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		otherID := vdr.TestDIDB.URI()
		v.ID = &otherID

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: credential ID must start with issuer")
	})

	t.Run("failed - missing default context", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.Context = []ssi.URI{stringToURI(NutsV1Context)}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: default context is required")
	})

	t.Run("failed - missing nuts context", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.Context = []ssi.URI{stringToURI("https://www.w3.org/2018/credentials/v1")}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: context 'https://nuts.nl/credentials/v1' or 'https://nuts.nl/credentials/v2' is required")
	})

	t.Run("failed - missing issuanceDate", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.IssuanceDate = time.Time{}

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: 'issuanceDate' is required")
	})

	t.Run("failed - missing proof", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.Proof = nil

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: 'proof' is required")
	})
}

func TestNutsAuthorizationCredentialValidator_Validate(t *testing.T) {
	jsonldInstance := jsonld.NewJSONLDInstance()
	_ = jsonldInstance.(core.Configurable).Configure(core.ServerConfig{})
	validator := nutsAuthorizationCredentialValidator{jsonldInstance.DocumentLoader()}

	t.Run("v1", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			logrus.SetLevel(logrus.DebugLevel)
			v := validV1NutsAuthorizationCredential()

			err := validator.Validate(*v)

			assert.NoError(t, err)
		})
	})
	t.Run("v2", func(t *testing.T) {
		t.Run("ok - implied", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()

			err := validator.Validate(*v)

			assert.NoError(t, err)
		})

		t.Run("ok - explicit", func(t *testing.T) {
			v := ValidV2ExplicitNutsAuthorizationCredential()

			err := validator.Validate(*v)

			assert.NoError(t, err)
		})

		t.Run("failed - invalid ID", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()
			otherID := vdr.TestDIDB.URI()
			v.ID = &otherID

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: credential ID must start with issuer")
		})

		t.Run("failed - wrong consentType", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()
			cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
			cs.LegalBase.ConsentType = "unknown"
			v.CredentialSubject[0] = cs

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: 'credentialSubject.LegalBase.ConsentType' must be 'implied' or 'explicit'")
		})

		t.Run("failed - missing VC type", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()
			v.Type = []ssi.URI{}

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: type 'VerifiableCredential' is required")
		})

		t.Run("failed - missing Nuts context", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()
			v.Context = []ssi.URI{vc.VCContextV1URI()}

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: context 'https://nuts.nl/credentials/v1' or 'https://nuts.nl/credentials/v2' is required")
		})

		t.Run("failed - missing authorization VC type", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()
			v.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: type 'NutsAuthorizationCredential' is required")
		})

		t.Run("failed - missing credentialSubject", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()
			v.CredentialSubject = []interface{}{}

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: single CredentialSubject expected")
		})

		t.Run("failed - missing credentialSubject.ID", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()
			cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
			cs.ID = ""
			v.CredentialSubject[0] = cs

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: 'credentialSubject.ID' is nil")
		})

		t.Run("failed - missing purposeOfUse", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()
			cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
			cs.PurposeOfUse = ""
			v.CredentialSubject[0] = cs

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: 'credentialSubject.PurposeOfUse' is nil")
		})

		t.Run("failed - resources: missing path", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()
			cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
			cs.Resources[0].Path = ""
			v.CredentialSubject[0] = cs

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: 'credentialSubject.Resources[].Path' is required'")
		})

		t.Run("failed - resources: missing operation", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()
			cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
			cs.Resources[0].Operations = []string{}
			v.CredentialSubject[0] = cs

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: 'credentialSubject.Resources[].Operations[]' requires at least one value")
		})

		t.Run("failed - resources: invalid operation", func(t *testing.T) {
			v := validV2ImpliedNutsAuthorizationCredential()
			cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
			cs.Resources[0].Operations = []string{"unknown"}
			v.CredentialSubject[0] = cs

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: 'credentialSubject.Resources[].Operations[]' contains an invalid operation 'unknown'")
		})

		t.Run("failed - missing subject for explicit", func(t *testing.T) {
			v := ValidV2ExplicitNutsAuthorizationCredential()
			cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
			cs.Subject = nil
			v.CredentialSubject[0] = cs

			err := validator.Validate(*v)

			assert.Error(t, err)
			assert.EqualError(t, err, "validation failed: 'credentialSubject.Subject' is required when consentType is 'explicit'")
		})
	})
}

func validNutsOrganizationCredential() *vc.VerifiableCredential {
	inputVC := vc.VerifiableCredential{}
	vcJSON, _ := os.ReadFile("../test/vc.json")
	_ = json.Unmarshal(vcJSON, &inputVC)
	return &inputVC
}

func TestDefaultCredentialValidator(t *testing.T) {
	jsonldInstance := jsonld.NewJSONLDInstance()
	_ = jsonldInstance.(core.Configurable).Configure(core.ServerConfig{})
	validator := defaultCredentialValidator{jsonldInstance.DocumentLoader()}

	t.Run("failed - missing ID", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.ID = nil

		err := validator.Validate(*v)

		assert.EqualError(t, err, "validation failed: 'ID' is required")
	})
	t.Run("ok", func(t *testing.T) {
		err := validator.Validate(*validNutsOrganizationCredential())

		assert.NoError(t, err)
	})
	t.Run("invalid fields", func(t *testing.T) {
		logrus.SetLevel(logrus.DebugLevel)
		var invalidCredentialSubject = make(map[string]interface{})
		invalidCredentialSubject["id"] = vdr.TestDIDB.String()
		invalidCredentialSubject["organizationButIncorrectFieldName"] = map[string]interface{}{
			"name": "Because we care B.V.",
			"city": "EIbergen",
		}

		inputVC := *validNutsOrganizationCredential()
		inputVC.CredentialSubject[0] = invalidCredentialSubject

		err := validator.Validate(inputVC)

		assert.EqualError(t, err, "validation failed: not all fields are defined by JSON-LD context")
	})
}
