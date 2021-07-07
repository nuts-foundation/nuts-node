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
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
)

func TestNutsOrganizationCredentialValidator_Validate(t *testing.T) {
	validator := nutsOrganizationCredentialValidator{}

	t.Run("ok", func(t *testing.T) {
		v := validNutsOrganizationCredential()

		err := validator.Validate(*v)

		assert.NoError(t, err)
	})

	t.Run("failed - missing custom type", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}

		err := validator.Validate(*v)

		assert.Error(t, err)
	})

	t.Run("failed - missing default type", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.Type = []ssi.URI{stringToURI(NutsOrganizationCredentialType)}

		err := validator.Validate(*v)

		assert.Error(t, err)
	})

	t.Run("failed - missing credential subject", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.CredentialSubject = []interface{}{}

		err := validator.Validate(*v)

		assert.Error(t, err)
	})

	t.Run("failed - missing organization", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.TestDIDB.String()
		v.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*v)

		assert.Error(t, err)
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

		assert.Error(t, err)
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

		assert.Error(t, err)
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

		assert.Error(t, err)
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

		assert.Error(t, err)
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

		assert.Error(t, err)
	})

	t.Run("failed - missing ID", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.ID = nil

		err := validator.Validate(*v)

		assert.Error(t, err)
	})

	t.Run("failed - missing default context", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.Context = []ssi.URI{stringToURI(NutsContext)}

		err := validator.Validate(*v)

		assert.Error(t, err)
	})

	t.Run("failed - missing nuts context", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.Context = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}

		err := validator.Validate(*v)

		assert.Error(t, err)
	})

	t.Run("failed - missing issuanceDate", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.IssuanceDate = time.Time{}

		err := validator.Validate(*v)

		assert.Error(t, err)
	})

	t.Run("failed - missing proof", func(t *testing.T) {
		v := validNutsOrganizationCredential()
		v.Proof = nil

		err := validator.Validate(*v)

		assert.Error(t, err)
	})
}

func TestNutsAuthorizationCredentialValidator_Validate(t *testing.T) {
	validator := nutsAuthorizationCredentialValidator{}

	t.Run("ok - implied", func(t *testing.T) {
		v := validImpliedNutsAuthorizationCredential()

		err := validator.Validate(*v)

		assert.NoError(t, err)
	})

	t.Run("ok - explicit", func(t *testing.T) {
		v := validExplicitNutsAuthorizationCredential()

		err := validator.Validate(*v)

		assert.NoError(t, err)
	})

	t.Run("failed - wrong consentType", func(t *testing.T) {
		v := validImpliedNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.LegalBase.ConsentType = "unknown"
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.LegalBase.ConsentType' must be 'implied' or 'explicit'")
	})

	t.Run("failed - missing VC type", func(t *testing.T) {
		v := validImpliedNutsAuthorizationCredential()
		v.Type = []ssi.URI{}

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: type 'VerifiableCredential' is required")
	})

	t.Run("failed - missing authorization VC type", func(t *testing.T) {
		v := validImpliedNutsAuthorizationCredential()
		v.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: type 'NutsAuthorizationCredential' is required")
	})

	t.Run("failed - missing credentialSubject", func(t *testing.T) {
		v := validImpliedNutsAuthorizationCredential()
		v.CredentialSubject = []interface{}{}

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: single CredentialSubject expected")
	})

	t.Run("failed - missing credentialSubject.ID", func(t *testing.T) {
		v := validImpliedNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.ID = ""
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.ID' is nil")
	})

	t.Run("failed - missing purposeOfUse", func(t *testing.T) {
		v := validImpliedNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.PurposeOfUse = ""
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.PurposeOfUse' is nil")
	})

	t.Run("failed - missing restrictions for implied", func(t *testing.T) {
		v := validImpliedNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.Restrictions = []Restriction{}
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.Restrictions' must have entries when consentType is 'implied'")
	})

	t.Run("failed - restrictions: missing resource", func(t *testing.T) {
		v := validImpliedNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.Restrictions[0].Resource = ""
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.Restrictions[].Resource' is required for a restriction'")
	})

	t.Run("failed - restrictions: missing operation", func(t *testing.T) {
		v := validImpliedNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.Restrictions[0].Operations = []string{}
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.Restrictions[].Operations' requires at least one value")
	})

	t.Run("failed - restrictions: invalid operation", func(t *testing.T) {
		v := validImpliedNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.Restrictions[0].Operations = []string{"unknown"}
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.Restrictions[].Operations' contains an invalid operation 'unknown'")
	})

	t.Run("failed - missing subject for explicit", func(t *testing.T) {
		v := validExplicitNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.Subject = nil
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.Subject' is required when consentType is 'explicit'")
	})

	t.Run("failed - missing evidence", func(t *testing.T) {
		v := validExplicitNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.LegalBase = LegalBase{
			ConsentType: "explicit",
		}
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.LegalBase.Evidence' is required when consentType is 'explicit'")
	})

	t.Run("failed - missing evidence.Path", func(t *testing.T) {
		v := validExplicitNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.LegalBase = LegalBase{
			ConsentType: "explicit",
			Evidence: &Evidence{
				Type: "application/pdf",
			},
		}
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.LegalBase.Evidence.Path' is required when consentType is 'explicit'")
	})

	t.Run("failed - missing evidence.Type", func(t *testing.T) {
		v := validExplicitNutsAuthorizationCredential()
		cs := v.CredentialSubject[0].(NutsAuthorizationCredentialSubject)
		cs.LegalBase = LegalBase{
			ConsentType: "explicit",
			Evidence: &Evidence{
				Path: "pdf/1.pdf",
			},
		}
		v.CredentialSubject[0] = cs

		err := validator.Validate(*v)

		assert.Error(t, err)
		assert.EqualError(t, err, "validation failed: 'credentialSubject.LegalBase.Evidence.Type' is required when consentType is 'explicit'")
	})
}

func validNutsOrganizationCredential() *vc.VerifiableCredential {
	var credentialSubject = make(map[string]interface{})
	credentialSubject["id"] = vdr.TestDIDB.String()
	credentialSubject["organization"] = map[string]interface{}{
		"name": "Because we care B.V.",
		"city": "EIbergen",
	}

	return &vc.VerifiableCredential{
		Context:           []ssi.URI{vc.VCContextV1URI(), *NutsContextURI},
		ID:                &ssi.URI{},
		Type:              []ssi.URI{*NutsOrganizationCredentialTypeURI, vc.VerifiableCredentialTypeV1URI()},
		Issuer:            stringToURI(vdr.TestDIDA.String()),
		IssuanceDate:      time.Now(),
		CredentialSubject: []interface{}{credentialSubject},
		Proof:             []interface{}{vc.Proof{}},
	}
}

func validImpliedNutsAuthorizationCredential() *vc.VerifiableCredential {
	credentialSubject := NutsAuthorizationCredentialSubject{
		ID: vdr.TestDIDB.String(),
		LegalBase: LegalBase{
			ConsentType: "implied",
		},
		PurposeOfUse: "eTransfer",
		Restrictions: []Restriction{
			{
				Resource:    "/composition/1",
				Operations:  []string{"read"},
				UserContext: true,
			},
		},
	}
	return validNutsAuthorizationCredential(credentialSubject)
}

func validExplicitNutsAuthorizationCredential() *vc.VerifiableCredential {
	patient := "urn:oid:2.16.840.1.113883.2.4.6.3:123456780"
	credentialSubject := NutsAuthorizationCredentialSubject{
		ID: vdr.TestDIDB.String(),
		LegalBase: LegalBase{
			ConsentType: "explicit",
			Evidence: &Evidence{
				Path: "/1.pdf",
				Type: "application/pdf",
			},
		},
		PurposeOfUse: "careViewer",
		Subject:      &patient,
	}
	return validNutsAuthorizationCredential(credentialSubject)
}

func validNutsAuthorizationCredential(credentialSubject NutsAuthorizationCredentialSubject) *vc.VerifiableCredential {
	return &vc.VerifiableCredential{
		Context:           []ssi.URI{vc.VCContextV1URI(), *NutsContextURI},
		ID:                &ssi.URI{},
		Type:              []ssi.URI{*NutsAuthorizationCredentialTypeURI, vc.VerifiableCredentialTypeV1URI()},
		Issuer:            stringToURI(vdr.TestDIDA.String()),
		IssuanceDate:      time.Now(),
		CredentialSubject: []interface{}{credentialSubject},
		Proof:             []interface{}{vc.Proof{}},
	}
}

func stringToURI(input string) ssi.URI {
	u, _ := ssi.ParseURI(input)
	return *u
}
