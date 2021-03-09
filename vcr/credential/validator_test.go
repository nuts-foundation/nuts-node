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

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr"
	"github.com/stretchr/testify/assert"
)

func TestNutsOrganizationCredentialValidator_Validate(t *testing.T) {
	validator := nutsOrganizationCredentialValidator{}

	t.Run("ok", func(t *testing.T) {
		vc := validNutsOrganizationCredential()

		err := validator.Validate(*vc)

		assert.NoError(t, err)
	})

	t.Run("failed - missing custom type", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		vc.Type = []did.URI{did.VerifiableCredentialTypeV1URI()}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - missing default type", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		vc.Type = []did.URI{stringToURI(NutsOrganizationCredentialType)}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - missing credential subject", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		vc.CredentialSubject = []interface{}{}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - missing organization", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.AltRandomDID.String()
		vc.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - missing organization name", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.AltRandomDID.String()
		credentialSubject["organization"] = map[string]interface{}{
			"city": "EIbergen",
		}
		vc.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - missing organization city", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.AltRandomDID.String()
		credentialSubject["organization"] = map[string]interface{}{
			"name": "Because we care B.V.",
		}
		vc.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - empty organization city", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.AltRandomDID.String()
		credentialSubject["organization"] = map[string]interface{}{
			"name": "Because we care B.V.",
			"city": " ",
		}
		vc.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - empty organization name", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["id"] = vdr.AltRandomDID.String()
		credentialSubject["organization"] = map[string]interface{}{
			"name": " ",
			"city": "EIbergen",
		}
		vc.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - missing credentialSubject.ID", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		var credentialSubject = make(map[string]interface{})
		credentialSubject["organization"] = map[string]interface{}{
			"name": "Because we care B.V.",
			"city": "EIbergen",
		}
		vc.CredentialSubject = []interface{}{credentialSubject}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - missing ID", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		vc.ID = nil

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - missing default context", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		vc.Context = []did.URI{stringToURI(NutsContext)}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - missing nuts context", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		vc.Context = []did.URI{did.VerifiableCredentialTypeV1URI()}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - missing issuanceDate", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		vc.IssuanceDate = time.Time{}

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})

	t.Run("failed - missing proof", func(t *testing.T) {
		vc := validNutsOrganizationCredential()
		vc.Proof = nil

		err := validator.Validate(*vc)

		assert.Error(t, err)
	})
}

func validNutsOrganizationCredential() *did.VerifiableCredential {
	var credentialSubject = make(map[string]interface{})
	credentialSubject["id"] = vdr.AltRandomDID.String()
	credentialSubject["organization"] = map[string]interface{}{
		"name": "Because we care B.V.",
		"city": "EIbergen",
	}

	return &did.VerifiableCredential{
		Context:           []did.URI{did.VCContextV1URI(), *NutsContextURI},
		ID:                &did.URI{},
		Type:              []did.URI{*NutsOrganizationCredentialTypeURI, did.VerifiableCredentialTypeV1URI()},
		Issuer:            stringToURI(vdr.RandomDID.String()),
		IssuanceDate:      time.Now(),
		CredentialSubject: []interface{}{credentialSubject},
		Proof:             []interface{}{did.Proof{}},
	}
}

func stringToURI(input string) did.URI {
	u, _ := did.ParseURI(input)
	return *u
}
