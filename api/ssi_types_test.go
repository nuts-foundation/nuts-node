/*
 * Copyright (C) 2022 Nuts community
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

package ssiTypes

import (
	"encoding/json"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	vcr "github.com/nuts-foundation/nuts-node/vcr/api/v2"
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
		vp.VerifiableCredential = []vcr.VerifiableCredential{createVerifiableCredential()}
		vp.Proof = []interface{}{"because"}

		remarshallTest(t, vp, VerifiablePresentation{})
	})
}

func createVerifiableCredential() vcr.VerifiableCredential {
	return vcr.VerifiableCredential{
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

func createVerifiablePresentation() vcr.VerifiablePresentation {
	return vcr.VerifiablePresentation{
		Context: []ssi.URI{
			ssi.MustParseURI("https://www.w3.org/2018/credentials/v1"),
			ssi.MustParseURI("https://nuts.nl/credentials/v1"),
		},
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
