/*
 * Copyright (C) 2024 Nuts community
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

package statuslist2021

import (
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStatusList2021CredentialValidator_Validate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		err := credentialValidator{}.Validate(cred)
		assert.NoError(t, err)
	})
	t.Run("error - wraps defaultCredentialValidator", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.Context = []ssi.URI{credentialTypeURI}
		err := credentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "default context is required")
	})
	t.Run("error - missing status list context", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.Context = []ssi.URI{vc.VCContextV1URI()}
		err := credentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "context 'https://w3id.org/vc/status-list/2021/v1' is required")
	})
	t.Run("error - missing StatusList credential type", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}
		err := credentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "type 'StatusList2021Credential' is required")
	})
	t.Run("error - invalid credential subject", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject = []any{"{"}
		err := credentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "json: cannot unmarshal string into Go value of type statuslist2021.CredentialSubject")
	})
	t.Run("error - wrong credential subject", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject = []any{struct{}{}}
		err := credentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "credentialSubject.type 'StatusList2021' is required")
	})
	t.Run("error - multiple credentialSubject", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject = []any{CredentialSubject{}, CredentialSubject{}}
		err := credentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "single CredentialSubject expected")
	})
	t.Run("error - missing credentialSubject.type", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(*CredentialSubject).Type = ""
		err := credentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "credentialSubject.type 'StatusList2021' is required")
	})
	t.Run("error - missing statusPurpose", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(*CredentialSubject).StatusPurpose = ""
		err := credentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "credentialSubject.statusPurpose is required")
	})
	t.Run("error - missing encodedList", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(*CredentialSubject).EncodedList = ""
		err := credentialValidator{}.Validate(cred)
		assert.EqualError(t, err, "credentialSubject.encodedList is required")
	})
}
