/*
 * Copyright (C) 2023 Nuts community
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
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestResolveSubjectDID(t *testing.T) {
	did1 := did.MustParseDID("did:test:123")
	did2 := did.MustParseDID("did:test:456")
	credential1 := vc.VerifiableCredential{
		CredentialSubject: []interface{}{map[string]interface{}{"id": did1}},
	}
	credential2 := vc.VerifiableCredential{
		CredentialSubject: []interface{}{map[string]interface{}{"id": did1}},
	}
	credential3 := vc.VerifiableCredential{
		CredentialSubject: []interface{}{map[string]interface{}{"id": did2}},
	}
	t.Run("all the same", func(t *testing.T) {
		actual, err := ResolveSubjectDID(credential1, credential2)
		assert.NoError(t, err)
		assert.Equal(t, did1, *actual)
	})
	t.Run("differ", func(t *testing.T) {
		actual, err := ResolveSubjectDID(credential1, credential3)
		assert.EqualError(t, err, "not all VCs have the same credentialSubject.id")
		assert.Nil(t, actual)
	})
	t.Run("no ID", func(t *testing.T) {
		actual, err := ResolveSubjectDID(vc.VerifiableCredential{CredentialSubject: []interface{}{map[string]interface{}{}}})
		assert.EqualError(t, err, "unable to get subject DID from VC: credential subjects have no ID")
		assert.Nil(t, actual)
	})
	t.Run("no credentialSubject", func(t *testing.T) {
		actual, err := ResolveSubjectDID(vc.VerifiableCredential{})
		assert.EqualError(t, err, "unable to get subject DID from VC: there must be at least 1 credentialSubject")
		assert.Nil(t, actual)
	})

}

func TestVerifyPresenterIsHolder(t *testing.T) {
	holder, _ := ssi.ParseURI("did:test:123")
	t.Run("ok", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			Holder: holder,
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{"id": holder}},
				},
			},
		}
		err := VerifyPresenterIsHolder(vp)
		assert.NoError(t, err)
	})
	t.Run("no holder", func(t *testing.T) {
		vp := vc.VerifiablePresentation{}
		err := VerifyPresenterIsHolder(vp)
		assert.EqualError(t, err, "no holder")
	})
	t.Run("no VC subject", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			Holder: holder,
			VerifiableCredential: []vc.VerifiableCredential{
				{},
			},
		}
		err := VerifyPresenterIsHolder(vp)
		assert.EqualError(t, err, "unable to get subject DID from VC: there must be at least 1 credentialSubject")
	})
	t.Run("no VC subject ID", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			Holder: holder,
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{}},
				},
			},
		}
		err := VerifyPresenterIsHolder(vp)
		assert.EqualError(t, err, "unable to get subject DID from VC: credential subjects have no ID")
	})
	t.Run("holder does not equal VC subject ID", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			Holder: holder,
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{"id": did.MustParseDID("did:test:456")}},
				},
			},
		}
		err := VerifyPresenterIsHolder(vp)
		assert.EqualError(t, err, "not all VC credentialSubject.id match VP holder")
	})
}
