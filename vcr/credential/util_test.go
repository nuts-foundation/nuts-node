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
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
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

func TestVerifyPresenterIsCredentialSubject(t *testing.T) {
	subjectDID := ssi.MustParseURI("did:test:123")
	keyID := ssi.MustParseURI("did:test:123#1")
	t.Run("ok", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{
					Type:               "JsonWebSignature2020",
					VerificationMethod: keyID,
				},
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{"id": subjectDID}},
				},
			},
		}
		err := VerifyPresenterIsCredentialSubject(vp)
		assert.NoError(t, err)
	})
	t.Run("no proof", func(t *testing.T) {
		vp := vc.VerifiablePresentation{}
		err := VerifyPresenterIsCredentialSubject(vp)
		assert.EqualError(t, err, "presentation should have exactly 1 proof, got 0")
	})
	t.Run("no VC subject", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{
					Type:               "JsonWebSignature2020",
					VerificationMethod: keyID,
				},
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{},
			},
		}
		err := VerifyPresenterIsCredentialSubject(vp)
		assert.EqualError(t, err, "unable to get subject DID from VC: there must be at least 1 credentialSubject")
	})
	t.Run("no VC subject ID", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{
					Type:               "JsonWebSignature2020",
					VerificationMethod: keyID,
				},
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{}},
				},
			},
		}
		err := VerifyPresenterIsCredentialSubject(vp)
		assert.EqualError(t, err, "unable to get subject DID from VC: credential subjects have no ID")
	})
	t.Run("proof verification method does not equal VC subject ID", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{
					Type:               "JsonWebSignature2020",
					VerificationMethod: keyID,
				},
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{"id": did.MustParseDID("did:test:456")}},
				},
			},
		}
		err := VerifyPresenterIsCredentialSubject(vp)
		assert.EqualError(t, err, "not all VC credentialSubject.id match VP signer")
	})
	t.Run("proof type is unsupported", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			Proof: []interface{}{
				true,
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{"id": subjectDID}},
				},
			},
		}
		err := VerifyPresenterIsCredentialSubject(vp)
		assert.EqualError(t, err, "invalid LD-proof for presentation: json: cannot unmarshal bool into Go value of type proof.LDProof")
	})
	t.Run("too many proofs", func(t *testing.T) {
		vp := vc.VerifiablePresentation{
			Proof: []interface{}{
				proof.LDProof{},
				proof.LDProof{},
			},
			VerifiableCredential: []vc.VerifiableCredential{
				{
					CredentialSubject: []interface{}{map[string]interface{}{"id": subjectDID}},
				},
			},
		}
		err := VerifyPresenterIsCredentialSubject(vp)
		assert.EqualError(t, err, "presentation should have exactly 1 proof, got 2")
	})
}
