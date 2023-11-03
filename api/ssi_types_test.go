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
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	vcr "github.com/nuts-foundation/nuts-node/vcr/api/vcr/v2"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

const (
	didString = "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey"
	idString  = "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey#c4199b74-0c0a-4e09-a463-6927553e65f5"
)

func Test_VerifiableCredential(t *testing.T) {
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

func Test_VerifiablePresentation(t *testing.T) {
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

func Test_Revocation(t *testing.T) {
	t.Run("required fields only", func(t *testing.T) {
		remarshallTest(t, createRevocation(), Revocation{})
	})

	t.Run("all fields", func(t *testing.T) {
		revocation := createRevocation()
		revocation.Context = []ssi.URI{
			ssi.MustParseURI("https://nuts.nl/credentials/v1"),
		}
		revocation.Type = []ssi.URI{
			ssi.MustParseURI("VerifiableCredential"),
			ssi.MustParseURI("CredentialRevocation"),
		}
		revocation.Reason = "why not"
		revocation.Proof = &vc.JSONWebSignature2020Proof{
			Proof: vc.Proof{},
			Jws:   "signature",
		}

		remarshallTest(t, revocation, Revocation{})
	})
}

func Test_DIDDocument(t *testing.T) {
	t.Run("all fields", func(t *testing.T) {
		remarshallTest(t, createDidDocument(), DIDDocument{})
	})
}

func Test_DIDDocumentMetadata(t *testing.T) {
	t.Run("required fields only", func(t *testing.T) {
		remarshallTest(t, createDidDocumentMetadata(), DIDDocumentMetadata{})
	})

	t.Run("all fields ", func(t *testing.T) {
		dm := createDidDocumentMetadata()
		now := time.Now()
		previous := hash.RandomHash()
		dm.Updated = &now
		dm.PreviousHash = &previous
		dm.SourceTransactions = []hash.SHA256Hash{previous}

		remarshallTest(t, dm, DIDDocumentMetadata{})
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

func createRevocation() vcr.Revocation {
	return vcr.Revocation{
		Issuer:  ssi.MustParseURI(didString),
		Subject: ssi.MustParseURI(idString),
		Date:    time.Now(),
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

func createDidDocument() did.Document {
	verificationMethod := &did.VerificationMethod{
		ID:         did.MustParseDIDURL(idString),
		Type:       "Secp256k1VerificationKey2018",
		Controller: did.MustParseDID(didString),
	}
	verificationRelationship := did.VerificationRelationship{VerificationMethod: verificationMethod}
	return did.Document{
		Context: []interface{}{
			ssi.MustParseURI("https://www.w3.org/ns/did/v1"),
			ssi.MustParseURI("https://www.w3.org/ns/did/v2"),
		},
		AssertionMethod:      did.VerificationRelationships{verificationRelationship},
		Authentication:       did.VerificationRelationships{verificationRelationship},
		CapabilityDelegation: did.VerificationRelationships{verificationRelationship},
		CapabilityInvocation: did.VerificationRelationships{verificationRelationship},
		KeyAgreement:         did.VerificationRelationships{verificationRelationship},
		VerificationMethod:   did.VerificationMethods{verificationMethod},
		Controller:           []did.DID{did.MustParseDID("did:example:controller")},
		ID:                   verificationMethod.ID,
		Service: []did.Service{
			{
				ID:              ssi.MustParseURI("example"),
				Type:            "type",
				ServiceEndpoint: "foo",
			},
		},
	}
}

func createDidDocumentMetadata() resolver.DocumentMetadata {
	return resolver.DocumentMetadata{
		Created:     time.Now(),
		Hash:        hash.RandomHash(),
		Deactivated: true,
	}
}

func remarshallTest(t *testing.T, source, target any) {
	jsonSource, err := json.Marshal(source)
	require.NoError(t, err)

	err = json.Unmarshal(jsonSource, &target)
	require.NoError(t, err)

	jsonTarget, err := json.Marshal(target)
	require.NoError(t, err)

	assert.JSONEq(t, string(jsonSource), string(jsonTarget))
}
