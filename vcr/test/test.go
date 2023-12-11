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

package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// CreateJWTPresentation creates a JWT presentation with the given subject DID and credentials.
func CreateJWTPresentation(t *testing.T, subjectDID did.DID, tokenVisitor func(token jwt.Token), credentials ...vc.VerifiableCredential) vc.VerifiablePresentation {
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.TypeKey, "JWT"))
	claims := map[string]interface{}{
		jwt.IssuerKey:     subjectDID.String(),
		jwt.SubjectKey:    subjectDID.String(),
		jwt.JwtIDKey:      subjectDID.String() + "#" + uuid.NewString(),
		jwt.NotBeforeKey:  time.Now().Unix(),
		jwt.ExpirationKey: time.Now().Add(5 * time.Second).Unix(),
		"vp": vc.VerifiablePresentation{
			Type:                 []ssi.URI{vc.VerifiablePresentationTypeV1URI()},
			VerifiableCredential: credentials,
		},
	}
	unsignedToken := jwt.New()
	for k, v := range claims {
		require.NoError(t, unsignedToken.Set(k, v))
	}
	if tokenVisitor != nil {
		tokenVisitor(unsignedToken)
	}
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	token, _ := jwt.Sign(unsignedToken, jwt.WithKey(jwa.ES256, privateKey, jws.WithProtectedHeaders(headers)))
	result, err := vc.ParseVerifiablePresentation(string(token))
	require.NoError(t, err)
	return *result
}

// CreateJSONLDPresentation creates a JSON-LD presentation with the given subject DID and credentials.
// The presentation is not actually signed.
func CreateJSONLDPresentation(t *testing.T, subjectDID did.DID, visitor func(presentation *vc.VerifiablePresentation), verifiableCredential ...vc.VerifiableCredential) vc.VerifiablePresentation {
	id := ssi.MustParseURI(subjectDID.String() + "#" + uuid.NewString())
	exp := time.Now().Add(5 * time.Second)
	nonce := crypto.GenerateNonce()
	vp := vc.VerifiablePresentation{
		ID:                   &id,
		VerifiableCredential: verifiableCredential,
		Proof: []interface{}{
			proof.LDProof{
				Type:               ssi.JsonWebSignature2020,
				VerificationMethod: ssi.MustParseURI(subjectDID.String() + "#1"),
				ProofOptions: proof.ProofOptions{
					Created: time.Now(),
					Expires: &exp,
					Nonce:   &nonce,
				},
			},
		},
	}
	if visitor != nil {
		visitor(&vp)
	}
	return ParsePresentation(t, vp)
}

// LDProofVisitor is a util function that creates a visitor for CreateJSONLDPresentation to easily modify the LinkedData proof.
func LDProofVisitor(visitor func(proof *proof.LDProof)) func(*vc.VerifiablePresentation) {
	return func(presentation *vc.VerifiablePresentation) {
		ldProof := presentation.Proof[0].(proof.LDProof)
		visitor(&ldProof)
		presentation.Proof[0] = ldProof
	}
}

// ParsePresentation marshals the given presentation and parses it again, to make sure the format property is set correctly.
func ParsePresentation(t *testing.T, presentation vc.VerifiablePresentation) vc.VerifiablePresentation {
	data, err := presentation.MarshalJSON()
	require.NoError(t, err)
	result, err := vc.ParseVerifiablePresentation(string(data))
	require.NoError(t, err)
	return *result
}
