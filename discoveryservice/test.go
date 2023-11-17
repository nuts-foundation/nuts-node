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

package discoveryservice

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"time"
)

var keyPairs map[string]*ecdsa.PrivateKey
var authorityDID did.DID
var aliceDID did.DID
var vcAlice vc.VerifiableCredential
var vpAlice vc.VerifiablePresentation
var bobDID did.DID
var vcBob vc.VerifiableCredential
var vpBob vc.VerifiablePresentation

var testServiceID = "usecase_v1"

func testDefinitions() map[string]Definition {
	return map[string]Definition{
		testServiceID: {
			ID:       testServiceID,
			Endpoint: "http://example.com/usecase",
			PresentationDefinition: pe.PresentationDefinition{
				InputDescriptors: []*pe.InputDescriptor{
					{
						Constraints: &pe.Constraints{
							Fields: []pe.Field{
								{
									Path: []string{"$.issuer"},
									Filter: &pe.Filter{
										Type: "string",
									},
								},
							},
						},
					},
				},
			},
			PresentationMaxValidity: int((24 * time.Hour).Seconds()),
		},
		"other": {
			ID:       "other",
			Endpoint: "http://example.com/other",
			PresentationDefinition: pe.PresentationDefinition{
				InputDescriptors: []*pe.InputDescriptor{
					{
						Constraints: &pe.Constraints{
							Fields: []pe.Field{
								{
									Path: []string{"$.issuer"},
									Filter: &pe.Filter{
										Type: "string",
									},
								},
							},
						},
					},
				},
			},
			PresentationMaxValidity: int((24 * time.Hour).Seconds()),
		},
	}
}

func init() {
	keyPairs = make(map[string]*ecdsa.PrivateKey)
	authorityDID = did.MustParseDID("did:example:authority")
	keyPairs[authorityDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	aliceDID = did.MustParseDID("did:example:alice")
	keyPairs[aliceDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bobDID = did.MustParseDID("did:example:bob")
	keyPairs[bobDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	vcAlice = createCredential(authorityDID, aliceDID)
	vpAlice = createPresentation(aliceDID, vcAlice)
	vcBob = createCredential(authorityDID, bobDID)
	vpBob = createPresentation(bobDID, vcBob)
}

func createCredential(issuerDID did.DID, subjectDID did.DID) vc.VerifiableCredential {
	return createCredentialWithClaims(issuerDID, subjectDID, func(claims map[string]interface{}) {
		// do nothing
	})
}

func createCredentialWithClaims(issuerDID did.DID, subjectDID did.DID, claimVisitor func(map[string]interface{})) vc.VerifiableCredential {
	vcID := did.DIDURL{DID: issuerDID}
	vcID.Fragment = uuid.NewString()
	vcIDURI := vcID.URI()
	expirationDate := time.Now().Add(time.Hour * 24)
	result, err := vc.CreateJWTVerifiableCredential(context.Background(), vc.VerifiableCredential{
		ID:             &vcIDURI,
		Issuer:         issuerDID.URI(),
		IssuanceDate:   time.Now(),
		ExpirationDate: &expirationDate,
		CredentialSubject: []interface{}{
			map[string]interface{}{
				"id": subjectDID.String(),
			},
		},
	}, func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
		claimVisitor(claims)
		return signJWT(subjectDID, claims, headers)
	})
	if err != nil {
		panic(err)
	}
	return *result
}

func createPresentation(subjectDID did.DID, credentials ...vc.VerifiableCredential) vc.VerifiablePresentation {
	return createPresentationCustom(subjectDID, func(_ map[string]interface{}, _ *vc.VerifiablePresentation) {
		// do nothing
	}, credentials...)
}

func createPresentationCustom(subjectDID did.DID, visitor func(claims map[string]interface{}, vp *vc.VerifiablePresentation), credentials ...vc.VerifiableCredential) vc.VerifiablePresentation {
	headers := map[string]interface{}{
		jws.TypeKey: "JWT",
	}
	innerVP := &vc.VerifiablePresentation{
		Type:                 append([]ssi.URI{ssi.MustParseURI("VerifiablePresentation")}),
		VerifiableCredential: credentials,
	}
	claims := map[string]interface{}{
		jwt.IssuerKey:     subjectDID.String(),
		jwt.SubjectKey:    subjectDID.String(),
		jwt.JwtIDKey:      subjectDID.String() + "#" + uuid.NewString(),
		jwt.NotBeforeKey:  time.Now().Unix(),
		jwt.ExpirationKey: time.Now().Add(time.Hour * 8),
	}
	visitor(claims, innerVP)
	claims["vp"] = *innerVP
	token, err := signJWT(subjectDID, claims, headers)
	if err != nil {
		panic(err)
	}
	presentation, err := vc.ParseVerifiablePresentation(token)
	if err != nil {
		panic(err)
	}
	return *presentation
}

func signJWT(subjectDID did.DID, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
	// Build JWK
	signingKey := keyPairs[subjectDID.String()]
	if signingKey == nil {
		return "", fmt.Errorf("key not found for DID: %s", subjectDID)
	}
	subjectKeyJWK, err := jwk.FromRaw(signingKey)
	if err != nil {
		return "", nil
	}
	keyID := did.DIDURL{DID: subjectDID}
	keyID.Fragment = "0"
	if err := subjectKeyJWK.Set(jwk.AlgorithmKey, jwa.ES256); err != nil {
		return "", err
	}
	if err := subjectKeyJWK.Set(jwk.KeyIDKey, keyID.String()); err != nil {
		return "", err
	}

	// Build token
	token := jwt.New()
	for k, v := range claims {
		if err := token.Set(k, v); err != nil {
			return "", err
		}
	}
	hdr := jws.NewHeaders()
	for k, v := range headers {
		if err := hdr.Set(k, v); err != nil {
			return "", err
		}
	}
	bytes, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, signingKey, jws.WithProtectedHeaders(hdr)))
	return string(bytes), err
}
