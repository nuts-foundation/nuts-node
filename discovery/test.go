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

package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core/to"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"time"
)

var keyPairs map[string]*ecdsa.PrivateKey
var authorityDID did.DID
var aliceSubject string
var aliceDID did.DID
var vcAlice vc.VerifiableCredential
var vpAlice vc.VerifiablePresentation
var aliceDiscoveryCredential vc.VerifiableCredential
var bobSubject string
var bobDID did.DID
var vcBob vc.VerifiableCredential
var vpBob vc.VerifiablePresentation
var unsupportedDID did.DID

var testServiceID = "usecase_v1"
var unsupportedServiceID = "unsupported"

func testDefinitions() map[string]ServiceDefinition {
	return map[string]ServiceDefinition{
		testServiceID: {
			ID:       testServiceID,
			Endpoint: "http://example.com/usecase",
			PresentationDefinition: pe.PresentationDefinition{
				Format: &pe.PresentationDefinitionClaimFormatDesignations{
					"ldp_vc": {
						"proof_type": []string{
							"JsonWebSignature2020",
						},
					},
					"ldp_vp": {
						"proof_type": []string{
							"JsonWebSignature2020",
						},
					},
					"jwt_vc": {
						"alg": []string{
							"ES256",
						},
					},
					"jwt_vp": {
						"alg": []string{
							"ES256",
						},
					},
				},
				InputDescriptors: []*pe.InputDescriptor{
					{
						Id: "1",
						Constraints: &pe.Constraints{
							Fields: []pe.Field{
								{
									Id:   to.Ptr("issuer_field"),
									Path: []string{"$.issuer"},
									Filter: &pe.Filter{
										Type:    "string",
										Pattern: to.Ptr("did:example:authority"),
									},
								},
							},
						},
					},
					{
						Id: "2",
						Constraints: &pe.Constraints{
							Fields: []pe.Field{
								{
									Id:   to.Ptr("auth_server_url_field"),
									Path: []string{"$.credentialSubject.authServerURL", "$.credentialSubject[0].authServerURL"},
									Filter: &pe.Filter{
										Type: "string",
									},
								},
								{
									Id:   to.Ptr("type_field"),
									Path: []string{"$.type"},
									Filter: &pe.Filter{
										Type:  "string",
										Const: to.Ptr(credential.DiscoveryRegistrationCredentialType),
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
		unsupportedServiceID: {
			ID:                      "unsupported",
			DIDMethods:              []string{"unsupported"},
			Endpoint:                "http://example.com/unsupported",
			PresentationMaxValidity: int((24 * time.Hour).Seconds()),
		},
	}
}

func init() {
	keyPairs = make(map[string]*ecdsa.PrivateKey)
	authorityDID = did.MustParseDID("did:example:authority")
	keyPairs[authorityDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	aliceSubject = "alice"
	aliceDID = did.MustParseDID("did:example:alice")
	keyPairs[aliceDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bobSubject = "bob"
	bobDID = did.MustParseDID("did:example:bob")
	keyPairs[bobDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	unsupportedDID = did.MustParseDID("did:web:example.com")
	keyPairs[unsupportedDID.String()], _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	aliceDiscoveryCredential = createHolderCredential(aliceDID, defaultRegistrationParams(aliceSubject))
	vcAlice = createCredential(authorityDID, aliceDID, map[string]interface{}{
		"person": map[string]interface{}{
			"givenName":  "Alice",
			"familyName": "Jones",
		},
	}, nil)
	vpAlice = createPresentationCustom(aliceDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
		claims[jwt.AudienceKey] = []string{testServiceID}
	}, vcAlice, aliceDiscoveryCredential)
	vcBob = createCredential(authorityDID, bobDID, map[string]interface{}{
		"person": map[string]interface{}{
			"givenName":  "Bob",
			"familyName": "Jomper",
		},
	}, nil)
	vpBob = createPresentationCustom(bobDID, func(claims map[string]interface{}, vp *vc.VerifiablePresentation) {
		claims[jwt.AudienceKey] = []string{testServiceID}
	}, vcBob)
}

func createCredential(issuerDID did.DID, subjectDID did.DID, credentialSubject map[string]interface{}, claimVisitor func(map[string]interface{})) vc.VerifiableCredential {
	vcID := did.DIDURL{DID: issuerDID}
	vcID.Fragment = uuid.NewString()
	vcIDURI := vcID.URI()
	issuanceDate := time.Now()
	expirationDate := issuanceDate.Add(time.Hour * 24)
	if credentialSubject == nil {
		credentialSubject = make(map[string]interface{})
	}
	credentialSubject["id"] = subjectDID.String()
	result, err := vc.CreateJWTVerifiableCredential(context.Background(), vc.VerifiableCredential{
		ID:                &vcIDURI,
		Type:              []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("TestCredential")},
		Issuer:            issuerDID.URI(),
		IssuanceDate:      issuanceDate,
		ExpirationDate:    &expirationDate,
		CredentialSubject: []interface{}{credentialSubject},
	}, func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
		if claimVisitor != nil {
			claimVisitor(claims)
		}
		return signJWT(subjectDID, claims, headers)
	})
	if err != nil {
		panic(err)
	}
	return *result
}

func createHolderCredential(subjectDID did.DID, credentialSubject map[string]interface{}) vc.VerifiableCredential {
	c := vc.VerifiableCredential{
		Context:           []ssi.URI{vc.VCContextV1URI(), credential.NutsV1ContextURI},
		Type:              []ssi.URI{vc.VerifiableCredentialTypeV1URI(), credential.DiscoveryRegistrationCredentialTypeV1URI()},
		CredentialSubject: []interface{}{credentialSubject},
	}
	c = credential.AutoCorrectSelfAttestedCredential(c, subjectDID)
	// serialize/deserialize
	bytes, _ := json.Marshal(c)
	result := vc.VerifiableCredential{}
	_ = json.Unmarshal(bytes, &result)
	return result
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
		Type:                 []ssi.URI{ssi.MustParseURI("VerifiablePresentation")},
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
	bytes, err := jwt.Sign(token, jwt.WithKey(subjectKeyJWK.Algorithm(), subjectKeyJWK, jws.WithProtectedHeaders(hdr)))
	return string(bytes), err
}

func defaultRegistrationParams(subject string) map[string]interface{} {
	return map[string]interface{}{
		"authServerURL": test.MustParseURL("https://example.com/oauth2/").JoinPath(subject).String(),
	}
}
