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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vdr"
)

func ValidNutsAuthorizationCredential() *vc.VerifiableCredential {
	id := stringToURI(vdr.TestDIDA.String() + "#38E90E8C-F7E5-4333-B63A-F9DD155A0272")
	issuanceDate := time.Now()
	return &vc.VerifiableCredential{
		Context:      []ssi.URI{vc.VCContextV1URI(), NutsV1ContextURI},
		ID:           &id,
		Type:         []ssi.URI{*NutsAuthorizationCredentialTypeURI, vc.VerifiableCredentialTypeV1URI()},
		Issuer:       stringToURI(vdr.TestDIDA.String()),
		IssuanceDate: &issuanceDate,
		CredentialSubject: []interface{}{
			NutsAuthorizationCredentialSubject{
				ID:           vdr.TestDIDB.String(),
				PurposeOfUse: "eTransfer",
				Resources: []Resource{
					{
						Path:        "/composition/1",
						Operations:  []string{"read"},
						UserContext: true,
					},
				},
			},
		},
		Proof: []interface{}{vc.Proof{}},
	}
}

func ValidNutsOrganizationCredential(t *testing.T) vc.VerifiableCredential {
	inputVC := vc.VerifiableCredential{}
	vcJSON, err := assets.TestAssets.ReadFile("test_assets/vc.json")
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(vcJSON, &inputVC)
	if err != nil {
		t.Fatal(err)
	}
	return inputVC
}

func JWTNutsOrganizationCredential(t *testing.T, subjectID did.DID) vc.VerifiableCredential {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	token := jwt.New()
	require.NoError(t, token.Set("vc", map[string]interface{}{
		"credentialSubject": map[string]interface{}{
			"id": subjectID,
			"organization": map[string]interface{}{
				"city": "IJbergen",
				"name": "care",
			},
		},
		"type": "NutsOrganizationCredential",
	}))
	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.ES384, privateKey))
	require.NoError(t, err)
	jwtVC, err := vc.ParseVerifiableCredential(string(signedToken))
	require.NoError(t, err)
	return *jwtVC
}

func ValidStatusList2021Credential(_ testing.TB) vc.VerifiableCredential {
	id := ssi.MustParseURI("https://example.com/credentials/status/3")
	validFrom := time.Now()
	validUntilTomorrow := validFrom.Add(24 * time.Hour)
	return vc.VerifiableCredential{
		Context:          []ssi.URI{vc.VCContextV1URI(), statusList2021ContextURI},
		ID:               &id,
		Type:             []ssi.URI{vc.VerifiableCredentialTypeV1URI(), stringToURI(StatusList2021CredentialType)},
		Issuer:           ssi.MustParseURI("did:example:12345"),
		ValidFrom:        &validFrom,
		ValidUntil:       &validUntilTomorrow,
		CredentialStatus: nil,
		CredentialSubject: []any{&StatusList2021CredentialSubject{
			Id:            "https://example-com/status/3#list",
			Type:          StatusList2021CredentialSubjectType,
			StatusPurpose: "revocation",
			EncodedList:   "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA",
		}},
		Proof: []any{vc.Proof{}},
	}
}

func stringToURI(input string) ssi.URI {
	return ssi.MustParseURI(input)
}
