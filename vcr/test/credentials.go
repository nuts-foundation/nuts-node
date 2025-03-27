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

package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/nuts-foundation/nuts-node/test/pki"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vdr"
)

func ValidNutsAuthorizationCredential(t testing.TB) vc.VerifiableCredential {
	if t == nil {
		panic("can only be used in tests")
	}
	id := ssi.MustParseURI(vdr.TestDIDA.String() + "#38E90E8C-F7E5-4333-B63A-F9DD155A0272")
	issuanceDate := time.Now()
	return vc.VerifiableCredential{
		Context:      []ssi.URI{vc.VCContextV1URI(), ssi.MustParseURI("https://nuts.nl/credentials/v1")},
		ID:           &id,
		Type:         []ssi.URI{ssi.MustParseURI("NutsAuthorizationCredential"), vc.VerifiableCredentialTypeV1URI()},
		Issuer:       ssi.MustParseURI(vdr.TestDIDA.String()),
		IssuanceDate: issuanceDate,
		CredentialSubject: []interface{}{
			map[string]any{
				"id":           vdr.TestDIDB.String(),
				"purposeOfUse": "eTransfer",
				"resources": []any{
					map[string]any{
						"path":        "/composition/1",
						"operations":  []string{"read"},
						"userContext": true,
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

func ValidStatusList2021Credential(t testing.TB) vc.VerifiableCredential {
	if t == nil {
		panic("can only be used in tests")
	}
	id := ssi.MustParseURI("https://example.com/credentials/status/3")
	issuanceDate := time.Now()
	expirationDate := issuanceDate.Add(24 * time.Hour)
	return vc.VerifiableCredential{
		Context:          []ssi.URI{vc.VCContextV1URI(), ssi.MustParseURI("https://w3id.org/vc/status-list/2021/v1")},
		ID:               &id,
		Type:             []ssi.URI{vc.VerifiableCredentialTypeV1URI(), ssi.MustParseURI("StatusList2021Credential")},
		Issuer:           ssi.MustParseURI("did:example:12345"),
		IssuanceDate:     issuanceDate,
		ExpirationDate:   &expirationDate,
		CredentialStatus: nil,
		CredentialSubject: []any{
			map[string]any{
				"id":            "https://example-com/status/3#list",
				"type":          "StatusList2021",
				"statusPurpose": "revocation",
				"encodedList":   "H4sIAAAAAAAA_-zAsQAAAAACsNDypwqjZ2sAAAAAAAAAAAAAAAAAAACAtwUAAP__NxdfzQBAAAA=", // has bit 1 set to true
			},
		},
		Proof: []any{vc.Proof{}},
	}
}

type credentialOption func(*jwt.Builder) *jwt.Builder

func ValidX509Credential(t *testing.T, options ...credentialOption) vc.VerifiableCredential {
	otherNameValue := "A_BIG_STRING"
	certs, keys, err := pki.BuildCertChain([]string{otherNameValue}, "123")
	require.NoError(t, err)
	rootCertificate := certs[len(certs)-1]
	rootKey := keys[len(keys)-1]
	rootHash := sha256.Sum256(rootCertificate.Raw)
	rootDID := did.MustParseDID(fmt.Sprintf("did:x509:0:%s:%s::subject:C:NL:O:NUTS%%20Foundation:L:Amsterdam:CN:www.example.com::san:otherName:%s", "sha256", base64.RawURLEncoding.EncodeToString(rootHash[:]), otherNameValue))
	x5c := cert.Chain{}
	for _, cert := range certs {
		_ = x5c.AddString(base64.StdEncoding.EncodeToString(cert.Raw))
	}

	x5t := sha256.Sum256(certs[0].Raw)
	headers := jws.NewHeaders()
	_ = headers.Set(jws.X509CertChainKey, &x5c)
	err = headers.Set(jws.X509CertThumbprintS256Key, base64.RawURLEncoding.EncodeToString(x5t[:]))
	require.NoError(t, err)
	builder := jwt.NewBuilder().
		JwtID(fmt.Sprintf("%s#1", rootDID)).
		Issuer(rootDID.String()).
		NotBefore(time.Now()).
		Subject("did:example:1").
		Claim("vc", map[string]interface{}{
			"@context": []string{"https://www.w3.org/2018/credentials/v1"},
			"type":     []string{vc.VerifiableCredentialType, "X509Credential"},
			"credentialSubject": map[string]interface{}{
				"id": rootDID.String(),
				"subject": map[string]interface{}{
					"C":  "NL",
					"O":  "NUTS Foundation",
					"L":  "Amsterdam",
					"CN": "www.example.com",
				},
				"san": map[string]interface{}{
					"otherName": otherNameValue,
				},
			},
		})
	for _, option := range options {
		builder = option(builder)
	}
	token, err := builder.Build()
	require.NoError(t, err)
	s, err := jwt.Sign(token, jwt.WithKey(jwa.RS256, rootKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	credential, err := vc.ParseVerifiableCredential(string(s))
	require.NoError(t, err)
	return *credential
}
