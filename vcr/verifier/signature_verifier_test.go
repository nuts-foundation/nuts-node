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

package verifier

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/cert"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/nuts-foundation/nuts-node/pki"
	"github.com/nuts-foundation/nuts-node/vdr/didx509"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vdr/didjwk"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestSignatureVerifier_VerifySignature(t *testing.T) {
	const testKID = "did:nuts:CuE3qeFGGLhEAS3gKzhMCeqd1dGa9at5JCbmCfyMU2Ey#sNGDQ3NlOe6Icv0E7_ufviOLG6Y25bSEyS5EbXBgp8Y"

	// load pub key
	pke := spi.PublicKeyEntry{}
	pkeJSON, _ := os.ReadFile("../test/public.json")
	json.Unmarshal(pkeJSON, &pke)
	var pk = new(ecdsa.PublicKey)
	pke.JWK().Raw(pk)

	t.Run("JSON-LD", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			sv, mockKeyResolver := signatureVerifierTestSetup(t)
			mockKeyResolver.EXPECT().ResolveKeyByID(testKID, gomock.Any(), resolver.NutsSigningKeyType).Return(pk, nil)

			err := sv.VerifySignature(testCredential(t), nil)

			assert.NoError(t, err)
		})
		t.Run("no proof", func(t *testing.T) {
			sv, _ := signatureVerifierTestSetup(t)
			credential := testCredential(t)
			credential.Proof = nil

			err := sv.VerifySignature(credential, nil)

			assert.Error(t, err)
		})
	})
	t.Run("JWT - X509", func(t *testing.T) {

		ura := "312312312"
		chainPems, rootCert, signingKey, signingCert, err := buildCertChain(ura)
		assert.NoError(t, err)

		cred, err := buildX509Credential(chainPems, signingCert, rootCert, signingKey, ura)
		assert.NoError(t, err)

		t.Run("happy flow", func(t *testing.T) {
			sv, validator := x509VerifierTestSetup(t)
			validator.EXPECT().ValidateStrict(gomock.Any()).Return(nil)
			err = sv.VerifySignature(*cred, nil)
			assert.NoError(t, err)
		})
		t.Run("failing ExtractProtectedHeaders", func(t *testing.T) {
			old := ExtractProtectedHeaders
			defer func() { ExtractProtectedHeaders = old }()
			expectedError := errors.New("failing ExtractProtectedHeaders")
			ExtractProtectedHeaders = func(jwt string) (map[string]interface{}, error) {
				return nil, expectedError
			}
			sv, _ := x509VerifierTestSetup(t)
			err = sv.VerifySignature(*cred, nil)
			assert.Error(t, err)
			assert.ErrorIs(t, err, expectedError)
		})
		t.Run("wrong ura", func(t *testing.T) {
			cred, err := buildX509Credential(chainPems, signingCert, rootCert, signingKey, ura)
			assert.NoError(t, err)
			sv, validator := x509VerifierTestSetup(t)
			expectedError := errors.New("wrong ura")
			validator.EXPECT().ValidateStrict(gomock.Any()).Return(expectedError)
			err = sv.VerifySignature(*cred, nil)
			assert.Error(t, err)
			assert.ErrorIs(t, err, expectedError)
		})
	})
	t.Run("JWT", func(t *testing.T) {
		// Create did:jwk for issuer, and sign credential
		keyStore := nutsCrypto.NewMemoryCryptoInstance(t)
		kid, key, err := keyStore.New(audit.TestContext(), func(key crypto.PublicKey) (string, error) {
			keyAsJWK, _ := jwk.FromRaw(key)
			keyJSON, _ := json.Marshal(keyAsJWK)
			return "did:jwk:" + base64.RawStdEncoding.EncodeToString(keyJSON) + "#0", nil
		})
		require.NoError(t, err)

		template := testCredential(t)
		template.Issuer = did.MustParseDIDURL(kid.KID).DID.URI()

		cred, err := vc.CreateJWTVerifiableCredential(audit.TestContext(), template, func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
			return keyStore.SignJWT(ctx, claims, headers, kid.KID)
		})
		require.NoError(t, err)

		t.Run("with kid header", func(t *testing.T) {
			sv, mockKeyResolver := signatureVerifierTestSetup(t)
			mockKeyResolver.EXPECT().ResolveKeyByID(kid.KID, gomock.Any(), resolver.NutsSigningKeyType).Return(key, nil)
			err = sv.VerifySignature(*cred, nil)

			assert.NoError(t, err)
		})
		t.Run("kid header does not match credential issuer", func(t *testing.T) {
			sv, mockKeyResolver := signatureVerifierTestSetup(t)

			cred, err := vc.CreateJWTVerifiableCredential(audit.TestContext(), template, func(ctx context.Context, claims map[string]interface{}, headers map[string]interface{}) (string, error) {
				return keyStore.SignJWT(ctx, claims, headers, kid.KID)
			})
			require.NoError(t, err)
			cred.Issuer = ssi.MustParseURI("did:example:test")

			mockKeyResolver.EXPECT().ResolveKeyByID(kid.KID, gomock.Any(), resolver.NutsSigningKeyType).Return(key, nil)
			err = sv.VerifySignature(*cred, nil)

			assert.ErrorIs(t, err, errVerificationMethodNotOfIssuer)
		})
		t.Run("signature invalid", func(t *testing.T) {
			sv, mockKeyResolver := signatureVerifierTestSetup(t)
			realKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			mockKeyResolver.EXPECT().ResolveKeyByID(kid.KID, gomock.Any(), resolver.NutsSigningKeyType).Return(realKey.Public(), nil)

			err = sv.VerifySignature(*cred, nil)

			assert.EqualError(t, err, "unable to validate JWT signature: could not verify message using any of the signatures or keys")
		})
		t.Run("expired token", func(t *testing.T) {
			// Credential taken from Sphereon Wallet, expires on Tue Oct 03 2023
			const credentialJSON = `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTYzMDE3MDgsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJHdWVzdENyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZmlyc3ROYW1lIjoiSGVsbG8iLCJsYXN0TmFtZSI6IlNwaGVyZW9uIiwiZW1haWwiOiJzcGhlcmVvbkBleGFtcGxlLmNvbSIsInR5cGUiOiJTcGhlcmVvbiBHdWVzdCIsImlkIjoiZGlkOmp3azpleUpoYkdjaU9pSkZVekkxTmtzaUxDSjFjMlVpT2lKemFXY2lMQ0pyZEhraU9pSkZReUlzSW1OeWRpSTZJbk5sWTNBeU5UWnJNU0lzSW5naU9pSmpNVmRZY3pkWE0yMTVjMlZWWms1Q2NYTjRaRkJYUWtsSGFFdGtORlI2TUV4U0xVWnFPRVpOV1dFd0lpd2llU0k2SWxkdGEwTllkVEYzZVhwYVowZE9OMVY0VG1Gd2NIRnVUMUZoVDJ0WE1rTm5UMU51VDI5NVRVbFVkV01pZlEifX0sIkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJHdWVzdENyZWRlbnRpYWwiXSwiZXhwaXJhdGlvbkRhdGUiOiIyMDIzLTEwLTAzVDAyOjU1OjA4LjEzM1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJmaXJzdE5hbWUiOiJIZWxsbyIsImxhc3ROYW1lIjoiU3BoZXJlb24iLCJlbWFpbCI6InNwaGVyZW9uQGV4YW1wbGUuY29tIiwidHlwZSI6IlNwaGVyZW9uIEd1ZXN0IiwiaWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOa3NpTENKMWMyVWlPaUp6YVdjaUxDSnJkSGtpT2lKRlF5SXNJbU55ZGlJNkluTmxZM0F5TlRack1TSXNJbmdpT2lKak1WZFljemRYTTIxNWMyVlZaazVDY1hONFpGQlhRa2xIYUV0a05GUjZNRXhTTFVacU9FWk5XV0V3SWl3aWVTSTZJbGR0YTBOWWRURjNlWHBhWjBkT04xVjRUbUZ3Y0hGdVQxRmhUMnRYTWtOblQxTnVUMjk1VFVsVWRXTWlmUSJ9LCJpc3N1ZXIiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lWRWN5U0RKNE1tUlhXRTR6ZFVOeFduQnhSakY1YzBGUVVWWkVTa1ZPWDBndFEwMTBZbWRxWWkxT1p5SXNJbmtpT2lJNVRUaE9lR1F3VUU0eU1rMDViRkJFZUdSd1JIQnZWRXg2TVRWM1pubGFTbk0yV21oTFNWVktNek00SW4wIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wOS0yOVQxMjozMTowOC4xMzNaIiwic3ViIjoiZGlkOmp3azpleUpoYkdjaU9pSkZVekkxTmtzaUxDSjFjMlVpT2lKemFXY2lMQ0pyZEhraU9pSkZReUlzSW1OeWRpSTZJbk5sWTNBeU5UWnJNU0lzSW5naU9pSmpNVmRZY3pkWE0yMTVjMlZWWms1Q2NYTjRaRkJYUWtsSGFFdGtORlI2TUV4U0xVWnFPRVpOV1dFd0lpd2llU0k2SWxkdGEwTllkVEYzZVhwYVowZE9OMVY0VG1Gd2NIRnVUMUZoVDJ0WE1rTm5UMU51VDI5NVRVbFVkV01pZlEiLCJuYmYiOjE2OTU5OTA2NjgsImlzcyI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVZFY3lTREo0TW1SWFdFNHpkVU54V25CeFJqRjVjMEZRVVZaRVNrVk9YMGd0UTAxMFltZHFZaTFPWnlJc0lua2lPaUk1VFRoT2VHUXdVRTR5TWswNWJGQkVlR1J3UkhCdlZFeDZNVFYzWm5sYVNuTTJXbWhMU1ZWS016TTRJbjAifQ.wdhtLXE4jU1C-3YBBpP9-qE-yh1xOZ6lBLJ-0e5_Sa7fnrUHcAaU1n3kN2CeCyTVjtm1Uy3Tl6RzUOM6MjP3vQ`
			cred, _ := vc.ParseVerifiableCredential(credentialJSON)

			sv := signatureVerifier{
				keyResolver: resolver.DIDKeyResolver{
					Resolver: didjwk.NewResolver(),
				},
			}
			err := sv.VerifySignature(*cred, nil)

			assert.EqualError(t, err, "unable to validate JWT signature: \"exp\" not satisfied")
		})
		t.Run("without kid header, derived from issuer", func(t *testing.T) {
			// Credential taken from Sphereon Wallet
			const credentialJSON = `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTYzMDE3MDgsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJHdWVzdENyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZmlyc3ROYW1lIjoiSGVsbG8iLCJsYXN0TmFtZSI6IlNwaGVyZW9uIiwiZW1haWwiOiJzcGhlcmVvbkBleGFtcGxlLmNvbSIsInR5cGUiOiJTcGhlcmVvbiBHdWVzdCIsImlkIjoiZGlkOmp3azpleUpoYkdjaU9pSkZVekkxTmtzaUxDSjFjMlVpT2lKemFXY2lMQ0pyZEhraU9pSkZReUlzSW1OeWRpSTZJbk5sWTNBeU5UWnJNU0lzSW5naU9pSmpNVmRZY3pkWE0yMTVjMlZWWms1Q2NYTjRaRkJYUWtsSGFFdGtORlI2TUV4U0xVWnFPRVpOV1dFd0lpd2llU0k2SWxkdGEwTllkVEYzZVhwYVowZE9OMVY0VG1Gd2NIRnVUMUZoVDJ0WE1rTm5UMU51VDI5NVRVbFVkV01pZlEifX0sIkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJHdWVzdENyZWRlbnRpYWwiXSwiZXhwaXJhdGlvbkRhdGUiOiIyMDIzLTEwLTAzVDAyOjU1OjA4LjEzM1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJmaXJzdE5hbWUiOiJIZWxsbyIsImxhc3ROYW1lIjoiU3BoZXJlb24iLCJlbWFpbCI6InNwaGVyZW9uQGV4YW1wbGUuY29tIiwidHlwZSI6IlNwaGVyZW9uIEd1ZXN0IiwiaWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOa3NpTENKMWMyVWlPaUp6YVdjaUxDSnJkSGtpT2lKRlF5SXNJbU55ZGlJNkluTmxZM0F5TlRack1TSXNJbmdpT2lKak1WZFljemRYTTIxNWMyVlZaazVDY1hONFpGQlhRa2xIYUV0a05GUjZNRXhTTFVacU9FWk5XV0V3SWl3aWVTSTZJbGR0YTBOWWRURjNlWHBhWjBkT04xVjRUbUZ3Y0hGdVQxRmhUMnRYTWtOblQxTnVUMjk1VFVsVWRXTWlmUSJ9LCJpc3N1ZXIiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lWRWN5U0RKNE1tUlhXRTR6ZFVOeFduQnhSakY1YzBGUVVWWkVTa1ZPWDBndFEwMTBZbWRxWWkxT1p5SXNJbmtpT2lJNVRUaE9lR1F3VUU0eU1rMDViRkJFZUdSd1JIQnZWRXg2TVRWM1pubGFTbk0yV21oTFNWVktNek00SW4wIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wOS0yOVQxMjozMTowOC4xMzNaIiwic3ViIjoiZGlkOmp3azpleUpoYkdjaU9pSkZVekkxTmtzaUxDSjFjMlVpT2lKemFXY2lMQ0pyZEhraU9pSkZReUlzSW1OeWRpSTZJbk5sWTNBeU5UWnJNU0lzSW5naU9pSmpNVmRZY3pkWE0yMTVjMlZWWms1Q2NYTjRaRkJYUWtsSGFFdGtORlI2TUV4U0xVWnFPRVpOV1dFd0lpd2llU0k2SWxkdGEwTllkVEYzZVhwYVowZE9OMVY0VG1Gd2NIRnVUMUZoVDJ0WE1rTm5UMU51VDI5NVRVbFVkV01pZlEiLCJuYmYiOjE2OTU5OTA2NjgsImlzcyI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVZFY3lTREo0TW1SWFdFNHpkVU54V25CeFJqRjVjMEZRVVZaRVNrVk9YMGd0UTAxMFltZHFZaTFPWnlJc0lua2lPaUk1VFRoT2VHUXdVRTR5TWswNWJGQkVlR1J3UkhCdlZFeDZNVFYzWm5sYVNuTTJXbWhMU1ZWS016TTRJbjAifQ.wdhtLXE4jU1C-3YBBpP9-qE-yh1xOZ6lBLJ-0e5_Sa7fnrUHcAaU1n3kN2CeCyTVjtm1Uy3Tl6RzUOM6MjP3vQ`
			cred, _ := vc.ParseVerifiableCredential(credentialJSON)

			sv := signatureVerifier{
				keyResolver: resolver.DIDKeyResolver{
					Resolver: didjwk.NewResolver(),
				},
			}
			validAt := time.Date(2023, 9, 30, 0, 0, 0, 0, time.UTC)
			err := sv.VerifySignature(*cred, &validAt)

			assert.NoError(t, err)
		})
		t.Run("no signature", func(t *testing.T) {
			// Credential taken from Sphereon Wallet
			const credentialJSON = `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTYzMDE3MDgsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJHdWVzdENyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiZmlyc3ROYW1lIjoiSGVsbG8iLCJsYXN0TmFtZSI6IlNwaGVyZW9uIiwiZW1haWwiOiJzcGhlcmVvbkBleGFtcGxlLmNvbSIsInR5cGUiOiJTcGhlcmVvbiBHdWVzdCIsImlkIjoiZGlkOmp3azpleUpoYkdjaU9pSkZVekkxTmtzaUxDSjFjMlVpT2lKemFXY2lMQ0pyZEhraU9pSkZReUlzSW1OeWRpSTZJbk5sWTNBeU5UWnJNU0lzSW5naU9pSmpNVmRZY3pkWE0yMTVjMlZWWms1Q2NYTjRaRkJYUWtsSGFFdGtORlI2TUV4U0xVWnFPRVpOV1dFd0lpd2llU0k2SWxkdGEwTllkVEYzZVhwYVowZE9OMVY0VG1Gd2NIRnVUMUZoVDJ0WE1rTm5UMU51VDI5NVRVbFVkV01pZlEifX0sIkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJHdWVzdENyZWRlbnRpYWwiXSwiZXhwaXJhdGlvbkRhdGUiOiIyMDIzLTEwLTAzVDAyOjU1OjA4LjEzM1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJmaXJzdE5hbWUiOiJIZWxsbyIsImxhc3ROYW1lIjoiU3BoZXJlb24iLCJlbWFpbCI6InNwaGVyZW9uQGV4YW1wbGUuY29tIiwidHlwZSI6IlNwaGVyZW9uIEd1ZXN0IiwiaWQiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOa3NpTENKMWMyVWlPaUp6YVdjaUxDSnJkSGtpT2lKRlF5SXNJbU55ZGlJNkluTmxZM0F5TlRack1TSXNJbmdpT2lKak1WZFljemRYTTIxNWMyVlZaazVDY1hONFpGQlhRa2xIYUV0a05GUjZNRXhTTFVacU9FWk5XV0V3SWl3aWVTSTZJbGR0YTBOWWRURjNlWHBhWjBkT04xVjRUbUZ3Y0hGdVQxRmhUMnRYTWtOblQxTnVUMjk1VFVsVWRXTWlmUSJ9LCJpc3N1ZXIiOiJkaWQ6andrOmV5SmhiR2NpT2lKRlV6STFOaUlzSW5WelpTSTZJbk5wWnlJc0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lWRWN5U0RKNE1tUlhXRTR6ZFVOeFduQnhSakY1YzBGUVVWWkVTa1ZPWDBndFEwMTBZbWRxWWkxT1p5SXNJbmtpT2lJNVRUaE9lR1F3VUU0eU1rMDViRkJFZUdSd1JIQnZWRXg2TVRWM1pubGFTbk0yV21oTFNWVktNek00SW4wIiwiaXNzdWFuY2VEYXRlIjoiMjAyMy0wOS0yOVQxMjozMTowOC4xMzNaIiwic3ViIjoiZGlkOmp3azpleUpoYkdjaU9pSkZVekkxTmtzaUxDSjFjMlVpT2lKemFXY2lMQ0pyZEhraU9pSkZReUlzSW1OeWRpSTZJbk5sWTNBeU5UWnJNU0lzSW5naU9pSmpNVmRZY3pkWE0yMTVjMlZWWms1Q2NYTjRaRkJYUWtsSGFFdGtORlI2TUV4U0xVWnFPRVpOV1dFd0lpd2llU0k2SWxkdGEwTllkVEYzZVhwYVowZE9OMVY0VG1Gd2NIRnVUMUZoVDJ0WE1rTm5UMU51VDI5NVRVbFVkV01pZlEiLCJuYmYiOjE2OTU5OTA2NjgsImlzcyI6ImRpZDpqd2s6ZXlKaGJHY2lPaUpGVXpJMU5pSXNJblZ6WlNJNkluTnBaeUlzSW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMweU5UWWlMQ0o0SWpvaVZFY3lTREo0TW1SWFdFNHpkVU54V25CeFJqRjVjMEZRVVZaRVNrVk9YMGd0UTAxMFltZHFZaTFPWnlJc0lua2lPaUk1VFRoT2VHUXdVRTR5TWswNWJGQkVlR1J3UkhCdlZFeDZNVFYzWm5sYVNuTTJXbWhMU1ZWS016TTRJbjAifQ.`
			cred, _ := vc.ParseVerifiableCredential(credentialJSON)

			sv := signatureVerifier{
				keyResolver: resolver.DIDKeyResolver{
					Resolver: didjwk.NewResolver(),
				},
			}
			err := sv.VerifySignature(*cred, nil)

			assert.EqualError(t, err, "unable to validate JWT signature: could not verify message using any of the signatures or keys")
		})
	})

	t.Run("error - invalid vm", func(t *testing.T) {
		sv, _ := signatureVerifierTestSetup(t)

		vc2 := testCredential(t)
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		_ = vc2.UnmarshalProofValue(&pr)
		u := ssi.MustParseURI(vc2.Issuer.String() + "2")
		pr[0].VerificationMethod = u
		vc2.Proof = []interface{}{pr[0]}

		err := sv.VerifySignature(vc2, nil)

		assert.Error(t, err)
		assert.ErrorIs(t, err, errVerificationMethodNotOfIssuer)
	})

	t.Run("error - wrong hashed payload", func(t *testing.T) {
		sv, mockKeyResolver := signatureVerifierTestSetup(t)
		vc2 := testCredential(t)
		issuanceDate := time.Now()
		vc2.IssuanceDate = issuanceDate
		mockKeyResolver.EXPECT().ResolveKeyByID(testKID, gomock.Any(), resolver.NutsSigningKeyType).Return(pk, nil)

		err := sv.VerifySignature(vc2, nil)

		assert.ErrorContains(t, err, "failed to verify signature")
	})

	t.Run("error - wrong hashed proof", func(t *testing.T) {
		sv, mockKeyResolver := signatureVerifierTestSetup(t)
		vc2 := testCredential(t)
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Created = time.Now()
		vc2.Proof = []interface{}{pr[0]}

		mockKeyResolver.EXPECT().ResolveKeyByID(testKID, gomock.Any(), resolver.NutsSigningKeyType).Return(pk, nil)

		err := sv.VerifySignature(vc2, nil)

		assert.ErrorContains(t, err, "failed to verify signature")
	})

	t.Run("error - no proof", func(t *testing.T) {
		sv, _ := signatureVerifierTestSetup(t)
		vc2 := testCredential(t)
		vc2.Proof = []interface{}{}

		err := sv.VerifySignature(vc2, nil)

		assert.EqualError(t, err, "verification error: missing proof")
	})

	t.Run("error - wrong jws in proof", func(t *testing.T) {
		sv, mockKeyResolver := signatureVerifierTestSetup(t)
		mockKeyResolver.EXPECT().ResolveKeyByID(testKID, gomock.Any(), resolver.NutsSigningKeyType).Return(pk, nil)
		vc2 := testCredential(t)
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Jws = ""
		vc2.Proof = []interface{}{pr[0]}

		err := sv.VerifySignature(vc2, nil)

		assert.ErrorContains(t, err, "invalid 'jws' value in proof")
	})

	t.Run("error - wrong base64 encoding in jws", func(t *testing.T) {
		sv, mockKeyResolver := signatureVerifierTestSetup(t)
		mockKeyResolver.EXPECT().ResolveKeyByID(testKID, gomock.Any(), resolver.NutsSigningKeyType).Return(pk, nil)
		vc2 := testCredential(t)
		pr := make([]vc.JSONWebSignature2020Proof, 0)
		vc2.UnmarshalProofValue(&pr)
		pr[0].Jws = "abac..ab//"
		vc2.Proof = []interface{}{pr[0]}

		err := sv.VerifySignature(vc2, nil)

		assert.ErrorContains(t, err, "illegal base64 data")
	})

	t.Run("error - resolving key", func(t *testing.T) {
		sv, mockKeyResolver := signatureVerifierTestSetup(t)
		mockKeyResolver.EXPECT().ResolveKeyByID(testKID, gomock.Any(), resolver.NutsSigningKeyType).Return(nil, errors.New("b00m!"))

		err := sv.VerifySignature(testCredential(t), nil)

		assert.Error(t, err)
	})
}

func buildX509Credential(chainPems *cert.Chain, signingCert *x509.Certificate, rootCert *x509.Certificate, signingKey *rsa.PrivateKey, ura string) (*vc.VerifiableCredential, error) {
	headers := map[string]interface{}{}
	headers["x5c"] = chainPems
	hashSha1 := sha1.Sum(signingCert.Raw)
	headers["x5t"] = base64.RawURLEncoding.EncodeToString(hashSha1[:])

	hashSha256 := sha256.Sum256(rootCert.Raw)
	rootCertHashBytes := hashSha256[:]
	rootCertHashStr := base64.RawURLEncoding.EncodeToString(rootCertHashBytes)
	did := "did:x509:0:sha256:" + rootCertHashStr + "::subject:serialNumber:" + ura
	headers["kid"] = did + "#0"

	claims := map[string]interface{}{}
	claims["iss"] = did
	claims["sub"] = did
	credential, err := testUraCredential(did, ura)
	if err != nil {
		return nil, err
	}

	claims["vc"] = *credential

	token, err := nutsCrypto.SignJWT(audit.TestContext(), signingKey, jwa.PS512, claims, headers)
	if err != nil {
		return nil, err
	}
	cred, err := vc.ParseVerifiableCredential(token)
	if err != nil {
		return nil, err
	}
	return cred, nil
}

func buildCertChain(ura string) (*cert.Chain, *x509.Certificate, *rsa.PrivateKey, *x509.Certificate, error) {
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	rootCertTmpl, err := CertTemplate("Root CA")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	rootCertTmpl.IsCA = true
	rootCertTmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	rootCertTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	rootCert, rootPem, err := CreateCert(rootCertTmpl, rootCertTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	intermediateL1Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	intermediateL1Tmpl, err := CertTemplate("Intermediate CA Level 1")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	intermediateL1Tmpl.IsCA = true
	intermediateL1Tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	intermediateL1Tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	intermediateL1Cert, intermediateL1Pem, err := CreateCert(intermediateL1Tmpl, rootCertTmpl, &intermediateL1Key.PublicKey, rootKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	intermediateL2Key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	intermediateL2Tmpl, err := CertTemplate("Intermediate CA Level 2")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	intermediateL2Tmpl.IsCA = true
	intermediateL2Tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	intermediateL2Tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	intermediateL2Cert, intermediateL2Pem, err := CreateCert(intermediateL2Tmpl, intermediateL1Cert, &intermediateL2Key.PublicKey, intermediateL1Key)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	signingTmpl, err := CertTemplate("Leaf")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	signingTmpl.Subject.SerialNumber = ura
	signingTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	signingTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	signingCert, signingPEM, err := CreateCert(signingTmpl, intermediateL2Cert, &signingKey.PublicKey, intermediateL2Key)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	certChain := &cert.Chain{}
	for _, str := range []string{signingPEM, intermediateL2Pem, intermediateL1Pem, rootPem} {
		fixedPem := strings.ReplaceAll(str, "\n", "\\n")
		err = certChain.Add([]byte(fixedPem))
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}

	return certChain, rootCert, signingKey, signingCert, nil
}

func testUraCredential(did string, ura string) (*vc.VerifiableCredential, error) {
	credential := &vc.VerifiableCredential{}
	credential.Issuer = ssi.MustParseURI(did)
	credential.Context = []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")}
	credential.Type = []ssi.URI{ssi.MustParseURI("VerifiableCredential"), ssi.MustParseURI("NutsUraCredential")}
	credentialId := ssi.MustParseURI(uuid.NewString())
	credential.ID = &credentialId
	credential.IssuanceDate = time.Now()
	exp := time.Now().Add(time.Hour * 24 * 365 * 12)
	credential.ExpirationDate = &exp
	subject := map[string]interface{}{}
	subject["id"] = did
	subject["uraNumber"] = ura
	credential.CredentialSubject = []interface{}{subject}
	return credential, nil
}

func fixChainHeaders(chain *cert.Chain) (*cert.Chain, error) {
	rv := &cert.Chain{}
	for i := 0; i < chain.Len(); i++ {
		value, _ := chain.Get(i)
		der := strings.ReplaceAll(string(value), "\n", "\\n")
		err := rv.AddString(der)
		if err != nil {
			return nil, err
		}
	}
	return rv, nil
}

func signatureVerifierTestSetup(t testing.TB) (signatureVerifier, *resolver.MockKeyResolver) {
	ctrl := gomock.NewController(t)
	keyResolver := resolver.NewMockKeyResolver(ctrl)
	return signatureVerifier{
		keyResolver:   keyResolver,
		jsonldManager: jsonld.NewTestJSONLDManager(t),
	}, keyResolver
}

func x509VerifierTestSetup(t testing.TB) (signatureVerifier, *pki.MockValidator) {
	ctrl := gomock.NewController(t)
	pkiMock := pki.NewMockValidator(ctrl)
	var keyResolver = resolver.DIDKeyResolver{
		Resolver: didx509.NewResolver(pkiMock),
	}
	return signatureVerifier{
		keyResolver:   keyResolver,
		jsonldManager: jsonld.NewTestJSONLDManager(t),
	}, pkiMock
}

// CertTemplate is a helper function to create a cert template with a serial number and other required fields
func CertTemplate(subjectName string) (*x509.Certificate, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 8)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{subjectName}},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 30), // valid for a month
		BasicConstraintsValid: true,
	}
	return &tmpl, nil
}

// CreateCert invokes x509.CreateCertificate and returns it in the x509.Certificate format
func CreateCert(template, parent *x509.Certificate, pub interface{}, parentPriv interface{}) (cert *x509.Certificate, certPEM string, err error) {
	certDER, err := x509.CreateCertificate(rand.Reader, template, parent, pub, parentPriv)
	if err != nil {
		return nil, "", err
	}
	// parse the resulting certificate so we can use it again
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return nil, "", err
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	certPEM = string(pem.EncodeToMemory(&b))
	return cert, certPEM, err
}
