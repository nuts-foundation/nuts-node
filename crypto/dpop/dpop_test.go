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

package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDPoP(t *testing.T) {
	t.Run("sets correct headers and claims", func(t *testing.T) {
		request, _ := http.NewRequest("POST", "https://server.example.com/token", nil)

		token := New(*request)

		require.NotNil(t, token)
		assert.Equal(t, DPopType, token.Headers.Type())
		assert.Equal(t, "POST", token.HTM())
		assert.Equal(t, "https://server.example.com/token", token.HTU())
		// check if jti is set
		jti, ok := token.Token.Get(jwt.JwtIDKey)
		require.True(t, ok)
		assert.NotEmpty(t, jti)
	})
}

func TestDPoP_Proof(t *testing.T) {
	t.Run("adds ath claim to token", func(t *testing.T) {
		request, _ := http.NewRequest("POST", "https://server.example.com/token", nil)

		token := New(*request)
		token.GenerateProof("token")

		ath, ok := token.Token.Get(ATHKey)
		require.True(t, ok)
		assert.Equal(t, "PEaenWxYddN6Q_NT1PiOYfz4EsZu7jRXRlpAsNpBU-A", ath)
	})
}

func TestDPoP_Sign(t *testing.T) {
	keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.FromRaw(keyPair)
	_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256)
	_ = jwkKey.Set(jwk.KeyIDKey, "kid")
	publicKey, _ := jwkKey.PublicKey()
	request, _ := http.NewRequest("POST", "https://server.example.com/token", nil)

	t.Run("ok", func(t *testing.T) {
		token := New(*request)
		token.GenerateProof("token")

		tokenString, err := token.Sign(jwkKey)

		require.NoError(t, err)
		// check if jwk header is set and if the private part of the is omitted
		message, err := jws.ParseString(tokenString)
		require.NoError(t, err)
		jwk, ok := message.Signatures()[0].ProtectedHeaders().Get(jws.JWKKey)
		require.True(t, ok)
		assert.Equal(t, publicKey, jwk)
	})
	t.Run("already signed", func(t *testing.T) {
		token := New(*request)
		_, _ = token.Sign(jwkKey)

		_, err := token.Sign(nil)

		require.Error(t, err)
		assert.EqualError(t, err, "already signed")
	})
}

func TestParseDPoP(t *testing.T) {
	keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.FromRaw(keyPair)
	_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256)
	_ = jwkKey.Set(jwk.KeyIDKey, "kid")
	pkey, _ := jwkKey.PublicKey()
	request, _ := http.NewRequest("GET", "https://server.example.com/token", nil)

	t.Run("ok", func(t *testing.T) {
		dpopToken := New(*request)
		dpopString, err := dpopToken.Sign(jwkKey)
		require.NoError(t, err)

		token, err := Parse(dpopString)
		require.NoError(t, err)

		assert.Equal(t, pkey, token.Headers.JWK())
		assert.Equal(t, "GET", token.HTM())
		assert.Equal(t, "https://server.example.com/token", token.HTU())
	})
	t.Run("invalid jwt", func(t *testing.T) {
		_, err := Parse("invalid")

		require.Error(t, err)
		assert.EqualError(t, err, "invalid DPoP token\ninvalid compact serialization format: invalid number of segments")
	})
	t.Run("unsupported algorithm", func(t *testing.T) {
		customJwt := jwt.New()
		sig, _ := jwt.Sign(customJwt, jwt.WithInsecureNoSignature())
		tokenString := string(sig)

		_, err := Parse(tokenString)

		require.Error(t, err)
		assert.EqualError(t, err, "invalid DPoP token: invalid alg: none")
	})
	t.Run("invalid type", func(t *testing.T) {
		dpopToken := New(*request)
		dpopToken.Headers.Set(jws.TypeKey, "JWT")
		dpopString, _ := dpopToken.Sign(jwkKey)

		_, err := Parse(dpopString)

		require.Error(t, err)
		assert.EqualError(t, err, "invalid DPoP token: invalid type: JWT")
	})
	t.Run("missing jwk", func(t *testing.T) {
		altToken := jwt.New()
		altHeaders := jws.NewHeaders()
		altHeaders.Set(jws.TypeKey, DPopType)

		tokenBytes, _ := jwt.Sign(altToken, jwt.WithKey(jwa.SignatureAlgorithm(jwkKey.Algorithm().String()), jwkKey, jws.WithProtectedHeaders(altHeaders)))

		_, err := Parse(string(tokenBytes))

		require.Error(t, err)
		assert.EqualError(t, err, "invalid DPoP token: missing jwk header")
	})
	t.Run("private key included", func(t *testing.T) {
		altToken := jwt.New()
		altHeaders := jws.NewHeaders()
		altHeaders.Set(jws.TypeKey, DPopType)
		altHeaders.Set(jws.JWKKey, jwkKey)

		tokenBytes, _ := jwt.Sign(altToken, jwt.WithKey(jwa.SignatureAlgorithm(jwkKey.Algorithm().String()), jwkKey, jws.WithProtectedHeaders(altHeaders)))

		_, err := Parse(string(tokenBytes))

		require.Error(t, err)
		assert.EqualError(t, err, "invalid DPoP token: invalid jwk header")
	})
	t.Run("jwt parsing failed due to wrong signature", func(t *testing.T) {
		dpopToken := New(*request)
		dpopString, _ := dpopToken.Sign(jwkKey)

		_, err := Parse(dpopString + "0")

		require.Error(t, err)
		assert.EqualError(t, err, "invalid DPoP token\ncould not verify message using any of the signatures or keys")
	})
	t.Run("missing iat claim", func(t *testing.T) {
		dpopToken := New(*request)
		_ = dpopToken.Token.Remove(jwt.IssuedAtKey)
		dpopString, _ := dpopToken.Sign(jwkKey)

		_, err := Parse(dpopString)

		require.Error(t, err)
		assert.EqualError(t, err, "invalid DPoP token: missing iat claim")

	})
	t.Run("missing htu claim", func(t *testing.T) {
		dpopToken := New(*request)
		_ = dpopToken.Token.Remove(HTUKey)
		dpopString, _ := dpopToken.Sign(jwkKey)

		_, err := Parse(dpopString)

		require.Error(t, err)
		assert.EqualError(t, err, "invalid DPoP token: missing htu claim")
	})
	t.Run("missing htm claim", func(t *testing.T) {
		dpopToken := New(*request)
		_ = dpopToken.Token.Remove(HTMKey)
		dpopString, _ := dpopToken.Sign(jwkKey)

		_, err := Parse(dpopString)

		require.Error(t, err)
		assert.EqualError(t, err, "invalid DPoP token: missing htm claim")
	})
	t.Run("missing jti claim", func(t *testing.T) {
		dpopToken := New(*request)
		_ = dpopToken.Token.Remove(jwt.JwtIDKey)
		dpopString, _ := dpopToken.Sign(jwkKey)

		_, err := Parse(dpopString)

		require.Error(t, err)
		assert.EqualError(t, err, "invalid DPoP token: missing jti claim")
	})
	t.Run("jti claim too long", func(t *testing.T) {
		dpopToken := New(*request)
		bytes := make([]byte, maxJtiLength+1)
		_, _ = rand.Reader.Read(bytes)
		dpopToken.Token.Set(jwt.JwtIDKey, string(bytes))
		dpopString, _ := dpopToken.Sign(jwkKey)

		_, err := Parse(dpopString)

		require.Error(t, err)
		assert.EqualError(t, err, "invalid DPoP token: jti claim too long")
	})
}

func TestDPoP_Match(t *testing.T) {
	accessToken := "token"
	keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.FromRaw(keyPair)
	_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256)
	thumbprint, _ := jwkKey.Thumbprint(crypto.SHA256)
	thumbprintString := base64.RawURLEncoding.EncodeToString(thumbprint)
	request, _ := http.NewRequest("POST", "https://server.example.com/token", nil)

	t.Run("ok", func(t *testing.T) {
		dpopToken := New(*request).GenerateProof(accessToken)
		dpopString, _ := dpopToken.Sign(jwkKey)
		parsedToken, _ := Parse(dpopString)

		ok, err := parsedToken.Match(thumbprintString, "POST", "https://server.example.com/token")

		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("ok with different port", func(t *testing.T) {
		dpopToken := New(*request).GenerateProof(accessToken)
		dpopString, _ := dpopToken.Sign(jwkKey)
		parsedToken, _ := Parse(dpopString)

		ok, err := parsedToken.Match(thumbprintString, "POST", "https://server.example.com:443/token")

		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("ok with different scheme", func(t *testing.T) {
		dpopToken := New(*request).GenerateProof(accessToken)
		dpopString, _ := dpopToken.Sign(jwkKey)
		parsedToken, _ := Parse(dpopString)

		ok, err := parsedToken.Match(thumbprintString, "POST", "http://server.example.com/token")

		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("ok with query/fragment", func(t *testing.T) {
		dpopToken := New(*request).GenerateProof(accessToken)
		dpopString, _ := dpopToken.Sign(jwkKey)
		parsedToken, _ := Parse(dpopString)

		ok, err := parsedToken.Match(thumbprintString, "POST", "https://server.example.com/token?a=b#c")

		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("invalid thumbprint", func(t *testing.T) {
		dpopToken := New(*request).GenerateProof(accessToken)
		dpopString, _ := dpopToken.Sign(jwkKey)
		parsedToken, _ := Parse(dpopString)

		ok, err := parsedToken.Match("jkt", "POST", "https://server.example.com/token")

		require.Error(t, err)
		assert.False(t, ok)
		assert.EqualError(t, err, "jkt mismatch")
	})
	t.Run("invalid method", func(t *testing.T) {
		dpopToken := New(*request).GenerateProof(accessToken)
		dpopString, _ := dpopToken.Sign(jwkKey)
		parsedToken, _ := Parse(dpopString)

		ok, err := parsedToken.Match(thumbprintString, "GET", "https://server.example.com/token")

		require.Error(t, err)
		assert.False(t, ok)
		assert.EqualError(t, err, "method mismatch, token: POST, given: GET")
	})
	t.Run("invalid url", func(t *testing.T) {
		dpopToken := New(*request).GenerateProof(accessToken)
		dpopString, _ := dpopToken.Sign(jwkKey)
		parsedToken, _ := Parse(dpopString)

		ok, err := parsedToken.Match(thumbprintString, "POST", "https://server.example.com/token2")

		require.Error(t, err)
		assert.False(t, ok)
		assert.EqualError(t, err, "url mismatch, token: https://server.example.com/token, given: https://server.example.com/token2")
	})
}

func TestDPoP_marshalling(t *testing.T) {
	keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.FromRaw(keyPair)
	_ = jwkKey.Set(jwk.AlgorithmKey, jwa.ES256)
	request, _ := http.NewRequest("POST", "https://server.example.com/token", nil)

	t.Run("marshal", func(t *testing.T) {
		dpopToken := New(*request).GenerateProof("token")
		dpopString, _ := dpopToken.Sign(jwkKey)

		marshalled, err := dpopToken.MarshalJSON()

		require.NoError(t, err)
		assert.Equal(t, []byte("\""+dpopString+"\""), marshalled)
	})
	t.Run("unmarshal", func(t *testing.T) {
		dpopToken := New(*request).GenerateProof("token")
		dpopString, _ := dpopToken.Sign(jwkKey)

		var token DPoP
		err := token.UnmarshalJSON([]byte("\"" + dpopString + "\""))

		require.NoError(t, err)
		assert.Equal(t, dpopToken.raw, token.raw)
	})
}
