/*
 * Nuts node
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
 */

package iam

import (
	crypto2 "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_dpopFromRequest(t *testing.T) {
	t.Run("without DPoP header", func(t *testing.T) {
		httpRequest, _ := http.NewRequest("POST", "https://server.example.com/token", nil)

		resp, err := dpopFromRequest(*httpRequest)

		require.NoError(t, err)
		assert.Nil(t, resp)
	})
	t.Run("invalid DPoP header", func(t *testing.T) {
		httpRequest, _ := http.NewRequest("POST", "https://server.example.com/token", nil)
		httpRequest.Header.Set("DPoP", "invalid")

		_, err := dpopFromRequest(*httpRequest)

		require.Error(t, err)
		_ = assertOAuthErrorWithCode(t, err, oauth.InvalidDPopProof, "DPoP header is invalid")
	})
}

func newTestDPoP() *dpop.DPoP {
	httpRequest, _ := http.NewRequest("POST", "https://server.example.com/token", nil)
	return dpop.New(*httpRequest)
}

func newSignedTestDPoP() (*dpop.DPoP, *dpop.DPoP, string) {
	dpopToken := newTestDPoP()
	withProof := newTestDPoP()
	keyPair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwkKey, _ := jwk.FromRaw(keyPair)
	jwkKey.Set(jwk.AlgorithmKey, jwa.ES256)
	_ = withProof.GenerateProof("token")
	_, _ = withProof.Sign(jwkKey)
	_, _ = dpopToken.Sign(jwkKey)
	thumbprintBytes, _ := dpopToken.Headers.JWK().Thumbprint(crypto2.SHA256)
	thumbprint := base64.RawURLEncoding.EncodeToString(thumbprintBytes)
	return dpopToken, withProof, thumbprint
}
