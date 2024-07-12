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
	"context"
	crypto2 "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	cryptoNuts "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/dpop"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestWrapper_CreateDPoPProof(t *testing.T) {
	accesstoken := "token"
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://example.com", nil)
	requestBody := CreateDPoPProofJSONRequestBody{
		Htm:   "GET",
		Token: accesstoken,
		Htu:   "https://example.com",
	}
	requestObject := CreateDPoPProofRequestObject{
		Body: &requestBody,
		Did:  webDID.String(),
	}
	didDocument := did.Document{ID: holderDID}
	vmId := did.MustParseDIDURL(webDID.String() + "#key1")
	key := cryptoNuts.NewTestKey(vmId.String())
	vm, _ := did.NewVerificationMethod(vmId, ssi.JsonWebKey2020, webDID, key.Public())
	didDocument.AddAssertionMethod(vm)
	dpopToken := dpop.New(*request)
	dpopToken.GenerateProof(accesstoken)
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.documentOwner.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)
		ctx.resolver.EXPECT().Resolve(webDID, gomock.Any()).Return(&didDocument, nil, nil)
		ctx.jwtSigner.EXPECT().SignDPoP(gomock.Any(), gomock.Any(), vmId.String()).DoAndReturn(func(_ context.Context, token dpop.DPoP, _ string) (string, error) {
			assert.Equal(t, dpopToken.String(), token.String())
			return "dpop", nil
		})

		res, err := ctx.client.CreateDPoPProof(context.Background(), requestObject)

		require.NoError(t, err)
		assert.Equal(t, "dpop", res.(CreateDPoPProof200JSONResponse).Dpop)
	})
	t.Run("missing method", func(t *testing.T) {
		ctx := newTestClient(t)
		requestBody.Htm = ""
		defer (func() { requestBody.Htm = "GET" })()

		_, err := ctx.client.CreateDPoPProof(context.Background(), requestObject)

		assert.EqualError(t, err, "missing method")
	})
	t.Run("invalid method", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.documentOwner.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)
		requestBody.Htm = "\\"
		defer (func() { requestBody.Htm = "GET" })()

		_, err := ctx.client.CreateDPoPProof(context.Background(), requestObject)

		assert.EqualError(t, err, "net/http: invalid method \"\\\\\"")
	})
	t.Run("missing token", func(t *testing.T) {
		ctx := newTestClient(t)
		requestBody.Token = ""
		defer (func() { requestBody.Token = accesstoken })()

		_, err := ctx.client.CreateDPoPProof(context.Background(), requestObject)

		assert.EqualError(t, err, "missing token")
	})
	t.Run("missing url", func(t *testing.T) {
		ctx := newTestClient(t)
		requestBody.Htu = ""
		defer (func() { requestBody.Htu = "https://example.com" })()

		_, err := ctx.client.CreateDPoPProof(context.Background(), requestObject)

		assert.EqualError(t, err, "missing url")
	})
	t.Run("did not owned", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.documentOwner.EXPECT().IsOwner(gomock.Any(), webDID).Return(false, nil)

		_, err := ctx.client.CreateDPoPProof(context.Background(), requestObject)

		assert.EqualError(t, err, "DID document not managed by this node")
	})
	t.Run("proof error", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.documentOwner.EXPECT().IsOwner(gomock.Any(), webDID).Return(true, nil)
		ctx.resolver.EXPECT().Resolve(webDID, gomock.Any()).Return(&didDocument, nil, nil)
		ctx.jwtSigner.EXPECT().SignDPoP(gomock.Any(), gomock.Any(), vmId.String()).Return("dpop", assert.AnError)

		_, err := ctx.client.CreateDPoPProof(context.Background(), requestObject)

		assert.Equal(t, assert.AnError, err)
	})
}

func TestWrapper_ValidateDPoPProof(t *testing.T) {
	accessToken := "token"
	dpopToken, dpopProof, thumbprint := newSignedTestDPoP()
	request := ValidateDPoPProofRequestObject{
		Body: &ValidateDPoPProofJSONRequestBody{
			DpopProof:  dpopProof.String(),
			Method:     "POST",
			Thumbprint: thumbprint,
			Token:      accessToken,
			Url:        "https://server.example.com/token",
		},
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)

		resp, err := ctx.client.ValidateDPoPProof(nil, request)

		require.NoError(t, err)
		require.IsType(t, ValidateDPoPProof200JSONResponse{}, resp)
		assert.True(t, resp.(ValidateDPoPProof200JSONResponse).Valid)
	})
	t.Run("no match", func(t *testing.T) {
		ctx := newTestClient(t)
		request.Body.Method = "GET"
		defer (func() { request.Body.Method = "POST" })()

		resp, err := ctx.client.ValidateDPoPProof(nil, request)

		require.NoError(t, err)
		require.IsType(t, ValidateDPoPProof200JSONResponse{}, resp)
		assert.False(t, resp.(ValidateDPoPProof200JSONResponse).Valid)
		assert.Equal(t, "method mismatch, token: POST, given: GET", *resp.(ValidateDPoPProof200JSONResponse).Reason)
	})
	t.Run("missing ath header", func(t *testing.T) {
		ctx := newTestClient(t)
		request.Body.DpopProof = dpopToken.String()
		defer (func() { request.Body.DpopProof = dpopProof.String() })()

		resp, err := ctx.client.ValidateDPoPProof(nil, request)

		require.NoError(t, err)
		require.IsType(t, ValidateDPoPProof200JSONResponse{}, resp)
		assert.False(t, resp.(ValidateDPoPProof200JSONResponse).Valid)
		assert.Equal(t, "missing ath claim", *resp.(ValidateDPoPProof200JSONResponse).Reason)
	})
	t.Run("parsing failed", func(t *testing.T) {
		ctx := newTestClient(t)
		request.Body.DpopProof = "invalid"
		defer (func() { request.Body.DpopProof = dpopProof.String() })()

		resp, err := ctx.client.ValidateDPoPProof(nil, request)

		require.NoError(t, err)
		require.IsType(t, ValidateDPoPProof200JSONResponse{}, resp)
		assert.False(t, resp.(ValidateDPoPProof200JSONResponse).Valid)
		assert.Equal(t, "failed to parse DPoP header: invalid DPoP token\ninvalid compact serialization format: invalid number of segments", *resp.(ValidateDPoPProof200JSONResponse).Reason)
	})
	t.Run("invalid accestoken", func(t *testing.T) {
		ctx := newTestClient(t)
		request.Body.Token = "invalid"
		defer (func() { request.Body.Token = accessToken })()

		resp, err := ctx.client.ValidateDPoPProof(nil, request)

		require.NoError(t, err)
		require.IsType(t, ValidateDPoPProof200JSONResponse{}, resp)
		assert.False(t, resp.(ValidateDPoPProof200JSONResponse).Valid)
		assert.Equal(t, "ath/token claim mismatch", *resp.(ValidateDPoPProof200JSONResponse).Reason)
	})
	t.Run("already used once", func(t *testing.T) {
		ctx := newTestClient(t)
		_ = ctx.client.useNonceOnceStore().Put(dpopProof.Token.JwtID(), struct{}{})

		resp, err := ctx.client.ValidateDPoPProof(nil, request)

		require.NoError(t, err)
		require.IsType(t, ValidateDPoPProof200JSONResponse{}, resp)
		assert.False(t, resp.(ValidateDPoPProof200JSONResponse).Valid)
		assert.Equal(t, "jti already used", *resp.(ValidateDPoPProof200JSONResponse).Reason)
	})
}

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
	_ = withProof.GenerateProof("token")
	_, _ = withProof.Sign(keyPair, jwa.ES256)
	_, _ = dpopToken.Sign(keyPair, jwa.ES256)
	thumbprintBytes, _ := dpopToken.Headers.JWK().Thumbprint(crypto2.SHA256)
	thumbprint := base64.RawURLEncoding.EncodeToString(thumbprintBytes)
	return dpopToken, withProof, thumbprint
}
