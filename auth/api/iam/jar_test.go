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

package iam

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/test"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth"
	"github.com/nuts-foundation/nuts-node/auth/client/iam"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	cryptoNuts "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestJar_Create(t *testing.T) {
	t.Run("request_uri_method=get", func(t *testing.T) {
		modifier := func(claims map[string]string) {
			claims["requestObjectModifier"] = "works"
		}
		req := jar{}.Create(verifierDID, holderURL, modifier)
		assert.Equal(t, "get", req.RequestURIMethod)
		assert.Equal(t, verifierDID, req.Client)
		assert.Len(t, req.Claims, 4)
		assert.Equal(t, verifierDID.String(), req.Claims[oauth.ClientIDParam])
		assert.Equal(t, verifierDID.String(), req.Claims[jwt.IssuerKey])
		assert.Equal(t, holderURL, req.Claims[jwt.AudienceKey])
		assert.Equal(t, "works", req.Claims["requestObjectModifier"])
	})
	t.Run("request_uri_method=post", func(t *testing.T) {
		modifier := func(claims map[string]string) {
			claims[jwt.IssuerKey] = holderDID.String()
		}
		req := jar{}.Create(verifierDID, "", modifier)
		assert.Equal(t, "post", req.RequestURIMethod)
		assert.Equal(t, verifierDID, req.Client)
		assert.Len(t, req.Claims, 2)
		assert.Equal(t, holderDID.String(), req.Claims[jwt.IssuerKey])
		assert.Equal(t, verifierDID.String(), req.Claims[oauth.ClientIDParam])
		assert.Empty(t, req.Claims[jwt.AudienceKey])
	})
}
func TestJar_Sign(t *testing.T) {
	clientDID := did.MustParseDID("did:web:example.com:iam:client")
	claims := oauthParameters{oauth.ClientIDParam: clientDID.String()}
	keyID := ssi.MustParseURI("this-key")
	t.Run("ok", func(t *testing.T) {
		ctx := newJarTestCtx(t)
		ctx.keyResolver.EXPECT().ResolveKey(clientDID, nil, resolver.AssertionMethod).Return(keyID, nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(context.Background(), claims, nil, keyID.String()).Return("valid token", nil)

		token, err := ctx.jar.Sign(context.Background(), claims)

		require.NoError(t, err)
		assert.Equal(t, "valid token", token)
	})
	t.Run("error - failed to sign JWT", func(t *testing.T) {
		ctx := newJarTestCtx(t)
		ctx.keyResolver.EXPECT().ResolveKey(clientDID, nil, resolver.NutsSigningKeyType).Return(keyID, nil, nil)
		ctx.jwtSigner.EXPECT().SignJWT(gomock.Any(), gomock.Any(), nil, gomock.Any()).Return("", assert.AnError)

		token, err := ctx.jar.Sign(context.Background(), claims)

		assert.ErrorIs(t, err, assert.AnError)
		assert.Empty(t, token)
	})
	t.Run("error - failed to resolve key", func(t *testing.T) {
		ctx := newJarTestCtx(t)
		ctx.keyResolver.EXPECT().ResolveKey(clientDID, nil, resolver.NutsSigningKeyType).Return(keyID, nil, resolver.ErrKeyNotFound)

		token, err := ctx.jar.Sign(context.Background(), claims)

		assert.ErrorIs(t, err, resolver.ErrKeyNotFound)
		assert.Empty(t, token)
	})
}

func TestJar_Parse(t *testing.T) {
	// setup did document and keys
	privateKey, _ := spi.GenerateKeyPair()
	kid := fmt.Sprintf("%s#%s", holderDID.String(), "key")

	bytes, err := createSignedRequestObject(t, kid, privateKey, oauthParameters{
		jwt.IssuerKey:       holderDID.String(),
		oauth.ClientIDParam: holderDID.String(),
	})
	require.NoError(t, err)
	token := string(bytes)
	walletIssuerURL := test.MustParseURL(walletDID.String())
	ctx := newJarTestCtx(t)
	t.Run("request_uri_method", func(t *testing.T) {

		t.Run("ok - get", func(t *testing.T) {
			ctx.iamClient.EXPECT().RequestObjectByGet(context.Background(), "request_uri").Return(token, nil)
			ctx.keyResolver.EXPECT().ResolveKeyByID(kid, nil, resolver.AssertionMethod).Return(privateKey.Public(), nil)

			res, err := ctx.jar.Parse(context.Background(), verifierDID,
				map[string][]string{
					oauth.ClientIDParam:         {holderDID.String()},
					oauth.RequestURIParam:       {"request_uri"},
					oauth.RequestURIMethodParam: {"get"},
				})

			assert.NoError(t, err)
			require.NotNil(t, res)
		})
		t.Run("ok - param not supported", func(t *testing.T) {
			ctx.iamClient.EXPECT().RequestObjectByGet(context.Background(), "request_uri").Return(token, nil)
			ctx.keyResolver.EXPECT().ResolveKeyByID(kid, nil, resolver.AssertionMethod).Return(privateKey.Public(), nil)

			res, err := ctx.jar.Parse(context.Background(), verifierDID,
				map[string][]string{
					oauth.ClientIDParam:         {holderDID.String()},
					oauth.RequestURIParam:       {"request_uri"},
					oauth.RequestURIMethodParam: {""},
				})

			assert.NoError(t, err)
			require.NotNil(t, res)
		})
		t.Run("ok - post", func(t *testing.T) {
			md, _ := authorizationServerMetadata(walletDID, walletIssuerURL)
			ctx.iamClient.EXPECT().RequestObjectByPost(context.Background(), "request_uri", *md).Return(token, nil)
			ctx.keyResolver.EXPECT().ResolveKeyByID(kid, nil, resolver.AssertionMethod).Return(privateKey.Public(), nil)

			res, err := ctx.jar.Parse(context.Background(), walletDID,
				map[string][]string{
					oauth.ClientIDParam:         {holderDID.String()},
					oauth.RequestURIParam:       {"request_uri"},
					oauth.RequestURIMethodParam: {"post"},
				})

			assert.NoError(t, err)
			require.NotNil(t, res)
		})
		t.Run("error - unsupported method", func(t *testing.T) {
			res, err := ctx.jar.Parse(context.Background(), verifierDID,
				map[string][]string{
					oauth.ClientIDParam:         {holderDID.String()},
					oauth.RequestURIParam:       {"request_uri"},
					oauth.RequestURIMethodParam: {"invalid"},
				})

			assert.EqualError(t, err, "invalid_request_uri_method - unsupported request_uri_method")
			assert.Nil(t, res)
		})
	})
	t.Run("ok - 'request'", func(t *testing.T) {
		ctx.keyResolver.EXPECT().ResolveKeyByID(kid, nil, resolver.AssertionMethod).Return(privateKey.Public(), nil)

		res, err := ctx.jar.Parse(context.Background(), verifierDID,
			map[string][]string{
				oauth.ClientIDParam: {holderDID.String()},
				oauth.RequestParam:  {token},
			})

		assert.NoError(t, err)
		require.NotNil(t, res)
	})
	t.Run("server error", func(t *testing.T) {
		t.Run("get", func(t *testing.T) {
			ctx.iamClient.EXPECT().RequestObjectByGet(context.Background(), "request_uri").Return("", errors.New("server error"))
			res, err := ctx.jar.Parse(context.Background(), verifierDID,
				map[string][]string{
					oauth.RequestURIParam: {"request_uri"},
				})

			requireOAuthError(t, err, oauth.InvalidRequestURI, "failed to get Request Object")
			assert.Nil(t, res)
		})
		t.Run("post (made by wallet)", func(t *testing.T) {
			md, _ := authorizationServerMetadata(walletDID, walletIssuerURL)
			ctx.iamClient.EXPECT().RequestObjectByPost(context.Background(), "request_uri", *md).Return("", errors.New("server error"))
			res, err := ctx.jar.Parse(context.Background(), walletDID,
				map[string][]string{
					oauth.RequestURIParam:       {"request_uri"},
					oauth.RequestURIMethodParam: {"post"},
				})

			requireOAuthError(t, err, oauth.InvalidRequestURI, "failed to get Request Object")
			assert.Nil(t, res)
		})
	})
	t.Run("error - both 'request' and 'request_uri'", func(t *testing.T) {
		res, err := ctx.jar.Parse(context.Background(), verifierDID,
			map[string][]string{
				oauth.RequestParam:    {"request"},
				oauth.RequestURIParam: {"request_uri"},
			})

		requireOAuthError(t, err, oauth.InvalidRequest, "claims 'request' and 'request_uri' are mutually exclusive")
		assert.Nil(t, res)
	})
	t.Run("error - no 'request' or 'request_uri'", func(t *testing.T) {
		res, err := ctx.jar.Parse(context.Background(), verifierDID, map[string][]string{})

		requireOAuthError(t, err, oauth.InvalidRequest, "authorization request are required to use signed request objects (RFC9101)")
		assert.Nil(t, res)
	})
	t.Run("error - request signature validation failed", func(t *testing.T) {
		res, err := ctx.jar.Parse(context.Background(), verifierDID,
			map[string][]string{
				oauth.ClientIDParam: {"invalid"},
				oauth.RequestParam:  {"invalid"},
			})

		requireOAuthError(t, err, oauth.InvalidRequestObject, "request signature validation failed")
		assert.Nil(t, res)
	})
	t.Run("error - client_id does not match", func(t *testing.T) {
		ctx.keyResolver.EXPECT().ResolveKeyByID(kid, nil, resolver.AssertionMethod).Return(privateKey.Public(), nil)

		res, err := ctx.jar.Parse(context.Background(), verifierDID,
			map[string][]string{
				oauth.ClientIDParam: {"invalid"},
				oauth.RequestParam:  {token},
			})

		requireOAuthError(t, err, oauth.InvalidRequestObject, "invalid client_id claim in signed authorization request")
		assert.Nil(t, res)
	})
	t.Run("error - client_id does not match signer", func(t *testing.T) {
		bytes, err := createSignedRequestObject(t, kid, privateKey, oauthParameters{
			jwt.IssuerKey:       verifierDID.String(),
			oauth.ClientIDParam: verifierDID.String(),
		})
		require.NoError(t, err)
		ctx.keyResolver.EXPECT().ResolveKeyByID(kid, nil, resolver.AssertionMethod).Return(privateKey.Public(), nil)

		res, err := ctx.jar.Parse(context.Background(), verifierDID,
			map[string][]string{
				oauth.ClientIDParam: {verifierDID.String()},
				oauth.RequestParam:  {string(bytes)},
			})

		requireOAuthError(t, err, oauth.InvalidRequestObject, "client_id does not match signer of authorization request")
		assert.Nil(t, res)
	})
}

func createSignedRequestObject(t testing.TB, kid string, privateKey crypto.PrivateKey, params oauthParameters) ([]byte, error) {
	request := jwt.New()
	for k, v := range params {
		require.NoError(t, request.Set(k, v))
	}
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.KeyIDKey, kid))
	return jwt.Sign(request, jwt.WithKey(jwa.ES256, privateKey, jws.WithProtectedHeaders(headers)))
}

type testJarCtx struct {
	jar         JAR
	auth        *auth.MockAuthenticationServices
	iamClient   *iam.MockClient
	jwtSigner   *cryptoNuts.MockJWTSigner
	keyResolver *resolver.MockKeyResolver
}

func newJarTestCtx(t testing.TB) testJarCtx {
	ctrl := gomock.NewController(t)
	mockIAMClient := iam.NewMockClient(ctrl)
	mockAuth := auth.NewMockAuthenticationServices(ctrl)
	mockAuth.EXPECT().IAMClient().Return(mockIAMClient).AnyTimes()
	mockSigner := cryptoNuts.NewMockJWTSigner(ctrl)
	mockResolver := resolver.NewMockKeyResolver(ctrl)
	return testJarCtx{
		jar: &jar{
			auth:        mockAuth,
			jwtSigner:   mockSigner,
			keyResolver: mockResolver,
		},
		auth:        mockAuth,
		iamClient:   mockIAMClient,
		keyResolver: mockResolver,
		jwtSigner:   mockSigner,
	}
}
