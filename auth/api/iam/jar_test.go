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
	"errors"
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
		req := jar{}.Create(verifierDID, &holderDID, modifier)
		assert.Equal(t, "get", req.RequestURIMethod)
		assert.Equal(t, verifierDID, req.Client)
		assert.Len(t, req.Claims, 5)
		assert.Equal(t, req.Claims[oauth.ClientIDParam], verifierDID.String())
		assert.Equal(t, req.Claims[jwt.IssuerKey], verifierDID.String())
		assert.Equal(t, req.Claims[jwt.AudienceKey], holderDID.String())
		assert.Equal(t, req.Claims["requestObjectModifier"], "works")
		assert.NotEmpty(t, req.Claims[oauth.NonceParam])
	})
	t.Run("request_uri_method=post", func(t *testing.T) {
		modifier := func(claims map[string]string) {
			claims[jwt.IssuerKey] = holderDID.String()
		}
		req := jar{}.Create(verifierDID, nil, modifier)
		assert.Equal(t, "post", req.RequestURIMethod)
		assert.Equal(t, verifierDID, req.Client)
		assert.Len(t, req.Claims, 3)
		assert.Equal(t, req.Claims[jwt.IssuerKey], holderDID.String())
		assert.Equal(t, req.Claims[oauth.ClientIDParam], verifierDID.String())
		assert.Empty(t, req.Claims[jwt.AudienceKey])
		assert.NotEmpty(t, req.Claims[oauth.NonceParam])
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
	key := cryptoNuts.NewTestKey(did.DIDURL{DID: holderDID, Fragment: "key"}.String())

	bytes, err := createSignedRequestObject(t, key, oauthParameters{
		jwt.IssuerKey:       holderDID.String(),
		oauth.ClientIDParam: holderDID.String(),
	})
	require.NoError(t, err)
	token := string(bytes)
	ctx := newJarTestCtx(t)
	t.Run("ok - 'request_uri'", func(t *testing.T) {
		ctx.iamClient.EXPECT().RequestObject(context.Background(), "request_uri").Return(token, nil)
		ctx.keyResolver.EXPECT().ResolveKeyByID(key.KID(), nil, resolver.AssertionMethod).Return(key.Public(), nil)

		res, err := ctx.jar.Parse(context.Background(), verifierDID,
			map[string][]string{
				oauth.ClientIDParam:   {holderDID.String()},
				oauth.RequestURIParam: {"request_uri"},
			})

		assert.NoError(t, err)
		require.NotNil(t, res)
	})
	t.Run("ok - 'request'", func(t *testing.T) {
		ctx.keyResolver.EXPECT().ResolveKeyByID(key.KID(), nil, resolver.AssertionMethod).Return(key.Public(), nil)

		res, err := ctx.jar.Parse(context.Background(), verifierDID,
			map[string][]string{
				oauth.ClientIDParam: {holderDID.String()},
				oauth.RequestParam:  {token},
			})

		assert.NoError(t, err)
		require.NotNil(t, res)
	})
	t.Run("error - server error", func(t *testing.T) {
		ctx.iamClient.EXPECT().RequestObject(context.Background(), "request_uri").Return("", errors.New("server error"))
		res, err := ctx.jar.Parse(context.Background(), verifierDID,
			map[string][]string{
				oauth.RequestURIParam: {"request_uri"},
			})

		requireOAuthError(t, err, oauth.InvalidRequestURI, "failed to get Request Object")
		assert.Nil(t, res)
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
		ctx.keyResolver.EXPECT().ResolveKeyByID(key.KID(), nil, resolver.AssertionMethod).Return(key.Public(), nil)

		res, err := ctx.jar.Parse(context.Background(), verifierDID,
			map[string][]string{
				oauth.ClientIDParam: {"invalid"},
				oauth.RequestParam:  {token},
			})

		requireOAuthError(t, err, oauth.InvalidRequestObject, "invalid client_id claim in signed authorization request")
		assert.Nil(t, res)
	})
	t.Run("error - client_id does not match signer", func(t *testing.T) {
		bytes, err := createSignedRequestObject(t, key, oauthParameters{
			jwt.IssuerKey:       verifierDID.String(),
			oauth.ClientIDParam: verifierDID.String(),
		})
		require.NoError(t, err)
		ctx.keyResolver.EXPECT().ResolveKeyByID(key.KID(), nil, resolver.AssertionMethod).Return(key.Public(), nil)

		res, err := ctx.jar.Parse(context.Background(), verifierDID,
			map[string][]string{
				oauth.ClientIDParam: {verifierDID.String()},
				oauth.RequestParam:  {string(bytes)},
			})

		requireOAuthError(t, err, oauth.InvalidRequestObject, "client_id does not match signer of authorization request")
		assert.Nil(t, res)
	})
}

func createSignedRequestObject(t testing.TB, testKey *cryptoNuts.TestKey, params oauthParameters) ([]byte, error) {
	request := jwt.New()
	for k, v := range params {
		require.NoError(t, request.Set(k, v))
	}
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.KeyIDKey, testKey.KID()))
	return jwt.Sign(request, jwt.WithKey(jwa.ES256, testKey.Private(), jws.WithProtectedHeaders(headers)))
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