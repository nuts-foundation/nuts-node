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

package iam

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestWrapper_RequestAccessToken(t *testing.T) {
	walletDID := did.MustParseDID("did:test:123")
	verifierDID := did.MustParseDID("did:test:456")
	body := &RequestAccessTokenJSONRequestBody{Verifier: verifierDID.String()}

	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)
		ctx.resolver.EXPECT().Resolve(verifierDID, nil).Return(&did.Document{}, &resolver.DocumentMetadata{}, nil)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.NoError(t, err)
	})
	t.Run("error - DID not owned", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(false, nil)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.ErrorContains(t, err, "not owned by this node")
	})
	t.Run("error - invalid DID", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: "invalid", Body: body})

		require.EqualError(t, err, "did not found: invalid DID")
	})
	t.Run("missing request body", func(t *testing.T) {
		ctx := newTestClient(t)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: walletDID.String()})

		require.Error(t, err)
		assert.EqualError(t, err, "missing request body")
	})
	t.Run("invalid verifier did", func(t *testing.T) {
		ctx := newTestClient(t)
		body := &RequestAccessTokenJSONRequestBody{Verifier: "invalid"}
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.EqualError(t, err, "invalid verifier: invalid DID")
	})
	t.Run("verifier not found", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vdr.EXPECT().IsOwner(nil, walletDID).Return(true, nil)
		ctx.resolver.EXPECT().Resolve(verifierDID, nil).Return(nil, nil, resolver.ErrNotFound)

		_, err := ctx.client.RequestAccessToken(nil, RequestAccessTokenRequestObject{Did: walletDID.String(), Body: body})

		require.Error(t, err)
		assert.EqualError(t, err, "verifier not found: unable to find the DID document")
	})
}

func TestWrapper_createAccessToken(t *testing.T) {
	credential, err := vc.ParseVerifiableCredential(jsonld.TestOrganizationCredential)
	require.NoError(t, err)
	presentation := vc.VerifiablePresentation{
		VerifiableCredential: []vc.VerifiableCredential{*credential},
	}
	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)

		accessToken, err := ctx.client.createAccessToken(issuerDID, time.Now(), presentation, "everything")

		require.NoError(t, err)
		assert.NotEmpty(t, accessToken.AccessToken)
		assert.Equal(t, "bearer", accessToken.TokenType)
		assert.Equal(t, 900, *accessToken.ExpiresIn)
		assert.Equal(t, "everything", *accessToken.Scope)

		var storedToken AccessToken
		err = ctx.client.accessTokenStore(issuerDID).Get(accessToken.AccessToken, &storedToken)
		require.NoError(t, err)
		assert.Equal(t, accessToken.AccessToken, storedToken.Token)
		expectedVPJSON, _ := presentation.MarshalJSON()
		actualVPJSON, _ := storedToken.Presentation.MarshalJSON()
		assert.JSONEq(t, string(expectedVPJSON), string(actualVPJSON))
		assert.Equal(t, issuerDID.String(), storedToken.Issuer)
		assert.NotEmpty(t, storedToken.Expiration)
	})
}
