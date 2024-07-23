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
	"context"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/http/user"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

var walletDID = did.MustParseDID("did:web:example.com:iam:123")
var userDID = did.MustParseDID("did:jwk:really-a-jwk")

var sessionCookie = http.Cookie{
	Name:     "__Host-SID",
	Value:    "sessionID",
	Path:     "/",
	Secure:   true,
	HttpOnly: true,
	SameSite: http.SameSiteStrictMode,
}

func TestWrapper_handleUserLanding(t *testing.T) {
	userDetails := UserDetails{
		Id:   "test",
		Name: "John Doe",
		Role: "Caregiver",
	}
	redirectSession := RedirectSession{
		OwnDID: walletDID,
		AccessTokenRequest: RequestUserAccessTokenRequestObject{
			Body: &RequestUserAccessTokenJSONRequestBody{
				Scope:               "first second",
				PreauthorizedUser:   &userDetails,
				AuthorizationServer: "https://example.com/oauth2/did:web:example.com:iam:verifier",
			},
			Did: walletDID.String(),
		},
	}

	// setup did document and keys
	vmId := did.DIDURL{
		DID:             walletDID,
		Fragment:        "key",
		DecodedFragment: "key",
	}
	key, _ := spi.GenerateKeyPair()
	didDocument := did.Document{ID: walletDID}
	vm, _ := did.NewVerificationMethod(vmId, ssi.JsonWebKey2020, did.DID{}, key.Public())
	didDocument.AddAssertionMethod(vm)

	serverMetadata := oauth.AuthorizationServerMetadata{
		AuthorizationEndpoint:      "https://example.com/authorize",
		TokenEndpoint:              "https://example.com/token",
		ClientIdSchemesSupported:   []string{didClientIDScheme},
		VPFormats:                  oauth.DefaultOpenIDSupportedFormats(),
		RequireSignedRequestObject: true,
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newTestClient(t)
		expectedURL := "https://example.com/authorize?client_id=did%3Aweb%3Aexample.com%3Aiam%3A123&request_uri=https://example.com/oauth2/" + webDID.String() + "/request.jwt/&request_uri_method=get"
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		httpRequest := &http.Request{
			Host: "example.com",
		}
		requestCtx, userSession := user.CreateTestSession(context.Background(), walletDID)
		httpRequest = httpRequest.WithContext(requestCtx)
		echoCtx.EXPECT().Request().MinTimes(1).Return(httpRequest)
		echoCtx.EXPECT().Redirect(http.StatusFound, gomock.Any()).DoAndReturn(func(_ int, arg1 string) error {
			testAuthzReqRedirectURI(t, expectedURL, arg1)
			return nil
		})

		var employeeCredentialTemplate vc.VerifiableCredential
		var employeeCredentialOptions issuer.CredentialOptions
		ctx.vcIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, t vc.VerifiableCredential, o issuer.CredentialOptions) (*vc.VerifiableCredential, error) {
			employeeCredentialTemplate = t
			employeeCredentialOptions = o
			return &t, nil
		})
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), verifierURL.String()).Return(&serverMetadata, nil).Times(2)
		ctx.jar.EXPECT().Create(webDID, verifierURL.String(), gomock.Any()).DoAndReturn(func(client did.DID, authServerURL string, modifier requestObjectModifier) jarRequest {
			req := createJarRequest(client, authServerURL, modifier)
			params := req.Claims

			// check the parameters
			assert.Equal(t, "first second", params["scope"])
			assert.NotEmpty(t, params["state"])
			return req
		})

		store := ctx.client.userRedirectStore()
		err := store.Put("token", redirectSession)
		require.NoError(t, err)

		err = ctx.client.handleUserLanding(echoCtx)
		require.NoError(t, err)
		// check for issued EmployeeCredential in session wallet
		require.NoError(t, err)
		assert.Equal(t, walletDID, userSession.SubjectID)
		require.Len(t, userSession.Wallet.Credentials, 1)
		// check the JWK can be parsed and contains a private key
		sessionKey, err := jwk.ParseKey(userSession.Wallet.JWK)
		require.NoError(t, err)
		assert.NotEmpty(t, sessionKey.KeyID)
		assert.Equal(t, jwa.EC, sessionKey.KeyType())
		// check for details of issued EmployeeCredential
		assert.Equal(t, "EmployeeCredential", employeeCredentialTemplate.Type[0].String())
		employeeCredentialSubject := employeeCredentialTemplate.CredentialSubject[0].(map[string]string)
		assert.True(t, strings.HasPrefix(employeeCredentialSubject["id"], "did:jwk:"))
		assert.Equal(t, userDetails.Id, employeeCredentialSubject["identifier"])
		assert.Equal(t, userDetails.Name, employeeCredentialSubject["name"])
		assert.Equal(t, userDetails.Role, employeeCredentialSubject["roleName"])
		// check issuance options
		assert.False(t, employeeCredentialOptions.Public)
		assert.False(t, employeeCredentialOptions.Publish)
		assert.False(t, employeeCredentialOptions.WithStatusListRevocation)
		assert.Equal(t, vc.JWTCredentialProofFormat, employeeCredentialOptions.Format)

		// check for deleted token
		err = store.Get("token", &RedirectSession{})
		assert.Error(t, err)
	})
	t.Run("error - no token", func(t *testing.T) {
		ctx := newTestClient(t)
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("")
		echoCtx.EXPECT().NoContent(http.StatusForbidden)

		err := ctx.client.handleUserLanding(echoCtx)

		assert.NoError(t, err)
	})
	t.Run("error - token not found", func(t *testing.T) {
		ctx := newTestClient(t)
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		echoCtx.EXPECT().NoContent(http.StatusForbidden)

		err := ctx.client.handleUserLanding(echoCtx)

		assert.NoError(t, err)
	})
	t.Run("error - authorization request error", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vcIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, t vc.VerifiableCredential, _ issuer.CredentialOptions) (*vc.VerifiableCredential, error) {
			// just return whatever template was given to avoid nil deref
			return &t, nil
		})
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		httpRequest := &http.Request{
			Host: "example.com",
		}
		requestCtx, _ := user.CreateTestSession(context.Background(), walletDID)
		httpRequest = httpRequest.WithContext(requestCtx)
		echoCtx.EXPECT().Request().MinTimes(1).Return(httpRequest)
		store := ctx.client.storageEngine.GetSessionDatabase().GetStore(time.Second*5, "user", "redirect")
		err := store.Put("token", redirectSession)
		require.NoError(t, err)
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), verifierURL.String()).Return(nil, assert.AnError)

		err = ctx.client.handleUserLanding(echoCtx)

		assert.ErrorIs(t, err, assert.AnError)
		// token has been burned
		assert.ErrorIs(t, store.Get("token", new(RedirectSession)), storage.ErrNotFound)
	})
	httpRequest := &http.Request{Host: "example.com"}
	session, _ := user.CreateTestSession(audit.TestContext(), walletDID)
	httpRequest = httpRequest.WithContext(session)
	t.Run("error - missing authorization_endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		ctx.vcIssuer.EXPECT().Issue(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, t vc.VerifiableCredential, _ issuer.CredentialOptions) (*vc.VerifiableCredential, error) {
			// just return whatever template was given to avoid nil deref
			return &t, nil
		})
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		echoCtx.EXPECT().Request().MinTimes(1).Return(httpRequest)
		require.NoError(t, ctx.client.userRedirectStore().Put("token", redirectSession))
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), verifierURL.String()).Return(&oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint: "",
			TokenEndpoint:         "",
		}, nil)

		err := ctx.client.handleUserLanding(echoCtx)

		assert.EqualError(t, err, "no authorization_endpoint found for https://example.com/oauth2/did:web:example.com:iam:verifier")
		// token has been burned
		assert.ErrorIs(t, ctx.client.userRedirectStore().Get("token", new(RedirectSession)), storage.ErrNotFound)
	})
	t.Run("error - missing authorization_endpoint", func(t *testing.T) {
		ctx := newTestClient(t)
		echoCtx := mock.NewMockContext(ctx.ctrl)
		echoCtx.EXPECT().QueryParam("token").Return("token")
		echoCtx.EXPECT().Request().MinTimes(1).Return(httpRequest)
		require.NoError(t, ctx.client.userRedirectStore().Put("token", redirectSession))
		ctx.iamClient.EXPECT().AuthorizationServerMetadata(gomock.Any(), verifierURL.String()).Return(&oauth.AuthorizationServerMetadata{
			AuthorizationEndpoint: "https://example.com/authorize",
			TokenEndpoint:         "",
		}, nil)

		err := ctx.client.handleUserLanding(echoCtx)

		assert.EqualError(t, err, "no token_endpoint found for https://example.com/oauth2/did:web:example.com:iam:verifier")
		// token has been burned
		assert.ErrorIs(t, ctx.client.userRedirectStore().Get("token", new(RedirectSession)), storage.ErrNotFound)
	})
}
