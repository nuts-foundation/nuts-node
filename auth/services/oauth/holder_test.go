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

package oauth

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	vcr "github.com/nuts-foundation/nuts-node/vcr/api/vcr/v2"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestHolderService_ClientMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createOAuthHolderContext(t)
		endpoint := fmt.Sprintf("%s/.well-known/oauth-authorization-server", ctx.tlsServer.URL)

		clientMetadata, err := ctx.holder.ClientMetadata(ctx.audit, endpoint)

		require.NoError(t, err)
		assert.NotNil(t, clientMetadata)
	})
	t.Run("error", func(t *testing.T) {
		ctx := createOAuthHolderContext(t)
		endpoint := fmt.Sprintf("%s/.well-known/oauth-authorization-server", ctx.tlsServer.URL)
		ctx.metadata = nil

		clientMetadata, err := ctx.holder.ClientMetadata(ctx.audit, endpoint)

		assert.Error(t, err)
		assert.Nil(t, clientMetadata)
	})
}

func TestHolderService_PostError(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createOAuthHolderContext(t)
		endpoint := fmt.Sprintf("%s/error", ctx.tlsServer.URL)
		oauthError := oauth.OAuth2Error{
			Code:        oauth.InvalidRequest,
			Description: "missing required parameter",
		}

		redirect, err := ctx.holder.PostError(ctx.audit, oauthError, endpoint, "state")

		require.NoError(t, err)
		assert.Equal(t, "redirect", redirect)
	})
	t.Run("error", func(t *testing.T) {
		ctx := createOAuthHolderContext(t)
		endpoint := fmt.Sprintf("%s/error", ctx.tlsServer.URL)
		ctx.errorResponse = nil

		redirect, err := ctx.holder.PostError(ctx.audit, oauth.OAuth2Error{}, endpoint, "state")

		assert.Error(t, err)
		assert.Empty(t, redirect)
	})
}

func TestHolderService_PostResponse(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createOAuthHolderContext(t)
		endpoint := fmt.Sprintf("%s/response", ctx.tlsServer.URL)
		vp := vc.VerifiablePresentation{Type: []ssi.URI{ssi.MustParseURI("VerifiablePresentation")}}
		// marshal and unmarshal to make sure Raw() works
		bytes, _ := json.Marshal(vp)
		_ = json.Unmarshal(bytes, &vp)

		redirect, err := ctx.holder.PostAuthorizationResponse(
			ctx.audit,
			vp,
			pe.PresentationSubmission{Id: "id"},
			endpoint,
			"state",
		)

		require.NoError(t, err)
		assert.Equal(t, "redirect", redirect)
	})
	t.Run("error", func(t *testing.T) {
		ctx := createOAuthHolderContext(t)
		endpoint := fmt.Sprintf("%s/response", ctx.tlsServer.URL)
		ctx.response = nil

		redirect, err := ctx.holder.PostAuthorizationResponse(ctx.audit, vc.VerifiablePresentation{}, pe.PresentationSubmission{}, endpoint, "")

		assert.Error(t, err)
		assert.Empty(t, redirect)
	})
}

func TestHolderService_BuildPresentation(t *testing.T) {
	credentials := []vcr.VerifiableCredential{credential.ValidNutsOrganizationCredential(t)}
	walletDID := did.MustParseDID("did:web:example.com:iam:wallet")
	verifierDID := did.MustParseDID("did:web:example.com:iam:verifier")
	presentationDefinition := pe.PresentationDefinition{InputDescriptors: []*pe.InputDescriptor{{Constraints: &pe.Constraints{Fields: []pe.Field{{Path: []string{"$.type"}}}}}}}
	vpFormats := oauth.DefaultOpenIDSupportedFormats()

	t.Run("ok", func(t *testing.T) {
		ctx := createHolderContext(t, nil)
		ctx.wallet.EXPECT().List(gomock.Any(), walletDID).Return(credentials, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), credentials, gomock.Any(), &walletDID, false).Return(&vc.VerifiablePresentation{}, nil)

		vp, submission, err := ctx.holder.BuildPresentation(context.Background(), walletDID, presentationDefinition, vpFormats, "", verifierDID.URI())

		assert.NoError(t, err)
		require.NotNil(t, vp)
		require.NotNil(t, submission)

	})
	// wallet failure, build failure, no credentials
	t.Run("error - wallet failure", func(t *testing.T) {
		ctx := createHolderContext(t, nil)
		ctx.wallet.EXPECT().List(gomock.Any(), walletDID).Return(nil, assert.AnError)

		vp, submission, err := ctx.holder.BuildPresentation(context.Background(), walletDID, presentationDefinition, vpFormats, "", verifierDID.URI())

		assert.Error(t, err)
		assert.Nil(t, vp)
		assert.Nil(t, submission)
	})
	t.Run("error - build failure", func(t *testing.T) {
		ctx := createHolderContext(t, nil)
		ctx.wallet.EXPECT().List(gomock.Any(), walletDID).Return(credentials, nil)
		ctx.wallet.EXPECT().BuildPresentation(gomock.Any(), credentials, gomock.Any(), &walletDID, false).Return(nil, assert.AnError)

		vp, submission, err := ctx.holder.BuildPresentation(context.Background(), walletDID, presentationDefinition, vpFormats, "", verifierDID.URI())

		assert.Error(t, err)
		assert.Nil(t, vp)
		assert.Nil(t, submission)
	})
	t.Run("error - no matching credentials", func(t *testing.T) {
		ctx := createHolderContext(t, nil)
		ctx.wallet.EXPECT().List(gomock.Any(), walletDID).Return(credentials, nil)

		vp, submission, err := ctx.holder.BuildPresentation(context.Background(), walletDID, pe.PresentationDefinition{}, vpFormats, "", verifierDID.URI())

		assert.Equal(t, ErrNoCredentials, err)
		assert.Nil(t, vp)
		assert.Nil(t, submission)
	})
}

func TestHolderService_PresentationDefinition(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createOAuthHolderContext(t)
		endpoint := fmt.Sprintf("%s/presentation_definition", ctx.tlsServer.URL)

		pd, err := ctx.holder.PresentationDefinition(context.Background(), endpoint)

		assert.NoError(t, err)
		assert.NotNil(t, pd)
	})
	t.Run("error", func(t *testing.T) {
		ctx := createOAuthHolderContext(t)
		endpoint := fmt.Sprintf("%s/presentation_definition", ctx.tlsServer.URL)
		ctx.presentationDefinition = nil

		pd, err := ctx.holder.PresentationDefinition(context.Background(), endpoint)

		assert.Error(t, err)
		assert.Nil(t, pd)
	})
}

type holderTestContext struct {
	ctrl   *gomock.Controller
	audit  context.Context
	holder Holder
	wallet *holder.MockWallet
}

func createHolderContext(t *testing.T, tlsConfig *tls.Config) *holderTestContext {
	ctrl := gomock.NewController(t)

	wallet := holder.NewMockWallet(ctrl)

	if tlsConfig == nil {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.InsecureSkipVerify = true

	return &holderTestContext{
		audit: audit.TestContext(),
		ctrl:  ctrl,
		holder: &HolderService{
			httpClientTLS: tlsConfig,
			wallet:        wallet,
		},
		wallet: wallet,
	}
}

type holderOAuthTestContext struct {
	*holderTestContext
	authzServerMetadata    *oauth.AuthorizationServerMetadata
	handler                http.HandlerFunc
	tlsServer              *httptest.Server
	verifierDID            did.DID
	metadata               func(writer http.ResponseWriter)
	errorResponse          func(writer http.ResponseWriter)
	response               func(writer http.ResponseWriter)
	presentationDefinition func(writer http.ResponseWriter)
}

func createOAuthHolderContext(t *testing.T) *holderOAuthTestContext {
	clientMetadata := &oauth.AuthorizationServerMetadata{VPFormats: oauth.DefaultOpenIDSupportedFormats()}
	ctx := &holderOAuthTestContext{
		holderTestContext: createHolderContext(t, nil),
		metadata: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(*clientMetadata)
			_, _ = writer.Write(bytes)
			return
		},
		errorResponse: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(oauth.Redirect{
				RedirectURI: "redirect",
			})
			_, _ = writer.Write(bytes)
			return
		},
		presentationDefinition: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(pe.PresentationDefinition{})
			_, _ = writer.Write(bytes)
			return
		},
		response: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(oauth.Redirect{
				RedirectURI: "redirect",
			})
			_, _ = writer.Write(bytes)
			return
		},
	}

	ctx.handler = func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/.well-known/oauth-authorization-server":
			if ctx.metadata != nil {
				ctx.metadata(writer)
				return
			}
		case "/error":
			if ctx.errorResponse != nil {
				assert.Equal(t, string(oauth.InvalidRequest), request.FormValue("error"))
				ctx.errorResponse(writer)
				return
			}
		case "/presentation_definition":
			if ctx.presentationDefinition != nil {
				ctx.presentationDefinition(writer)
				return
			}
		case "/response":
			if ctx.response != nil {
				assert.NotEmpty(t, request.FormValue(oauth.VpTokenParam))
				assert.NotEmpty(t, request.FormValue(oauth.PresentationSubmissionParam))
				assert.NotEmpty(t, request.FormValue(oauth.StateParam))
				ctx.errorResponse(writer)
				return
			}
		}
		writer.WriteHeader(http.StatusNotFound)
	}
	ctx.tlsServer = http2.TestTLSServer(t, ctx.handler)
	ctx.verifierDID = didweb.ServerURLToDIDWeb(t, ctx.tlsServer.URL)

	return ctx
}
