/*
 * Nuts node
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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestVerifier_AuthorizationServerMetadata(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctx := createVContext(t)

		metadata, err := ctx.verifier.AuthorizationServerMetadata(context.Background(), ctx.verifierDID)

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, ctx.authzServerMetadata, *metadata)
	})
	t.Run("error - failed to get metadata", func(t *testing.T) {
		ctx := createVContext(t)
		ctx.metadata = nil

		_, err := ctx.verifier.AuthorizationServerMetadata(context.Background(), ctx.verifierDID)

		require.Error(t, err)
		assert.EqualError(t, err, "failed to retrieve remote OAuth Authorization Server metadata: server returned HTTP 404 (expected: 200)")
	})
}

func TestVerifierServiceProvider_ClientMetadataURL(t *testing.T) {
	verifier := NewVerifier(false, 0, &tls.Config{InsecureSkipVerify: true})
	webdid := did.MustParseDID("did:web:example.com:iam:holder")

	t.Run("ok", func(t *testing.T) {
		url, err := verifier.ClientMetadataURL(webdid)

		require.NoError(t, err)
		require.NotNil(t, url)
		assert.Equal(t, "https://example.com/.well-known/oauth-authorization-server/iam/holder", url.String())
	})
	t.Run("error - invalid DID", func(t *testing.T) {
		_, err := verifier.ClientMetadataURL(did.DID{})

		require.Error(t, err)
		assert.EqualError(t, err, "failed to convert DID to URL: URL does not represent a Web DID\nunsupported DID method: ")
	})
}

type vTestContext struct {
	ctrl                *gomock.Controller
	verifier            Verifier
	authzServerMetadata oauth.AuthorizationServerMetadata
	handler             http.HandlerFunc
	tlsServer           *httptest.Server
	verifierDID         did.DID
	metadata            func(writer http.ResponseWriter)
}

func createVContext(t *testing.T) *vTestContext {
	ctrl := gomock.NewController(t)
	authzServerMetadata := oauth.AuthorizationServerMetadata{}
	ctx := &vTestContext{
		ctrl: ctrl,
		metadata: func(writer http.ResponseWriter) {
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			bytes, _ := json.Marshal(authzServerMetadata)
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
		}
		writer.WriteHeader(http.StatusNotFound)
	}
	ctx.tlsServer = http2.TestTLSServer(t, ctx.handler)
	ctx.verifierDID = didweb.ServerURLToDIDWeb(t, ctx.tlsServer.URL)
	ctx.authzServerMetadata = authzServerMetadata
	ctx.verifier = NewVerifier(false, 0, &tls.Config{InsecureSkipVerify: true})

	return ctx
}
