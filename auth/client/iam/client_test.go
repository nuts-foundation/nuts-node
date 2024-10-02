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
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	test2 "github.com/nuts-foundation/nuts-node/crypto/test"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPClient_OAuthAuthorizationServerMetadata(t *testing.T) {
	ctx := context.Background()

	t.Run("ok using root web:did", func(t *testing.T) {
		result := oauth.AuthorizationServerMetadata{TokenEndpoint: "/token"}
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: result}
		tlsServer, client := testServerAndClient(t, &handler)

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, tlsServer.URL)

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, "/token", metadata.TokenEndpoint)
		require.NotNil(t, handler.Request)
		assert.Equal(t, "GET", handler.Request.Method)
		assert.Equal(t, "/.well-known/oauth-authorization-server", handler.Request.URL.Path)
	})
	t.Run("ok using user web:did", func(t *testing.T) {
		result := oauth.AuthorizationServerMetadata{TokenEndpoint: "/token"}
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: result}
		tlsServer, client := testServerAndClient(t, &handler)

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, tlsServer.URL+"/iam/123")

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, "/token", metadata.TokenEndpoint)
		require.NotNil(t, handler.Request)
		assert.Equal(t, "GET", handler.Request.Method)
		assert.Equal(t, "/.well-known/oauth-authorization-server/iam/123", handler.Request.URL.Path)
	})
	t.Run("error - server error changes status code to 502", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusInternalServerError}
		tlsServer, client := testServerAndClient(t, &handler)

		_, err := client.OAuthAuthorizationServerMetadata(ctx, tlsServer.URL)

		require.Error(t, err)
		httpErr, ok := err.(core.HttpError)
		require.True(t, ok)
		assert.Equal(t, http.StatusBadGateway, httpErr.StatusCode)
	})
}

func TestHTTPClient_PresentationDefinition(t *testing.T) {
	ctx := context.Background()
	definition := pe.PresentationDefinition{
		Id: "123",
	}

	t.Run("ok", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: definition}
		tlsServer, client := testServerAndClient(t, &handler)
		pdUrl := test.MustParseURL(tlsServer.URL)

		response, err := client.PresentationDefinition(ctx, *pdUrl)

		require.NoError(t, err)
		require.NotNil(t, definition)
		assert.Equal(t, definition, *response)
		require.NotNil(t, handler.Request)
	})
	t.Run("error - generic error results in 502", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusInternalServerError}
		tlsServer, client := testServerAndClient(t, &handler)
		pdUrl := test.MustParseURL(tlsServer.URL)

		_, err := client.PresentationDefinition(ctx, *pdUrl)

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrBadGateway)
	})
	t.Run("error - oauth error", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: oauth.OAuth2Error{Code: oauth.InvalidRequest}}
		tlsServer, client := testServerAndClient(t, &handler)
		pdUrl := test.MustParseURL(tlsServer.URL)

		_, err := client.PresentationDefinition(ctx, *pdUrl)

		require.Error(t, err)
		oauthErr, ok := err.(oauth.OAuth2Error)
		require.True(t, ok)
		assert.Equal(t, oauth.InvalidRequest, oauthErr.Code)
	})
}

func TestHTTPClient_AccessToken(t *testing.T) {
	ctx := context.Background()
	// params are checked server side, so we don't need to provide valid values here
	tokenResponse := oauth.TokenResponse{
		AccessToken: "token",
	}
	dpopHeader := "dpop"
	data := url.Values{}

	t.Run("ok", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: tokenResponse}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.AccessToken(ctx, tlsServer.URL, data, dpopHeader)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, tokenResponse, response)
		require.NotNil(t, handler.Request)
	})
	t.Run("error - incorrect url", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: tokenResponse}
		_, client := testServerAndClient(t, &handler)

		_, err := client.AccessToken(ctx, ":", data, dpopHeader)

		require.Error(t, err)
		assert.EqualError(t, err, "parse \":\": missing protocol scheme")
	})
	t.Run("error - oauth error", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: oauth.OAuth2Error{Code: oauth.InvalidRequest}}
		tlsServer, client := testServerAndClient(t, &handler)

		_, err := client.AccessToken(ctx, tlsServer.URL, data, dpopHeader)

		require.Error(t, err)
		// check if the error is an OAuth error
		oauthError, ok := err.(oauth.OAuth2Error)
		require.True(t, ok)
		assert.Equal(t, oauth.InvalidRequest, oauthError.Code)
	})
	t.Run("error - generic server error", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusBadGateway, ResponseData: "offline"}
		tlsServer, client := testServerAndClient(t, &handler)

		_, err := client.AccessToken(ctx, tlsServer.URL, data, dpopHeader)

		require.Error(t, err)
		// check if the error is a http error
		httpError, ok := err.(core.HttpError)
		require.True(t, ok)
		assert.Equal(t, "offline", string(httpError.ResponseBody))
	})
	t.Run("error - invalid response", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: "}"}
		tlsServer, client := testServerAndClient(t, &handler)

		_, err := client.AccessToken(ctx, tlsServer.URL, data, dpopHeader)

		require.Error(t, err)
		assert.EqualError(t, err, "unable to unmarshal response: invalid character '}' looking for beginning of value, }")
	})

}

func TestHTTPClient_ClientMetadata(t *testing.T) {
	ctx := context.Background()
	metadata := oauth.OAuthClientMetadata{
		SoftwareID: "id",
	}

	t.Run("ok", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: metadata}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.ClientMetadata(ctx, tlsServer.URL)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, metadata, *response)
		require.NotNil(t, handler.Request)
	})
}

func TestHTTPClient_OpenIDConfiguration(t *testing.T) {
	ctx := context.Background()
	configuration := oauth.OpenIDConfiguration{
		Issuer: "issuer",
	}

	// create jwt
	createToken := func(t *testing.T, client *HTTPClient) string {
		testKey := client.keyResolver.(testKeyResolver).key
		claims := make(map[string]interface{})
		asJson, _ := json.Marshal(configuration)
		_ = json.Unmarshal(asJson, &claims)
		alg, _ := nutsCrypto.SignatureAlgorithm(testKey.Public())
		headers := map[string]interface{}{jws.AlgorithmKey: alg, jws.KeyIDKey: "test"}
		token, err := nutsCrypto.SignJWT(audit.TestContext(), testKey, alg, claims, headers)
		require.NoError(t, err)
		return token
	}

	t.Run("ok", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK}
		tlsServer, client := testServerAndClient(t, &handler)
		handler.ResponseData = createToken(t, client)

		response, err := client.OpenIDConfiguration(ctx, tlsServer.URL)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, configuration, *response)
		require.NotNil(t, handler.Request)
	})
	t.Run("error - invalid url", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK}
		_, client := testServerAndClient(t, &handler)
		handler.ResponseData = createToken(t, client)

		_, err := client.OpenIDConfiguration(ctx, ":")

		require.Error(t, err)
		assert.EqualError(t, err, "parse \":\": missing protocol scheme")
	})
	t.Run("error - error return", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusInternalServerError}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.OpenIDConfiguration(ctx, tlsServer.URL)

		require.Error(t, err)
		require.Nil(t, response)
		assert.EqualError(t, err, "server returned HTTP 500 (expected: 200)")
	})
	t.Run("error - not a signed jwt", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: ""}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.OpenIDConfiguration(ctx, tlsServer.URL)

		require.Error(t, err)
		require.Nil(t, response)
		assert.EqualError(t, err, "unable to parse response: failed to parse jws: invalid byte sequence")
	})
	t.Run("error - unknown key", func(t *testing.T) {
		otherClient := &HTTPClient{
			keyResolver: newTestKeyResolver(),
		}
		handler := http2.Handler{StatusCode: http.StatusOK}
		tlsServer, client := testServerAndClient(t, &handler)
		handler.ResponseData = createToken(t, otherClient)

		response, err := client.OpenIDConfiguration(ctx, tlsServer.URL)

		require.Error(t, err)
		require.Nil(t, response)
		assert.EqualError(t, err, "unable to parse response: could not verify message using any of the signatures or keys")
	})
}

func TestHTTPClient_PostError(t *testing.T) {
	redirectReturn := oauth.Redirect{
		RedirectURI: "http://test.test",
	}
	t.Run("ok", func(t *testing.T) {
		ctx := context.Background()
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: redirectReturn}
		tlsServer, client := testServerAndClient(t, &handler)
		tlsServerURL := test.MustParseURL(tlsServer.URL)

		redirectURI, err := client.PostError(ctx, oauth.OAuth2Error{Code: oauth.InvalidRequest, Description: "test"}, *tlsServerURL)

		require.NoError(t, err)
		assert.Equal(t, redirectReturn.RedirectURI, redirectURI)
	})
}

func TestHTTPClient_PostAuthorizationResponse(t *testing.T) {
	presentation := vc.VerifiablePresentation{ID: &ssi.URI{URL: url.URL{Scheme: "https", Host: "test.test"}}}
	submission := pe.PresentationSubmission{Id: "id"}
	redirectReturn := oauth.Redirect{
		RedirectURI: "http://test.test",
	}
	t.Run("ok", func(t *testing.T) {
		ctx := context.Background()
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: redirectReturn}
		tlsServer, client := testServerAndClient(t, &handler)
		tlsServerURL := test.MustParseURL(tlsServer.URL)

		redirectURI, err := client.PostAuthorizationResponse(ctx, presentation, submission, *tlsServerURL, "")

		require.NoError(t, err)
		assert.Equal(t, redirectReturn.RedirectURI, redirectURI)
	})
}

func TestHTTPClient_postFormExpectRedirect(t *testing.T) {
	redirectReturn := oauth.Redirect{
		RedirectURI: "http://test.test",
	}
	data := url.Values{}
	data.Set("test", "test")

	t.Run("ok", func(t *testing.T) {
		ctx := context.Background()
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: redirectReturn}
		tlsServer, client := testServerAndClient(t, &handler)
		tlsServerURL := test.MustParseURL(tlsServer.URL)

		redirectURI, err := client.postFormExpectRedirect(ctx, data, *tlsServerURL)

		require.NoError(t, err)
		assert.Equal(t, redirectReturn.RedirectURI, redirectURI)
	})
}

func TestHTTPClient_RequestObject(t *testing.T) {
	ctx := context.Background()
	// params are checked server side, so we don't need to provide valid values here
	t.Run("ok", func(t *testing.T) {
		responseData := "signed request object"
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: responseData}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.RequestObjectByGet(ctx, tlsServer.URL)

		require.NoError(t, err)
		assert.Equal(t, responseData, response)
	})
	t.Run("error - invalid request_uri", func(t *testing.T) {
		_, client := testServerAndClient(t, &http2.Handler{})

		response, err := client.RequestObjectByGet(ctx, ":")

		assert.EqualError(t, err, "parse \":\": missing protocol scheme")
		assert.Empty(t, response)
	})
	t.Run("error - not found", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusNotFound, ResponseData: "throw this away"}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.RequestObjectByGet(ctx, tlsServer.URL)

		var httpErr core.HttpError
		require.ErrorAs(t, err, &httpErr)
		assert.Equal(t, http.StatusNotFound, httpErr.StatusCode)
		assert.Empty(t, response)

	})
}

func TestHTTPClient_RequestObjectPost(t *testing.T) {
	ctx := context.Background()
	// params are checked server side, so we don't need to provide valid values here
	t.Run("ok", func(t *testing.T) {
		responseData := "signed request object"
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: responseData}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.RequestObjectByPost(ctx, tlsServer.URL, url.Values{})

		require.NoError(t, err)
		assert.Equal(t, responseData, response)
	})
	t.Run("error - invalid request_uri", func(t *testing.T) {
		_, client := testServerAndClient(t, &http2.Handler{})

		response, err := client.RequestObjectByPost(ctx, ":", url.Values{})

		assert.EqualError(t, err, "parse \":\": missing protocol scheme")
		assert.Empty(t, response)
	})
	t.Run("error - not found", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusNotFound, ResponseData: "throw this away"}
		tlsServer, client := testServerAndClient(t, &handler)

		response, err := client.RequestObjectByPost(ctx, tlsServer.URL, url.Values{})

		var httpErr core.HttpError
		require.ErrorAs(t, err, &httpErr)
		assert.Equal(t, http.StatusNotFound, httpErr.StatusCode)
		assert.Empty(t, response)

	})
}

func TestHTTPClient_doGet(t *testing.T) {
	t.Run("error - non 200 return value", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusBadRequest}
		tlsServer, client := testServerAndClient(t, &handler)

		err := client.doGet(context.Background(), tlsServer.URL, nil)

		assert.Error(t, err)
	})
	t.Run("error - bad contents", func(t *testing.T) {
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: "not json"}
		tlsServer, client := testServerAndClient(t, &handler)

		var target interface{}
		err := client.doGet(context.Background(), tlsServer.URL, &target)

		assert.Error(t, err)
	})
	t.Run("error - server not responding", func(t *testing.T) {
		_, client := testServerAndClient(t, nil)

		var target interface{}
		err := client.doGet(context.Background(), "https://localhost:9999", &target)

		assert.Error(t, err)
	})
}

func newTestKeyResolver() resolver.KeyResolver {
	return testKeyResolver{
		kid: uuid.NewString(),
		key: test2.GenerateECKey(),
	}
}

type testKeyResolver struct {
	kid string
	key *ecdsa.PrivateKey
}

func (t testKeyResolver) ResolveKeyByID(keyID string, validAt *time.Time, relationType resolver.RelationType) (crypto.PublicKey, error) {
	return t.key.Public(), nil
}

func (t testKeyResolver) ResolveKey(id did.DID, validAt *time.Time, relationType resolver.RelationType) (string, crypto.PublicKey, error) {
	return t.kid, t.key.Public(), nil
}

func testServerAndClient(t *testing.T, handler http.Handler) (*httptest.Server, *HTTPClient) {
	tlsServer := http2.TestTLSServer(t, handler)
	return tlsServer, &HTTPClient{
		httpClient:  tlsServer.Client(),
		keyResolver: newTestKeyResolver(),
	}
}
