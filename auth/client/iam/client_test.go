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
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
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

	// metadataServer serves AuthorizationServerMetadata at the listed paths and returns
	// missStatus for any other path. The served issuer equals the server URL plus issuerPath,
	// so it matches an identifier of tlsServer.URL+issuerPath. It records every requested path.
	metadataServer := func(t *testing.T, missStatus int, issuerPath string, servedPaths ...string) (*httptest.Server, *HTTPClient, *[]string) {
		var requested []string
		served := make(map[string]struct{}, len(servedPaths))
		var issuer string
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requested = append(requested, r.URL.Path)
			if _, ok := served[r.URL.Path]; ok {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(oauth.AuthorizationServerMetadata{Issuer: issuer, TokenEndpoint: "/token"})
				return
			}
			w.WriteHeader(missStatus)
		})
		tlsServer, client := testServerAndClient(t, handler)
		issuer = tlsServer.URL + issuerPath
		for _, p := range servedPaths {
			served[p] = struct{}{}
		}
		return tlsServer, client, &requested
	}

	// The insert/append fallback, identifier-match, and error-joining behavior is exhaustively
	// covered by oauth.FetchMetadata's own tests; this wraps it with no extra logic, so these
	// tests only need to confirm the wiring (well-known constant, httpClient, strictMode) and
	// that this specific bug (rewriting an upstream status code) doesn't reappear.
	t.Run("ok - append form when insert 404s", func(t *testing.T) {
		tlsServer, client, requested := metadataServer(t, http.StatusNotFound, "/iam/123", "/iam/123/.well-known/oauth-authorization-server")

		metadata, err := client.OAuthAuthorizationServerMetadata(ctx, tlsServer.URL+"/iam/123")

		require.NoError(t, err)
		require.NotNil(t, metadata)
		assert.Equal(t, []string{
			"/.well-known/oauth-authorization-server/iam/123",
			"/iam/123/.well-known/oauth-authorization-server",
		}, *requested)
	})
	t.Run("error - errors are returned as-is", func(t *testing.T) {
		tlsServer, client, _ := metadataServer(t, http.StatusInternalServerError, "")

		_, err := client.OAuthAuthorizationServerMetadata(ctx, tlsServer.URL)

		require.Error(t, err)
		var httpErr core.HttpError
		require.ErrorAs(t, err, &httpErr)
		assert.Equal(t, http.StatusInternalServerError, httpErr.StatusCode)
	})
	t.Run("error - all candidates 4xx classifies as ErrInvalidClientCall", func(t *testing.T) {
		tlsServer, client, _ := metadataServer(t, http.StatusNotFound, "/iam/123")

		_, err := client.OAuthAuthorizationServerMetadata(ctx, tlsServer.URL+"/iam/123")

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidClientCall)
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
		var oauthErr oauth.OAuth2Error
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth.InvalidRequest, oauthErr.Code)
		require.ErrorAs(t, err, new(oauth.RemoteOAuthError))
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
		// check if the error is a remote OAuth error
		var oauthError oauth.OAuth2Error
		require.ErrorAs(t, err, &oauthError)
		assert.Equal(t, oauth.InvalidRequest, oauthError.Code)
		require.ErrorAs(t, err, new(oauth.RemoteOAuthError))
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
	t.Run("error - oauth error with non-400 status", func(t *testing.T) {
		// Some authorization servers return non-400 status codes for OAuth errors (e.g. 401, 500).
		// The client should still recognize a JSON body with an "error" field as an OAuth error.
		handler := http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: oauth.OAuth2Error{Code: oauth.InvalidRequest}}
		tlsServer, client := testServerAndClient(t, &handler)

		_, err := client.AccessToken(ctx, tlsServer.URL, data, dpopHeader)

		require.Error(t, err)
		var oauthError oauth.OAuth2Error
		require.ErrorAs(t, err, &oauthError)
		assert.Equal(t, oauth.InvalidRequest, oauthError.Code)
		require.ErrorAs(t, err, new(oauth.RemoteOAuthError))
	})
	t.Run("error - non-JSON response with non-OK status", func(t *testing.T) {
		// Not JSON, so must not be treated as an OAuth error.
		handler := http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: "not json"}
		tlsServer, client := testServerAndClient(t, &handler)

		_, err := client.AccessToken(ctx, tlsServer.URL, data, dpopHeader)

		require.Error(t, err)
		httpError, ok := err.(core.HttpError)
		require.True(t, ok)
		assert.Equal(t, "not json", string(httpError.ResponseBody))
	})
	t.Run("error - JSON response without OAuth error code", func(t *testing.T) {
		// JSON, but without an "error" field — must not be treated as an OAuth error.
		handler := http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: map[string]string{"message": "something went wrong"}}
		tlsServer, client := testServerAndClient(t, &handler)

		_, err := client.AccessToken(ctx, tlsServer.URL, data, dpopHeader)

		require.Error(t, err)
		_, ok := err.(core.HttpError)
		require.True(t, ok)
		require.NotErrorAs(t, err, new(oauth.RemoteOAuthError))
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
		JWKs:   jwk.NewSet(),
	}

	// create jwt
	createToken := func(t *testing.T, client *HTTPClient) string {
		testKey := client.keyResolver.(testKeyResolver).key
		claims := make(map[string]interface{})
		asJson, _ := json.Marshal(configuration)
		_ = json.Unmarshal(asJson, &claims)
		// jwx v3 rejects a token whose "exp" is set to the zero value (epoch) as expired;
		// the marshaled zero-value OpenIDConfiguration includes "exp":0, so drop it to keep the token valid.
		delete(claims, "exp")
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
		assert.EqualError(t, err, "unable to parse response: jwt.Parse: failed to parse token: jws.Verify: failed to parse jws: jws.Parse: failed to parse compact format: jws.Parse: invalid compact serialization format: jwsbb: invalid number of segments")
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
		assert.EqualError(t, err, "unable to parse response: jwt.Parse: failed to parse token: jws.Verify: could not verify message using any of the signatures or keys: jws.Verify: failed to verify signature #1 with key *ecdsa.PublicKey: invalid ECDSA signature\njws.Verify: signature #1: tried 1 key(s) but none verified successfully")
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

func (t testKeyResolver) ResolveKeyByID(keyID string, metadata *resolver.ResolveMetadata, relationType resolver.RelationType) (crypto.PublicKey, error) {
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
