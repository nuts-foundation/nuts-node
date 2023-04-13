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

package oidc4vci

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/test"
	"net/http"
	"testing"
	"time"
)

// setupClientTest starts an HTTP server that stubs OIDC4VCI operations, which can then be used to test OIDC4VCI clients.
func setupClientTest(t *testing.T) *oidcClientTestContext {
	issuerMetadata := new(CredentialIssuerMetadata)
	providerMetadata := new(ProviderMetadata)
	walletMetadata := new(OAuth2ClientMetadata)
	credentialResponse := CredentialResponse{
		Format: VerifiableCredentialJSONLDFormat,
		Credential: &map[string]interface{}{
			"@context":          []string{"https://www.w3.org/2018/credentials/v1"},
			"type":              []string{"VerifiableCredential"},
			"issuer":            "issuer",
			"issuanceDate":      time.Now().Format(time.RFC3339),
			"credentialSubject": map[string]interface{}{"id": "id"},
		},
	}
	clientTest := &oidcClientTestContext{
		issuerMetadata:   issuerMetadata,
		providerMetadata: providerMetadata,
		walletMetadata:   walletMetadata,
	}
	clientTest.issuerMetadataHandler = clientTest.httpGetHandler(issuerMetadata)
	clientTest.providerMetadataHandler = clientTest.httpGetHandler(providerMetadata)
	clientTest.credentialHandler = clientTest.httpPostHandler(credentialResponse)
	clientTest.tokenHandler = clientTest.httpPostHandler(TokenResponse{AccessToken: "secret"})
	clientTest.walletMetadataHandler = clientTest.httpGetHandler(walletMetadata)
	clientTest.credentialOfferHandler = clientTest.httpGetHandler(nil)

	mux := http.NewServeMux()
	mux.HandleFunc("/issuer"+CredentialIssuerMetadataWellKnownPath, func(writer http.ResponseWriter, request *http.Request) {
		clientTest.issuerMetadataHandler(writer, request)
	})
	mux.HandleFunc("/issuer"+ProviderMetadataWellKnownPath, func(writer http.ResponseWriter, request *http.Request) {
		clientTest.providerMetadataHandler(writer, request)
	})
	mux.HandleFunc("/issuer/credential", func(writer http.ResponseWriter, request *http.Request) {
		clientTest.credentialHandler(writer, request)
	})
	mux.HandleFunc("/issuer/token", func(writer http.ResponseWriter, request *http.Request) {
		clientTest.tokenHandler(writer, request)
	})
	mux.HandleFunc("/wallet/metadata", func(writer http.ResponseWriter, request *http.Request) {
		clientTest.walletMetadataHandler(writer, request)
	})
	mux.HandleFunc("/wallet/credential_offer", func(writer http.ResponseWriter, request *http.Request) {
		clientTest.credentialOfferHandler(writer, request)
	})
	serverURL := startHTTPServer(t, mux)

	clientTest.walletMetadata.CredentialOfferEndpoint = serverURL + "/wallet/credential_offer"
	clientTest.walletMetadataURL = serverURL + "/wallet/metadata"
	issuerIdentifier := serverURL + "/issuer"
	issuerMetadata.CredentialIssuer = issuerIdentifier
	issuerMetadata.CredentialEndpoint = issuerIdentifier + "/credential"
	providerMetadata.Issuer = issuerIdentifier
	providerMetadata.TokenEndpoint = issuerIdentifier + "/token"
	return clientTest
}

func (i *oidcClientTestContext) httpPostHandler(response interface{}) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		i.requests = append(i.requests, *request)

		defer request.Body.Close()
		if request.Method != "POST" {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		data, _ := json.Marshal(response)
		writer.WriteHeader(http.StatusOK)
		writer.Write(data)
	}
}

func (i *oidcClientTestContext) httpGetHandler(response interface{}) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		i.requests = append(i.requests, *request)

		defer request.Body.Close()
		if request.Method != "GET" {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		data, _ := json.Marshal(response)
		writer.WriteHeader(http.StatusOK)
		writer.Write(data)
	}
}

type oidcClientTestContext struct {
	issuerMetadata          *CredentialIssuerMetadata
	providerMetadata        *ProviderMetadata
	walletMetadata          *OAuth2ClientMetadata
	walletMetadataURL       string
	issuerMetadataHandler   http.HandlerFunc
	providerMetadataHandler http.HandlerFunc
	credentialHandler       http.HandlerFunc
	credentialOfferHandler  http.HandlerFunc
	tokenHandler            http.HandlerFunc
	walletMetadataHandler   http.HandlerFunc
	requests                []http.Request
}

func startHTTPServer(t *testing.T, mux *http.ServeMux) string {
	httpPort := test.FreeTCPPort()
	server := &http.Server{Addr: fmt.Sprintf(":%d", httpPort), Handler: mux}
	httpServerURL := fmt.Sprintf("http://localhost:%d", httpPort)
	startErrorChannel := make(chan error)
	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			startErrorChannel <- err
		}
	}()
	test.WaitFor(t, func() (bool, error) {
		// Check if Start() error-ed
		if len(startErrorChannel) > 0 {
			return false, <-startErrorChannel
		}
		_, err := http.Get(httpServerURL)
		return err == nil, nil
	}, 5*time.Second, "time-out waiting for HTTP server to start")
	t.Cleanup(func() {
		server.Shutdown(context.Background())
	})
	return httpServerURL
}
