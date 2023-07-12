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

package test

import (
	"bytes"
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/core"
	httpModule "github.com/nuts-foundation/nuts-node/http"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/didman"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/node"
	"github.com/nuts-foundation/nuts-node/vcr"
	credentialTypes "github.com/nuts-foundation/nuts-node/vcr/credential"
	vdrTypes "github.com/nuts-foundation/nuts-node/vdr/types"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vdr/didservice"
	"github.com/stretchr/testify/require"
)

// TestOpenID4VCIHappyFlow tests issuing a VC using OpenID4VCI.
func TestOpenID4VCIHappyFlow(t *testing.T) {
	auditLogs := audit.CaptureLogs(t)
	ctx := audit.TestContext()
	baseURL, system := node.StartServer(t, func(serverURL string) {
		t.Setenv("NUTS_VCR_OPENID4VCI_ENABLED", "true")
	})
	vcrService := system.FindEngineByName("vcr").(vcr.VCR)

	issuerDID := registerDID(t, system)
	registerBaseURL(t, baseURL, system, issuerDID)
	holderDID := registerDID(t, system)
	registerBaseURL(t, baseURL, system, holderDID)

	credential := testCredential()
	credential.Issuer = issuerDID.URI()
	credential.ID, _ = ssi.ParseURI(issuerDID.URI().String() + "#1")
	credential.CredentialSubject = append(credential.CredentialSubject, map[string]interface{}{
		"id":           holderDID.URI().String(),
		"purposeOfUse": "test",
	})
	issuedVC, err := vcrService.Issuer().Issue(ctx, credential, true, false)

	require.NoError(t, err)
	require.NotNil(t, issuedVC)

	test.WaitFor(t, func() (bool, error) {
		return auditLogs.Contains(t, audit.VerifiableCredentialRetrievedEvent), nil
	}, 5*time.Second, "credential not retrieved by holder")
}

func TestOpenID4VCIConnectionReuse(t *testing.T) {
	// default http.Transport has MaxConnsPerHost=100,
	// but we need to adjust it to something lower, so we can assert connection reuse
	const maxConnsPerHost = 3
	// 2 hosts; 1 to 127.0.0.1 (IPv4) and 1 to [::1] (IPv6),
	// so we expect maxConnsPerHost*2 connections in total.
	const expectedConnsCount = maxConnsPerHost * 2
	http.DefaultTransport.(*http.Transport).MaxConnsPerHost = maxConnsPerHost

	ctx := audit.TestContext()
	baseURL, system := node.StartServer(t, func(serverURL string) {
		t.Setenv("NUTS_VCR_OPENID4VCI_ENABLED", "true")
	})
	vcrService := system.FindEngineByName("vcr").(vcr.VCR)

	issuerDID := registerDID(t, system)
	registerBaseURL(t, baseURL, system, issuerDID)
	holderDID := registerDID(t, system)
	registerBaseURL(t, baseURL, system, holderDID)

	credential := testCredential()
	credential.Issuer = issuerDID.URI()
	credential.ID, _ = ssi.ParseURI(issuerDID.URI().String() + "#1")
	credential.CredentialSubject = append(credential.CredentialSubject, map[string]interface{}{
		"id":           holderDID.URI().String(),
		"purposeOfUse": "test",
	})

	newConns := map[string]int{}
	mux := sync.Mutex{}
	openid4vci.HttpClientTrace = &httptrace.ClientTrace{
		ConnectStart: func(network, addr string) {
			log.Logger().Infof("Conn: %s/%s", network, addr)
			mux.Lock()
			defer mux.Unlock()
			newConns[network+"/"+addr]++
		},
	}

	const numCreds = 4
	errChan := make(chan error, numCreds)
	wg := sync.WaitGroup{}
	for i := 0; i < numCreds; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := vcrService.Issuer().Issue(ctx, credential, true, false)
			if err != nil {
				errChan <- err
				return
			}
		}()
	}

	wg.Wait()
	// Drain errs channel, non-blocking
	close(errChan)
	var errs []string
	for {
		err := <-errChan
		if err == nil {
			break

		}
		errs = append(errs, err.Error())
	}
	assert.Empty(t, errs, "error issuing credential")
	connsTotal := 0
	for _, v := range newConns {
		connsTotal += v
	}
	assert.LessOrEqualf(t, connsTotal, expectedConnsCount, "number of created HTTP connections should be at most %d", expectedConnsCount)
}

// TestOpenID4VCI_Metadata tests resolving OpenID4VCI metadata, while the party hasn't registered its base URL.
func TestOpenID4VCI_Metadata(t *testing.T) {
	ctx := audit.TestContext()
	baseURL, system := node.StartServer(t, func(serverURL string) {
		t.Setenv("NUTS_VCR_OPENID4VCI_ENABLED", "true")
		t.Setenv("NUTS_HTTP_DEFAULT_TLS", string(httpModule.TLServerClientCertMode))
	})
	vcrService := system.FindEngineByName("vcr").(vcr.VCR)
	issuerDID := registerDID(t, system)
	// Set OpenID4VCI Wallet Identifier TLS resolver port to the server port generated by the test server
	parsedURL, _ := url.Parse(baseURL)
	serverPort, _ := strconv.Atoi(parsedURL.Port())
	openid4vci.SetTLSIdentifierResolverPort(t, serverPort)

	issuer, err := vcrService.GetOpenIDIssuer(ctx, issuerDID)

	require.NoError(t, err)
	require.NotNil(t, issuer)
	metadata := issuer.Metadata()
	require.NotNil(t, metadata)
}

// TestOpenID4VCIDisabled tests the issuer won't try to issue over OpenID4VCI when it's disabled.
func TestOpenID4VCIDisabled(t *testing.T) {
	baseURL, system := node.StartServer(t)

	// Setup issuer/holder
	walletDID := registerDID(t, system)
	registerBaseURL(t, baseURL, system, walletDID)

	t.Run("API returns 404", func(t *testing.T) {
		resp, err := http.Get(core.JoinURLPaths(baseURL, "n2n", "identity", url.PathEscape(walletDID.String()), openid4vci.WalletMetadataWellKnownPath))
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
		data, _ := io.ReadAll(resp.Body)
		assert.Equal(t, `{"detail":"openid4vci is disabled","status":404,"title":"Operation failed"}`, string(data))
	})
}

// TestOpenID4VCIErrorResponses tests the API returns the correct error responses (as specified in the OpenID4VCI spec, not as Problem types).
func TestOpenID4VCIErrorResponses(t *testing.T) {
	ctx := audit.TestContext()
	httpServerURL, system := node.StartServer(t, func(serverURL string) {
		t.Setenv("NUTS_VCR_OPENID4VCI_ENABLED", "true")
	})
	vcrService := system.FindEngineByName("vcr").(vcr.VCR)

	// Setup issuer/holder
	walletDID := registerDID(t, system)
	registerBaseURL(t, httpServerURL, system, walletDID)
	issuer, err := vcrService.GetOpenIDIssuer(ctx, walletDID)
	require.NoError(t, err)

	requestBody, _ := json.Marshal(openid4vci.CredentialRequest{
		Format: openid4vci.VerifiableCredentialJSONLDFormat,
	})

	t.Run("error from API layer (missing access token)", func(t *testing.T) {
		httpRequest, _ := http.NewRequest("POST", issuer.Metadata().CredentialEndpoint, bytes.NewReader(requestBody))
		httpRequest.Header.Set("Content-Type", "application/json")

		httpResponse, err := http.DefaultClient.Do(httpRequest)

		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, httpResponse.StatusCode)
		responseBody, _ := io.ReadAll(httpResponse.Body)
		assert.JSONEq(t, `{"error":"invalid_token"}`, string(responseBody))
	})
	t.Run("error from service layer (unknown access token)", func(t *testing.T) {
		httpRequest, _ := http.NewRequest("POST", issuer.Metadata().CredentialEndpoint, bytes.NewReader(requestBody))
		httpRequest.Header.Set("Content-Type", "application/json")
		httpRequest.Header.Set("Authentication", "Bearer not-a-valid-token")

		httpResponse, err := http.DefaultClient.Do(httpRequest)

		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, httpResponse.StatusCode)
		responseBody, _ := io.ReadAll(httpResponse.Body)
		assert.JSONEq(t, `{"error":"invalid_token"}`, string(responseBody))
	})
}

func testCredential() vc.VerifiableCredential {
	return vc.VerifiableCredential{
		Context: []ssi.URI{
			didservice.JWS2020ContextV1URI(),
			credentialTypes.NutsV1ContextURI,
		},
		Type: []ssi.URI{
			ssi.MustParseURI("NutsAuthorizationCredential"),
		},
		IssuanceDate: time.Now().Truncate(time.Second),
	}
}

func registerDID(t *testing.T, system *core.System) did.DID {
	vdrService := system.FindEngineByName("vdr").(vdrTypes.VDR)
	ctx := audit.TestContext()
	didDocument, _, err := vdrService.Create(ctx, didservice.DefaultCreationOptions())
	require.NoError(t, err)
	return didDocument.ID

}

func registerBaseURL(t *testing.T, httpServerURL string, system *core.System, id did.DID) {
	didmanService := system.FindEngineByName("didman").(didman.Didman)
	baseURL, _ := url.Parse(httpServerURL)
	_, err := didmanService.AddEndpoint(audit.TestContext(), id, vdrTypes.BaseURLServiceType, *baseURL)
	require.NoError(t, err)
}
