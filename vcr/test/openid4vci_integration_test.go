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
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/issuer"
	"github.com/nuts-foundation/nuts-node/vcr/openid4vci"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/node"
	"github.com/nuts-foundation/nuts-node/vcr"
	credentialTypes "github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/require"
)

// TestOpenID4VCIHappyFlow tests issuing a VC using OpenID4VCI.
func TestOpenID4VCIHappyFlow(t *testing.T) {
	auditLogs := audit.CaptureAuditLogs(t)
	ctx := audit.TestContext()
	_, baseURL, system := node.StartServer(t)
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
	issuedVC, err := vcrService.Issuer().Issue(ctx, credential, issuer.CredentialOptions{
		Publish: true,
		Public:  false,
	})

	require.NoError(t, err)
	require.NotNil(t, issuedVC)

	test.WaitFor(t, func() (bool, error) {
		return auditLogs.Contains(t, audit.VerifiableCredentialRetrievedEvent), nil
	}, 5*time.Second, "credential not retrieved by holder")
}

// TestOpenID4VCIDisabled tests the issuer won't try to issue over OpenID4VCI when it's disabled.
func TestOpenID4VCIDisabled(t *testing.T) {
	_, baseURL, system := node.StartServer(t, func(_, _ string) {
		t.Setenv("NUTS_VCR_OPENID4VCI_ENABLED", "false")
	})

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
	t.Run("Issues over network", func(t *testing.T) {
		credential := testCredential()
		credential.Issuer = walletDID.URI()
		credential.ID, _ = ssi.ParseURI(walletDID.URI().String() + "#1")
		credential.CredentialSubject = append(credential.CredentialSubject, map[string]interface{}{
			"id":           walletDID.URI().String(),
			"purposeOfUse": "test",
		})

		vcrService := system.FindEngineByName("vcr").(vcr.VCR)
		_, err := vcrService.Issuer().Issue(audit.TestContext(), credential, issuer.CredentialOptions{
			Publish: true,
			Public:  false,
		})

		assert.ErrorContains(t, err, "unable to publish the issued credential")
	})
}

// TestOpenID4VCIErrorResponses tests the API returns the correct error responses (as specified in the OpenID4VCI spec, not as Problem types).
func TestOpenID4VCIErrorResponses(t *testing.T) {
	ctx := audit.TestContext()
	_, httpServerURL, system := node.StartServer(t)
	vcrService := system.FindEngineByName("vcr").(vcr.VCR)

	// Setup issuer/holder
	walletDID := registerDID(t, system)
	registerBaseURL(t, httpServerURL, system, walletDID)
	issuer, err := vcrService.GetOpenIDIssuer(ctx, walletDID)
	require.NoError(t, err)

	requestBody, _ := json.Marshal(openid4vci.CredentialRequest{
		Format: vc.JSONLDCredentialProofFormat,
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
	issuanceDate := time.Now().Truncate(time.Second)
	return vc.VerifiableCredential{
		Context: []ssi.URI{
			jsonld.JWS2020ContextV1URI(),
			credentialTypes.NutsV1ContextURI,
		},
		Type: []ssi.URI{
			ssi.MustParseURI("NutsAuthorizationCredential"),
		},
		IssuanceDate: issuanceDate,
	}
}

func registerDID(t *testing.T, system *core.System) did.DID {
	vdrService := system.FindEngineByName("vdr").(didsubject.Manager)
	ctx := audit.TestContext()
	didDocument, _, err := vdrService.Create(ctx, didsubject.DefaultCreationOptions().With(didsubject.NutsLegacyNamingOption{}))
	require.NoError(t, err)
	return didDocument[0].ID

}

func registerBaseURL(t *testing.T, httpServerURL string, system *core.System, id did.DID) {
	subjectManager := system.FindEngineByName("vdr").(didsubject.Manager)
	baseURL, _ := url.Parse(httpServerURL)
	_, err := subjectManager.CreateService(audit.TestContext(), id.String(), did.Service{Type: resolver.BaseURLServiceType, ServiceEndpoint: baseURL.String()})
	require.NoError(t, err)
}
