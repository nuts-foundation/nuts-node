//go:build e2e_tests

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

package openid4vp_employeecredential

import (
	"github.com/chromedp/chromedp"
	"github.com/nuts-foundation/go-did/did"
	iamAPI "github.com/nuts-foundation/nuts-node/auth/api/iam"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/e2e-tests/browser"
	"github.com/nuts-foundation/nuts-node/e2e-tests/browser/rfc019_selfsigned/apps"
	didAPI "github.com/nuts-foundation/nuts-node/vdr/api/v2"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

var nodeClientConfig = core.ClientConfig{Address: "http://localhost:8081"}

func init() {
	os.Setenv("SHOW_BROWSER", "true")
	os.Setenv("KEEP_BROWSER_OPEN", "true")
}

func Test_UserAccessToken_EmployeeCredential(t *testing.T) {
	const oauth2Scope = "zorgtoepassing"

	headless := os.Getenv("SHOW_BROWSER") != "true"
	ctx, cancel := browser.NewChrome(headless)
	defer func() {
		if t.Failed() && !headless {
			duration := time.Minute
			t.Logf("Test failed, keeping browser open for %s", duration)
			time.Sleep(duration)
		}
		cancel()
	}()

	verifyingOrganization, err := createDID("verifier")
	require.NoError(t, err)
	err = browser.IssueOrganizationCredential(verifyingOrganization, "Verifying Organization", "Testland")
	require.NoError(t, err)

	requesterOrganization, err := createDID("requester")
	require.NoError(t, err)
	err = browser.IssueOrganizationCredential(requesterOrganization, "Requesting Organization", "Testland")
	require.NoError(t, err)

	iamClient, err := iamAPI.NewClient(nodeClientConfig.GetAddress())
	require.NoError(t, err)
	openid4vp := OpenID4VP{
		ctx:       ctx,
		iamClient: iamClient,
	}
	err = chromedp.Run(ctx, chromedp.Navigate("about:blank"))
	require.NoError(t, err)
	// Request an access token with user from verifying organization
	userDetails := iamAPI.UserDetails{
		Id:   "jdoe@example.com",
		Name: "John Doe",
		Role: "Accountant",
	}
	redirectSession, err := openid4vp.RequesterUserAccessToken(requesterOrganization.ID, verifyingOrganization.ID, userDetails, oauth2Scope)
	require.NoError(t, err)
	// Navigate browser to redirect URL, which performs the OAuth2 authorization code flow
	err = chromedp.Run(ctx, chromedp.Navigate(redirectSession.RedirectUri))
	require.NoError(t, err)
	// The browser was now successfully redirected back to the redirect URI (actually the node's public / URL),
	// indicating the flow was successful. We can now retrieve the access token.
	accessToken, err := openid4vp.RetrieveAccessToken(redirectSession.SessionId)
	require.NoError(t, err)
	// In a real-world scenario, this client would now use the access token to request some resources.
	// We just introspect the access token (which we can since Client and Authorization Server are the same Nuts node),
	// to verify the access token.
	tokenInfo, err := openid4vp.IntrospectAccessToken(accessToken)
	require.NoError(t, err)
	require.True(t, tokenInfo.Active)
	require.Equal(t, oauth2Scope, *tokenInfo.Scope)
	// Note to reviewer: audience is empty?
	require.Equal(t, requesterOrganization.ID.String(), *tokenInfo.ClientId)
	require.Equal(t, verifyingOrganization.ID.String(), *tokenInfo.Iss)
	// Note to reviewer: is "sub" right?
	require.Equal(t, verifyingOrganization.ID.String(), *tokenInfo.Sub)
	require.NotEmpty(t, tokenInfo.Exp)
	require.NotEmpty(t, tokenInfo.Iat)
	// Check the mapped input descriptor fields: for organization credential and employee credential
	require.NotEmpty(t, tokenInfo.AdditionalProperties)
	require.Equal(t, "Requesting Organization", tokenInfo.AdditionalProperties["organization_name"].(string))
	require.Equal(t, "Testland", tokenInfo.AdditionalProperties["organization_city"].(string))
	require.Equal(t, "jdoe@example.com", tokenInfo.AdditionalProperties["employee_identifier"].(string))
	require.Equal(t, "John Doe", tokenInfo.AdditionalProperties["employee_name"].(string))
	require.Equal(t, "Accountant", tokenInfo.AdditionalProperties["employee_role"].(string))

	if os.Getenv("KEEP_BROWSER_OPEN") == "true" {
		timeout := time.Minute
		t.Logf("Keeping browser open for %s", timeout)
		time.Sleep(timeout)
	}
}

func createDID(id string) (*did.Document, error) {
	didClient := didAPI.HTTPClient{ClientConfig: apps.NodeClientConfig}
	return didClient.Create(didAPI.CreateDIDOptions{Tenant: &id})
}
