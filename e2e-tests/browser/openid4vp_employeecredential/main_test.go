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
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/e2e-tests/browser"
	iamAPI "github.com/nuts-foundation/nuts-node/e2e-tests/browser/client/iam"
	didAPI "github.com/nuts-foundation/nuts-node/vdr/api/v2"
	"github.com/stretchr/testify/require"
)

var nodeAClientConfig = core.ClientConfig{Address: "http://localhost:18081"}
var nodeBClientConfig = core.ClientConfig{Address: "http://localhost:28081"}

func init() {
	// uncomment this to get feedback during development
	// os.Setenv("SHOW_BROWSER", "true")
	// os.Setenv("KEEP_BROWSER_OPEN", "true")
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

	didVerifier, openid4vpClientA := setupNode(t, ctx, nodeAClientConfig)
	didRequester, openid4vpClientB := setupNode(t, ctx, nodeBClientConfig)
	err := chromedp.Run(ctx, chromedp.Navigate("about:blank"))
	require.NoError(t, err)
	// Request an access token with user from verifying organization
	userDetails := iamAPI.UserDetails{
		Id:   "jdoe@example.com",
		Name: "John Doe",
		Role: "Accountant",
	}
	redirectSession, err := openid4vpClientB.RequesterUserAccessToken(didRequester, didVerifier, userDetails, oauth2Scope)
	require.NoError(t, err)
	// Navigate browser to redirect URL, which performs the OAuth2 authorization code flow
	err = chromedp.Run(ctx, chromedp.Navigate(redirectSession.RedirectUri))
	require.NoError(t, err)
	// The browser was now successfully redirected back to the redirect URI (actually the node's public / URL),
	// indicating the flow was successful. We can now retrieve the access token.
	accessToken, err := openid4vpClientB.RetrieveAccessToken(redirectSession.SessionId)
	require.NoError(t, err)
	// In a real-world scenario, this client would now use the access token to request some resources.
	// We just introspect the access token (which we can since Client and Authorization Server are the same Nuts node),
	// to verify the access token.
	tokenInfo, err := openid4vpClientA.IntrospectAccessToken(accessToken)
	require.NoError(t, err)
	require.True(t, tokenInfo.Active)
	require.Equal(t, oauth2Scope, *tokenInfo.Scope)
	// Note to reviewer: audience is empty?
	require.Equal(t, didRequester.String(), *tokenInfo.ClientId)
	require.Equal(t, didVerifier.String(), *tokenInfo.Iss)
	// Note to reviewer: is "sub" right?
	require.Equal(t, didVerifier.String(), *tokenInfo.Sub)
	require.NotEmpty(t, tokenInfo.Exp)
	require.NotEmpty(t, tokenInfo.Iat)
	// Check the mapped input descriptor fields: for organization credential and employee credential
	require.NotEmpty(t, tokenInfo.AdditionalProperties)
	require.Equal(t, fmt.Sprintf("%s Organization", didRequester.String()), tokenInfo.AdditionalProperties["organization_name"].(string))
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

func setupNode(t testing.TB, ctx context.Context, config core.ClientConfig) (did.DID, OpenID4VP) {
	didDoc, err := createDID(config)
	require.NoError(t, err)
	err = browser.IssueOrganizationCredential(didDoc, fmt.Sprintf("%s Organization", didDoc.ID.String()), "Testland", config)
	require.NoError(t, err)

	iamClientB, err := iamAPI.NewClient(config.GetAddress())
	require.NoError(t, err)
	openid4vp := OpenID4VP{
		ctx:       ctx,
		iamClient: iamClientB,
	}
	return didDoc.ID, openid4vp
}

func createDID(config core.ClientConfig) (*did.Document, error) {
	didClient := didAPI.HTTPClient{ClientConfig: config}
	return didClient.Create(didAPI.CreateDIDOptions{})
}
