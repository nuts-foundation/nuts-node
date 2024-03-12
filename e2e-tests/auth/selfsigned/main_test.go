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

package selfsigned

import (
	"github.com/nuts-foundation/go-did/did"
	didmanAPI "github.com/nuts-foundation/nuts-node/didman/api/v1"
	"github.com/nuts-foundation/nuts-node/e2e-tests/auth/selfsigned/apps"
	"github.com/nuts-foundation/nuts-node/e2e-tests/auth/selfsigned/browser"
	vcrAPI "github.com/nuts-foundation/nuts-node/vcr/api/vcr/v2"
	didAPI "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func Test_LoginWithSelfSignedMeans(t *testing.T) {
	const purposeOfUse = "zorgtoepassing"

	headless := os.Getenv("SHOW_BROWSER") != "true"
	ctx, cancel := browser.NewChrome(headless)
	defer func() {
		if t.Failed() && !headless {
			duration := 10 * time.Second
			t.Logf("Test failed, keeping browser open for %s", duration)
			time.Sleep(duration)
		}
		cancel()
	}()

	verifyingOrganization, err := createDID()
	require.NoError(t, err)
	err = registerCompoundService(verifyingOrganization.ID, purposeOfUse)
	require.NoError(t, err)
	err = issueOrganizationCredential(verifyingOrganization, "Verifying Organization", "Testland")
	require.NoError(t, err)

	issuingOrganization, err := createDID()
	require.NoError(t, err)
	err = registerCompoundService(issuingOrganization.ID, purposeOfUse)
	require.NoError(t, err)
	err = issueOrganizationCredential(issuingOrganization, "Issuing Organization", "Testland")
	require.NoError(t, err)

	selfSigned := apps.SelfSigned{
		URL:     "http://localhost:8081",
		Context: ctx,
	}
	roleName := "Soulpeeker"
	employeeInfo := apps.EmployeeInfo{
		Identifier: "jdoe@example.com",
		Initials:   "J",
		FamilyName: "Doe",
		RoleName:   &roleName,
	}
	// Start a self-signed session
	session, err := selfSigned.Start(issuingOrganization.ID.String(), employeeInfo)
	require.NoError(t, err)
	require.Equal(t, employeeInfo.Identifier, session.EmployeeIdentifier)
	require.Equal(t, employeeInfo.Initials+" "+employeeInfo.FamilyName, session.EmployeeName)
	require.Equal(t, *employeeInfo.RoleName, session.EmployeeRole)

	// Accept
	acceptedText, err := selfSigned.Accept()
	require.NoError(t, err)
	require.Equal(t, "De identificatie is voltooid.", acceptedText)

	// Check resulting VP
	status, presentation, err := selfSigned.GetSessionStatus(session.ID)
	require.NoError(t, err)
	require.Equal(t, "completed", status)
	require.Equal(t, "NutsSelfSignedPresentation", presentation.Type[1].String())
	require.Equal(t, issuingOrganization.ID.String(), presentation.VerifiableCredential[0].Issuer.String())

	// Issue #2428: Issuer of NutsEmployeeCredential should not need to be trusted
	// It's automatically trusted on issuance, and we've got a single node, so we're untrusting it.
	err = selfSigned.UntrustEmployeeCredential(issuingOrganization.ID.String())
	require.NoError(t, err)

	// Now request an access token
	accessToken, err := selfSigned.RequestAccessToken(issuingOrganization.ID.String(), verifyingOrganization.ID.String(), purposeOfUse, presentation)
	require.NoError(t, err)
	assert.Equal(t, "zorgtoepassing", *accessToken.Service)
	assert.Equal(t, "J", *accessToken.Initials)
	assert.Equal(t, "Doe", *accessToken.FamilyName)
	assert.Equal(t, "Soulpeeker", *accessToken.UserRole)
	assert.Equal(t, "jdoe@example.com", *accessToken.Username)
	assert.Equal(t, "low", string(*accessToken.AssuranceLevel))

	if os.Getenv("KEEP_BROWSER_OPEN") == "true" {
		timeout := time.Minute
		t.Logf("Keeping browser open for %s", timeout)
		time.Sleep(timeout)
	}
}

func issueOrganizationCredential(organization *did.Document, name, city string) error {
	vcrClient := vcrAPI.HTTPClient{ClientConfig: apps.NodeClientConfig}
	visibility := vcrAPI.Public
	request := vcrAPI.IssueVCRequest{
		Issuer: organization.ID.String(),
		CredentialSubject: map[string]interface{}{
			"id": organization.ID.String(),
			"organization": map[string]interface{}{
				"name": name,
				"city": city,
			},
		},
		Visibility: &visibility,
	}
	err := request.Type.FromIssueVCRequestType1([]any{"VerifiableCredential", "NutsOrganizationCredential"})
	if err != nil {
		return err
	}
	_, err = vcrClient.IssueVC(request)
	return err
}

func registerCompoundService(id did.DID, compoundServiceType string) error {
	client := didmanAPI.HTTPClient{ClientConfig: apps.NodeClientConfig}
	_, err := client.AddCompoundService(id.String(), compoundServiceType, map[string]string{
		"oauth": apps.PublicNodeAddress + "/n2n/auth/v1/accesstoken",
	})
	return err
}

func createDID() (*did.Document, error) {
	didClient := didAPI.HTTPClient{ClientConfig: apps.NodeClientConfig}
	return didClient.Create(didAPI.DIDCreateRequest{})
}
