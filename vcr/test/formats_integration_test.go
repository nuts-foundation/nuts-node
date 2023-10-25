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
	"context"
	"encoding/json"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/test/node"
	"github.com/nuts-foundation/nuts-node/vcr"
	v2 "github.com/nuts-foundation/nuts-node/vcr/api/vcr/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCredentialFormats tests issuing and verifying different VC.
func TestCredentialFormats(t *testing.T) {
	ctx := audit.TestContext()
	_, system := node.StartServer(t)

	issuerDID := registerDID(t, system)
	subjectDID := registerDID(t, system)
	publish := false
	credentialRequestTemplate := v2.IssueVCRequest{
		Type: "NutsOrganizationCredential",
		CredentialSubject: map[string]interface{}{
			"id": subjectDID.String(),
			"organization": map[string]interface{}{
				"name": "Nuts Foundation",
				"city": "Notendam",
			},
		},
		Issuer:           issuerDID.String(),
		PublishToNetwork: &publish,
	}
	vcrAPI := v2.Wrapper{VCR: system.FindEngineByName("vcr").(vcr.VCR)}

	t.Run("VC in JSON-LD format", func(t *testing.T) {
		// Issuance
		credentialRequest := credentialRequestTemplate
		credential := issueVC(t, vcrAPI, ctx, credentialRequest)
		assert.True(t, strings.HasPrefix(credential.Raw(), "{"), "expected JSON-LD VC response")
		// Verification
		verifyVC(t, ctx, credential, vcrAPI)
	})
	t.Run("VC in JWT format", func(t *testing.T) {
		// Issuance
		var format v2.IssueVCRequestFormat = "jwt_vc"
		credentialRequest := credentialRequestTemplate
		credentialRequest.Format = &format
		credential := issueVC(t, vcrAPI, ctx, credentialRequest)
		assert.True(t, strings.HasPrefix(credential.Raw(), `ey`), "expected JWT VC response")
		// Verification
		verifyVC(t, ctx, credential, vcrAPI)
	})
	t.Run("VP in JSON-LD format, containing VC in JSON-LD format", func(t *testing.T) {
		credential := issueVC(t, vcrAPI, ctx, credentialRequestTemplate)
		// Issuance
		presentation := createVP(t, ctx, credential, "", vcrAPI) // empty string = default format
		assert.True(t, strings.HasPrefix(presentation.Raw(), "{"), "expected JSON-LD VP response")
		assert.True(t, strings.HasPrefix(presentation.VerifiableCredential[0].Raw(), "{"), "expected JSON-LD VC in VP response")
		// Verification
		verifyVP(t, ctx, presentation, vcrAPI)
	})
	t.Run("VP in JSON-LD format, containing VC in JWT format", func(t *testing.T) {
		var format v2.IssueVCRequestFormat = "jwt_vc"
		credentialRequest := credentialRequestTemplate
		credentialRequest.Format = &format
		credential := issueVC(t, vcrAPI, ctx, credentialRequest)
		// Issuance
		presentation := createVP(t, ctx, credential, "", vcrAPI) // empty string = default format
		assert.True(t, strings.HasPrefix(presentation.Raw(), "{"), "expected JSON-LD VP response")
		assert.True(t, strings.HasPrefix(presentation.VerifiableCredential[0].Raw(), "ey"), "expected JWT VC in VP response")
		// Verification
		verifyVP(t, ctx, presentation, vcrAPI)
	})
	t.Run("VP in JWT format, containing VC in JWT format", func(t *testing.T) {
		var format v2.IssueVCRequestFormat = "jwt_vc"
		credentialRequest := credentialRequestTemplate
		credentialRequest.Format = &format
		credential := issueVC(t, vcrAPI, ctx, credentialRequest)
		// Issuance
		presentation := createVP(t, ctx, credential, vc.JWTPresentationProofFormat, vcrAPI)
		assert.True(t, strings.HasPrefix(presentation.Raw(), "ey"), "expected JWT VP response")
		assert.True(t, strings.HasPrefix(presentation.VerifiableCredential[0].Raw(), "ey"), "expected JWT VC in VP response")
		// Verification
		verifyVP(t, ctx, presentation, vcrAPI)
	})
	t.Run("VP in JWT format, containing VC in JSON-LD format", func(t *testing.T) {
		credential := issueVC(t, vcrAPI, ctx, credentialRequestTemplate)
		// Issuance
		presentation := createVP(t, ctx, credential, vc.JWTPresentationProofFormat, vcrAPI)
		assert.True(t, strings.HasPrefix(presentation.Raw(), "ey"), "expected JWT VP response")
		assert.True(t, strings.HasPrefix(presentation.VerifiableCredential[0].Raw(), "{"), "expected JWT VC in VP response")
		// Verification
		verifyVP(t, ctx, presentation, vcrAPI)
	})
}

func createVP(t *testing.T, ctx context.Context, credential v2.VerifiableCredential, format string, vcrAPI v2.Wrapper) vc.VerifiablePresentation {
	request := v2.CreateVPJSONRequestBody{
		VerifiableCredentials: []v2.VerifiableCredential{credential},
	}
	if format != "" {
		f := v2.CreateVPRequestFormat(format)
		request.Format = &f
	}
	response, err := vcrAPI.CreateVP(ctx, v2.CreateVPRequestObject{Body: &request})
	require.NoError(t, err)
	httpResponse := httptest.NewRecorder()
	require.NoError(t, response.VisitCreateVPResponse(httpResponse))
	var result vc.VerifiablePresentation
	err = json.Unmarshal(httpResponse.Body.Bytes(), &result)
	require.NoError(t, err)
	return result
}

func issueVC(t *testing.T, vcrAPI v2.Wrapper, ctx context.Context, credentialRequest v2.IssueVCRequest) v2.VerifiableCredential {
	response, err := vcrAPI.IssueVC(ctx, v2.IssueVCRequestObject{Body: &credentialRequest})
	require.NoError(t, err)
	httpResponse := httptest.NewRecorder()
	require.NoError(t, response.VisitIssueVCResponse(httpResponse))
	var credential v2.VerifiableCredential
	err = json.Unmarshal(httpResponse.Body.Bytes(), &credential)
	require.NoError(t, err)
	return credential
}

func verifyVC(t *testing.T, ctx context.Context, credential vc.VerifiableCredential, vcrAPI v2.Wrapper) {
	verifyResponse, err := vcrAPI.VerifyVC(ctx, v2.VerifyVCRequestObject{Body: &v2.VerifyVCJSONRequestBody{
		VerifiableCredential: credential,
	}})
	require.NoError(t, err)
	assert.True(t, verifyResponse.(v2.VerifyVC200JSONResponse).Validity)
	if !assert.Nil(t, verifyResponse.(v2.VerifyVC200JSONResponse).Message) {
		t.Log(*(verifyResponse.(v2.VerifyVC200JSONResponse).Message))
	}
}

func verifyVP(t *testing.T, ctx context.Context, presentation vc.VerifiablePresentation, vcrAPI v2.Wrapper) {
	verifyResponse, err := vcrAPI.VerifyVP(ctx, v2.VerifyVPRequestObject{Body: &v2.VerifyVPJSONRequestBody{
		VerifiablePresentation: presentation,
	}})
	require.NoError(t, err)
	assert.True(t, verifyResponse.(v2.VerifyVP200JSONResponse).Validity)
	assert.Nil(t, verifyResponse.(v2.VerifyVP200JSONResponse).Message)
}
