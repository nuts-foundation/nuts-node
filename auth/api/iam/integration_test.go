/*
 * Copyright (C) 2026 Nuts community
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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nuts-foundation/nuts-node/auth/oauth"
	"github.com/nuts-foundation/nuts-node/policy"
	"github.com/nuts-foundation/nuts-node/policy/authzen"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestIntegration_DynamicScopePolicy_AuthZenEndToEnd exercises the server-side token handler
// with a real AuthZen HTTP client talking to an httptest server. Unlike the unit tests in
// s2s_vptoken_test.go which mock the AuthZen evaluator directly, this test validates the
// full HTTP roundtrip: request serialization, response parsing, and error propagation.
func TestIntegration_DynamicScopePolicy_AuthZenEndToEnd(t *testing.T) {
	// Shared fixtures
	var presentationDefinition pe.PresentationDefinition
	require.NoError(t, json.Unmarshal([]byte(`{
		"format": {
			"ldp_vc": {"proof_type": ["JsonWebSignature2020"]}
		},
		"input_descriptors": [{
			"id": "1",
			"constraints": {
				"fields": [{
					"path": ["$.type"],
					"filter": {"type": "string", "const": "NutsOrganizationCredential"}
				}]
			}
		}]
	}`), &presentationDefinition))
	walletOwnerMapping := pe.WalletOwnerMapping{pe.WalletOwnerOrganization: presentationDefinition}

	var submission pe.PresentationSubmission
	require.NoError(t, json.Unmarshal([]byte(`{
		"descriptor_map": [{"id": "1", "path": "$.verifiableCredential", "format": "ldp_vc"}]
	}`), &submission))
	submissionJSONBytes, _ := json.Marshal(submission)
	submissionJSON := string(submissionJSONBytes)

	verifiableCredential := test.ValidNutsOrganizationCredential(t)
	subjectDID, _ := verifiableCredential.SubjectDID()
	proofVisitor := test.LDProofVisitor(func(p *proof.LDProof) {
		p.Domain = &issuerClientID
	})
	presentation := test.CreateJSONLDPresentation(t, *subjectDID, proofVisitor, verifiableCredential)

	dpopHeader, _, _ := newSignedTestDPoP()
	httpRequest := &http.Request{Header: http.Header{"Dpop": []string{dpopHeader.String()}}}
	contextWithValue := context.WithValue(context.Background(), httpRequestContextKey{}, httpRequest)
	clientID := "https://example.com/oauth2/holder"

	t.Run("PDP approves all scopes - token issued with all scopes", func(t *testing.T) {
		var receivedRequest authzen.EvaluationsRequest
		pdpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/access/v1/evaluations", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			require.NoError(t, json.NewDecoder(r.Body).Decode(&receivedRequest))

			resp := authzen.EvaluationsResponse{
				Evaluations: []authzen.EvaluationResult{
					{Decision: true},
					{Decision: true},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer pdpServer.Close()

		realAuthzenClient := authzen.NewClient(pdpServer.URL, http.DefaultClient)

		ctx := newTestClient(t)
		ctx.vcVerifier.EXPECT().VerifyVP(gomock.Any(), true, true, gomock.Any()).Return(presentation.VerifiableCredential, nil)
		ctx.policy.EXPECT().FindCredentialProfile(gomock.Any(), "example-scope extra-scope").Return(&policy.CredentialProfileMatch{
			CredentialProfileScope: "example-scope",
			WalletOwnerMapping:     walletOwnerMapping,
			ScopePolicy:            policy.ScopePolicyDynamic,
			OtherScopes:            []string{"extra-scope"},
		}, nil)
		ctx.policy.EXPECT().AuthZenEvaluator().Return(realAuthzenClient)

		resp, err := ctx.client.handleS2SAccessTokenRequest(contextWithValue, clientID, issuerSubjectID, "example-scope extra-scope", submissionJSON, presentation.Raw())

		require.NoError(t, err)
		tokenResponse := TokenResponse(resp.(HandleTokenRequest200JSONResponse))
		assert.Equal(t, "example-scope extra-scope", *tokenResponse.Scope)

		// Verify the PDP received a well-formed request via actual HTTP roundtrip
		assert.Equal(t, "organization", receivedRequest.Subject.Type)
		assert.Equal(t, "request_scope", receivedRequest.Action.Name)
		assert.Equal(t, "example-scope", receivedRequest.Context.Policy)
		require.Len(t, receivedRequest.Evaluations, 2)
		assert.Equal(t, "scope", receivedRequest.Evaluations[0].Resource.Type)
		assert.Equal(t, "example-scope", receivedRequest.Evaluations[0].Resource.ID)
		assert.Equal(t, "extra-scope", receivedRequest.Evaluations[1].Resource.ID)
	})

	t.Run("PDP partial denial - denied scopes excluded from token", func(t *testing.T) {
		pdpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := authzen.EvaluationsResponse{
				Evaluations: []authzen.EvaluationResult{
					{Decision: true},
					{Decision: false, Context: &authzen.EvaluationResultContext{Reason: "not permitted"}},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(resp)
		}))
		defer pdpServer.Close()
		realAuthzenClient := authzen.NewClient(pdpServer.URL, http.DefaultClient)

		ctx := newTestClient(t)
		ctx.vcVerifier.EXPECT().VerifyVP(gomock.Any(), true, true, gomock.Any()).Return(presentation.VerifiableCredential, nil)
		ctx.policy.EXPECT().FindCredentialProfile(gomock.Any(), "example-scope extra-scope").Return(&policy.CredentialProfileMatch{
			CredentialProfileScope: "example-scope",
			WalletOwnerMapping:     walletOwnerMapping,
			ScopePolicy:            policy.ScopePolicyDynamic,
			OtherScopes:            []string{"extra-scope"},
		}, nil)
		ctx.policy.EXPECT().AuthZenEvaluator().Return(realAuthzenClient)

		resp, err := ctx.client.handleS2SAccessTokenRequest(contextWithValue, clientID, issuerSubjectID, "example-scope extra-scope", submissionJSON, presentation.Raw())

		require.NoError(t, err)
		tokenResponse := TokenResponse(resp.(HandleTokenRequest200JSONResponse))
		assert.Equal(t, "example-scope", *tokenResponse.Scope)
	})

	t.Run("PDP returns HTTP 500 - server_error", func(t *testing.T) {
		pdpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer pdpServer.Close()
		realAuthzenClient := authzen.NewClient(pdpServer.URL, http.DefaultClient)

		ctx := newTestClient(t)
		ctx.vcVerifier.EXPECT().VerifyVP(gomock.Any(), true, true, gomock.Any()).Return(presentation.VerifiableCredential, nil)
		ctx.policy.EXPECT().FindCredentialProfile(gomock.Any(), "example-scope extra-scope").Return(&policy.CredentialProfileMatch{
			CredentialProfileScope: "example-scope",
			WalletOwnerMapping:     walletOwnerMapping,
			ScopePolicy:            policy.ScopePolicyDynamic,
			OtherScopes:            []string{"extra-scope"},
		}, nil)
		ctx.policy.EXPECT().AuthZenEvaluator().Return(realAuthzenClient)

		resp, err := ctx.client.handleS2SAccessTokenRequest(contextWithValue, clientID, issuerSubjectID, "example-scope extra-scope", submissionJSON, presentation.Raw())

		_ = assertOAuthErrorWithCode(t, err, oauth.ServerError, "policy decision point unavailable")
		assert.Nil(t, resp)
	})
}
