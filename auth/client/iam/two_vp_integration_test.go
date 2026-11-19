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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/url"
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/v6/audit"
	"github.com/nuts-foundation/nuts-node/v6/auth/oauth"
	"github.com/nuts-foundation/nuts-node/v6/core"
	"github.com/nuts-foundation/nuts-node/v6/crypto"
	"github.com/nuts-foundation/nuts-node/v6/jsonld"
	"github.com/nuts-foundation/nuts-node/v6/policy"
	"github.com/nuts-foundation/nuts-node/v6/storage/orm"
	"github.com/nuts-foundation/nuts-node/v6/vcr/holder"
	"github.com/nuts-foundation/nuts-node/v6/vcr/pe"
	"github.com/nuts-foundation/nuts-node/v6/vdr/resolver"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestRequestServiceAccessToken_TwoVP_SharedFieldIDs runs the jwt-bearer two-VP token request with the real pieces:
// the policy file is loaded by the policy module (test/two_vp_field_ids/policy.json), and both VPs are selected and
// signed by a real (in-memory) wallet. Only the network (authorization server metadata and token endpoint, served by
// a test server), the DIDs of the subjects and the key lookup are stubbed.
//
// The organization and service_provider PDs of the fixture share the field id "ura": a field id names one value
// across the token request, so the service provider's delegation must be the one of the organization that is
// presented in the organization VP. "organization_name" and "organization_city" are only declared by the
// organization PD, "role" only by the service_provider PD.
func TestRequestServiceAccessToken_TwoVP_SharedFieldIDs(t *testing.T) {
	const scope = "two-vp-integration"
	const organizationSubjectID = "organization"
	const serviceProviderSubjectID = "service-provider"
	organizationDID := did.MustParseDID("did:test:organization")
	serviceProviderDID := did.MustParseDID("did:test:service-provider")
	auditContext := audit.TestContext()

	// The policy is loaded the way the node loads it at startup, which includes the field id validation.
	pdp := policy.New()
	pdp.Config().(*policy.Config).Directory = "test/two_vp_field_ids"
	require.NoError(t, pdp.Configure(core.ServerConfig{}))
	profile, err := pdp.FindCredentialProfile(context.Background(), scope)
	require.NoError(t, err)
	organizationPD := profile.WalletOwnerMapping[pe.WalletOwnerOrganization]

	// Signing keys for both subjects, so the wallet produces real signed VPs.
	keyStorage := crypto.NewMemoryStorage()
	keyStore := crypto.NewTestCryptoInstance(orm.NewTestDatabase(t), keyStorage)
	keyIDs := map[did.DID]string{}
	for _, subjectDID := range []did.DID{organizationDID, serviceProviderDID} {
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		keyID := subjectDID.String() + "#1"
		require.NoError(t, keyStorage.SavePrivateKey(auditContext, keyID, privateKey))
		require.NoError(t, keyStore.Link(auditContext, keyID, keyID, "1"))
		keyIDs[subjectDID] = keyID
	}
	documentLoader := jsonld.NewTestJSONLDManager(t).DocumentLoader()

	newCredential := func(id string, credentialType string, subject string) vc.VerifiableCredential {
		result, err := vc.ParseVerifiableCredential(`{
			"@context": ["https://www.w3.org/2018/credentials/v1"],
			"type": ["VerifiableCredential", "` + credentialType + `"],
			"id": "` + id + `",
			"issuer": "did:test:issuer",
			"issuanceDate": "2026-01-01T00:00:00Z",
			"credentialSubject": ` + subject + `
		}`)
		require.NoError(t, err)
		return *result
	}
	organizationA := newCredential("urn:organization:a", "HealthcareProviderCredential",
		`{"id": "did:test:organization", "ura": "1", "name": "Org A", "city": "Amsterdam"}`)
	organizationB := newCredential("urn:organization:b", "HealthcareProviderCredential",
		`{"id": "did:test:organization", "ura": "2", "name": "Org B", "city": "Utrecht"}`)
	delegation := func(id string, ura string, role string) vc.VerifiableCredential {
		return newCredential(id, "ServiceProviderDelegationCredential",
			`{"id": "did:test:service-provider", "delegatedBy": "`+ura+`", "role": "`+role+`"}`)
	}

	type testContext struct {
		*clientServerTestContext
		// tokenRequest is the form posted to the token endpoint, nil when no token request was sent.
		tokenRequest url.Values
	}
	// setup returns a client whose wallets hold the given credentials. Unless expectWalletUse is false, the subjects'
	// DIDs can be listed; when it is false, listing them (which precedes building any VP) fails the test.
	setup := func(t *testing.T, organizationWallet []vc.VerifiableCredential, serviceProviderWallet []vc.VerifiableCredential, expectWalletUse bool) *testContext {
		ctx := &testContext{clientServerTestContext: createClientServerTestContext(t)}
		ctx.authzServerMetadata.GrantTypesSupported = []string{oauth.JwtBearerGrantType}
		ctx.token = func(writer http.ResponseWriter, request *http.Request) {
			require.NoError(t, request.ParseForm())
			ctx.tokenRequest = request.PostForm
			writer.Header().Add("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			_, _ = writer.Write([]byte(`{"access_token": "token", "token_type": "bearer"}`))
		}
		keyResolver := resolver.NewMockKeyResolver(ctx.ctrl)
		keyResolver.EXPECT().ResolveKey(gomock.Any(), nil, resolver.NutsSigningKeyType).
			DoAndReturn(func(id did.DID, _ interface{}, _ resolver.RelationType) (string, interface{}, error) {
				return keyIDs[id], nil, nil
			}).AnyTimes()
		if expectWalletUse {
			ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), organizationSubjectID).Return([]did.DID{organizationDID}, nil).AnyTimes()
			ctx.subjectManager.EXPECT().ListDIDs(gomock.Any(), serviceProviderSubjectID).Return([]did.DID{serviceProviderDID}, nil).AnyTimes()
		}
		client := ctx.client.(*OpenID4VPClient)
		client.experimentalJwtBearerClient = true
		client.policyBackend = pdp
		client.pdResolver.policyBackend = pdp
		client.wallet = holder.NewMemoryWallet(documentLoader, keyResolver, keyStore, map[did.DID][]vc.VerifiableCredential{
			organizationDID:    organizationWallet,
			serviceProviderDID: serviceProviderWallet,
		})
		return ctx
	}
	requestToken := func(ctx *testContext, selection map[string]string) error {
		serviceProviderSubject := serviceProviderSubjectID
		_, err := ctx.client.RequestServiceAccessToken(auditContext, "", organizationSubjectID, ctx.verifierURL.String(), scope, false, nil, selection, &serviceProviderSubject)
		return err
	}
	credentialIDs := func(t *testing.T, rawPresentation string) []string {
		presentation, err := vc.ParseVerifiablePresentation(rawPresentation)
		require.NoError(t, err)
		var result []string
		for _, credential := range presentation.VerifiableCredential {
			result = append(result, credential.ID.String())
		}
		return result
	}
	// verifyOrganizationVP checks the organization VP the way a verifier checks a presentation against the organization
	// PD, and returns the field values a verifier resolves from it. The jwt-bearer request carries no presentation
	// submission (the receiving side of the two-VP flow is not implemented yet), so the credentials are mapped by
	// matching them against the PD; the mapping is then validated and the field values resolved, which rejects
	// differing values for one field id.
	verifyOrganizationVP := func(t *testing.T, rawPresentation string) map[string]interface{} {
		presentation, err := vc.ParseVerifiablePresentation(rawPresentation)
		require.NoError(t, err)
		_, mappings, err := organizationPD.Match(presentation.VerifiableCredential)
		require.NoError(t, err)
		submission := pe.PresentationSubmission{Id: "verifier", DefinitionId: organizationPD.Id, DescriptorMap: mappings}
		envelope, err := pe.NewEnvelopeFromVP(*presentation)
		require.NoError(t, err)
		credentialMap, err := submission.Validate(*envelope, organizationPD)
		require.NoError(t, err)
		values, err := organizationPD.ResolveConstraintsFields(credentialMap)
		require.NoError(t, err)
		return values
	}

	t.Run("the service-provider VP follows the organization of the organization VP", func(t *testing.T) {
		// The delegation of another organization comes first in the service provider's wallet. Without the shared id
		// it would be selected; now the value of "ura" in the organization VP is carried over and selects the
		// delegation of that organization.
		ctx := setup(t,
			[]vc.VerifiableCredential{organizationB},
			[]vc.VerifiableCredential{delegation("urn:delegation:a", "1", "nurse"), delegation("urn:delegation:b", "2", "nurse")},
			true)

		err := requestToken(ctx, nil)

		require.NoError(t, err)
		require.NotNil(t, ctx.tokenRequest)
		assert.Equal(t, oauth.JwtBearerGrantType, ctx.tokenRequest.Get(oauth.GrantTypeParam))
		assert.Equal(t, []string{"urn:organization:b"}, credentialIDs(t, ctx.tokenRequest.Get(oauth.AssertionParam)))
		assert.Equal(t, []string{"urn:delegation:b"}, credentialIDs(t, ctx.tokenRequest.Get(oauth.ClientAssertionParam)))
		assert.Equal(t, "2", verifyOrganizationVP(t, ctx.tokenRequest.Get(oauth.AssertionParam))["ura"])
	})
	t.Run("a key only one of the PDs declares is accepted and selects on that PD", func(t *testing.T) {
		testCases := []struct {
			name                    string
			organizationWallet      []vc.VerifiableCredential
			serviceProviderWallet   []vc.VerifiableCredential
			selection               map[string]string
			expectedOrganization    string
			expectedServiceProvider string
		}{
			{
				// The organization is pinned by name; the delegation follows through the shared "ura".
				name:                    "key only the organization PD declares",
				organizationWallet:      []vc.VerifiableCredential{organizationA, organizationB},
				serviceProviderWallet:   []vc.VerifiableCredential{delegation("urn:delegation:a", "1", "nurse"), delegation("urn:delegation:b", "2", "nurse")},
				selection:               map[string]string{"organization_name": "Org B"},
				expectedOrganization:    "urn:organization:b",
				expectedServiceProvider: "urn:delegation:b",
			},
			{
				// The service provider holds two delegations of the organization, differing in role; the caller pins
				// the role, which only the service_provider PD declares.
				name:                    "key only the service_provider PD declares",
				organizationWallet:      []vc.VerifiableCredential{organizationB},
				serviceProviderWallet:   []vc.VerifiableCredential{delegation("urn:delegation:nurse", "2", "nurse"), delegation("urn:delegation:doctor", "2", "doctor")},
				selection:               map[string]string{"role": "doctor"},
				expectedOrganization:    "urn:organization:b",
				expectedServiceProvider: "urn:delegation:doctor",
			},
		}
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				ctx := setup(t, tc.organizationWallet, tc.serviceProviderWallet, true)

				err := requestToken(ctx, tc.selection)

				require.NoError(t, err)
				require.NotNil(t, ctx.tokenRequest)
				assert.Equal(t, []string{tc.expectedOrganization}, credentialIDs(t, ctx.tokenRequest.Get(oauth.AssertionParam)))
				assert.Equal(t, []string{tc.expectedServiceProvider}, credentialIDs(t, ctx.tokenRequest.Get(oauth.ClientAssertionParam)))
			})
		}
	})
	t.Run("an id only the organization PD declares does not break the service-provider VP", func(t *testing.T) {
		// "organization_city" resolves in the organization VP and is carried over to the service-provider wallet,
		// whose PD does not declare it: the wallet skips it.
		ctx := setup(t,
			[]vc.VerifiableCredential{organizationA},
			[]vc.VerifiableCredential{delegation("urn:delegation:a", "1", "nurse")},
			true)

		err := requestToken(ctx, nil)

		require.NoError(t, err)
		require.NotNil(t, ctx.tokenRequest)
		assert.Equal(t, "Amsterdam", verifyOrganizationVP(t, ctx.tokenRequest.Get(oauth.AssertionParam))["organization_city"])
		assert.Equal(t, []string{"urn:delegation:a"}, credentialIDs(t, ctx.tokenRequest.Get(oauth.ClientAssertionParam)))
	})
	t.Run("a key no PD declares fails with invalid_request naming it, before any VP is built", func(t *testing.T) {
		// No DIDs can be listed (setup with expectWalletUse=false), so building a VP would fail the test.
		ctx := setup(t,
			[]vc.VerifiableCredential{organizationB},
			[]vc.VerifiableCredential{delegation("urn:delegation:b", "2", "nurse")},
			false)

		err := requestToken(ctx, map[string]string{"organization_name": "Org B", "organisation_city": "Utrecht"})

		var oauthErr oauth.OAuth2Error
		require.ErrorAs(t, err, &oauthErr)
		assert.Equal(t, oauth.InvalidRequest, oauthErr.Code)
		assert.Contains(t, oauthErr.Description, "organisation_city")
		assert.NotContains(t, oauthErr.Description, "organization_name")
		assert.Nil(t, ctx.tokenRequest)
	})
	t.Run("a pinned value no credential has fails with missing credentials naming the input descriptor and id", func(t *testing.T) {
		// pe.ErrNoCredentials is answered with HTTP 412 Precondition Failed by the API.
		ctx := setup(t,
			[]vc.VerifiableCredential{organizationA, organizationB},
			[]vc.VerifiableCredential{delegation("urn:delegation:a", "1", "nurse"), delegation("urn:delegation:b", "2", "nurse")},
			true)

		err := requestToken(ctx, map[string]string{"ura": "3"})

		require.ErrorIs(t, err, pe.ErrNoCredentials)
		assert.ErrorContains(t, err, "id_organization_credential")
		assert.ErrorContains(t, err, "ura")
		assert.Nil(t, ctx.tokenRequest)
	})
	t.Run("a pinned value leaving credentials that differ on another id fails with multiple credentials naming the input descriptor", func(t *testing.T) {
		// The caller pins the organization; both delegations of that organization match the service_provider PD, but
		// they differ on "role". The node cannot choose between them for the caller.
		ctx := setup(t,
			[]vc.VerifiableCredential{organizationA, organizationB},
			[]vc.VerifiableCredential{delegation("urn:delegation:nurse", "2", "nurse"), delegation("urn:delegation:doctor", "2", "doctor")},
			true)

		err := requestToken(ctx, map[string]string{"ura": "2"})

		require.ErrorIs(t, err, pe.ErrMultipleCredentials)
		assert.ErrorContains(t, err, "id_delegation_credential")
		assert.ErrorContains(t, err, "role")
		assert.Nil(t, ctx.tokenRequest)
	})
}
