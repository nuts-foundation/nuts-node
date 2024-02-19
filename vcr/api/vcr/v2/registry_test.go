/*
 * Copyright (C) 2022 Nuts community
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

package v2

import (
	"encoding/json"
	"errors"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

const organizationQuery = `
{
	"query": {
		"@context": ["https://www.w3.org/2018/credentials/v1","https://nuts.nl/credentials/v1"],
		"type": ["VerifiableCredential", "NutsOrganizationCredential"],
		"credentialSubject":{
			"id":"did:nuts:123",
			"organization": {
				"name": "Zorggroep de Nootjes",
				"city": "Amandelmere"
			}
		}
	}
}
`

const untrustedOrganizationQuery = `
{
	"query": {
		"@context": ["https://www.w3.org/2018/credentials/v1","https://nuts.nl/credentials/v1"],
		"type": ["VerifiableCredential", "NutsOrganizationCredential"],
		"credentialSubject":{
			"id":"did:nuts:123",
			"organization": {
				"name": "Zorggroep de Nootjes",
				"city": "Amandelmere"
			}
		}
	},
	"searchOptions": {
		"allowUntrustedIssuer": true
	}
}
`

const multiSubjectQuery = `
{
	"query": {
		"@context": ["https://www.w3.org/2018/credentials/v1","https://nuts.nl/credentials/v1"],
		"type": ["VerifiableCredential", "NutsAuthorizationCredential"],
		"issuer": "did:nuts:issuer",
		"credentialSubject":[{
			"id": "did:nuts:123",
			"purposeOfUse": "eOverdracht-receiver",
			"resources": {
				"path":"/Task/123"
			},
			"subject": "urn:oid:2.16.840.1.113883.2.4.6.3:123456782"
		},
		{
			"id": "did:nuts:123",
			"purposeOfUse": "eOverdracht-receiver",
			"resources": {
				"path":"/Task/123"
			},
			"subject": "urn:oid:2.16.840.1.113883.2.4.6.3:123456782"
		}]
	}
}
`

const customQuery = `
{
	"query": ` + jsonld.JSONLDExample + `
}
`

func TestWrapper_SearchVCs(t *testing.T) {
	searchTerms := []vcr.SearchTerm{
		{IRIPath: jsonld.CredentialSubjectPath, Value: "did:nuts:123"},
		{IRIPath: jsonld.OrganizationCityPath, Value: "Amandelmere"},
		{IRIPath: jsonld.OrganizationNamePath, Value: "Zorggroep de Nootjes"},
	}

	t.Run("ok - exact match returns results", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SearchVCsJSONRequestBody{}
		err := json.Unmarshal([]byte(organizationQuery), &request)
		require.NoError(t, err)
		// Not an organization VC, but doesn't matter
		actualVC := test.ValidNutsAuthorizationCredential(t)
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{actualVC}, nil)
		ctx.mockVerifier.EXPECT().GetRevocation(*actualVC.ID).Return(nil, nil)
		expectedResponse := SearchVCs200JSONResponse(SearchVCResults{[]SearchVCResult{{VerifiableCredential: actualVC}}})

		response, err := ctx.client.SearchVCs(ctx.requestCtx, SearchVCsRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})
	t.Run("ok - prefix match returns results", func(t *testing.T) {
		const prefixQuery = `
{
	"query": {
		"@context": ["https://www.w3.org/2018/credentials/v1","https://nuts.nl/credentials/v1"],
		"type": ["VerifiableCredential", "NutsOrganizationCredential"],
		"credentialSubject":{
			"id":"did:nuts:123",
			"organization": {
				"name": "Zorg*",
				"city": "Aman*"
			}
		}
	}
}
`

		searchTerms := []vcr.SearchTerm{
			{IRIPath: jsonld.CredentialSubjectPath, Value: "did:nuts:123"},
			{IRIPath: jsonld.OrganizationCityPath, Value: "Aman", Type: vcr.Prefix},
			{IRIPath: jsonld.OrganizationNamePath, Value: "Zorg", Type: vcr.Prefix},
		}

		ctx := newMockContext(t)
		request := SearchVCsJSONRequestBody{}
		err := json.Unmarshal([]byte(prefixQuery), &request)
		require.NoError(t, err)
		// Not an organization VC, but doesn't matter
		actualVC := test.ValidNutsAuthorizationCredential(t)
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{actualVC}, nil)
		ctx.mockVerifier.EXPECT().GetRevocation(*actualVC.ID).Return(nil, nil)
		expectedResponse := SearchVCs200JSONResponse(SearchVCResults{[]SearchVCResult{{VerifiableCredential: actualVC}}})

		response, err := ctx.client.SearchVCs(ctx.requestCtx, SearchVCsRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})
	t.Run("ok - wildcard indicating not nil", func(t *testing.T) {
		const wildcardOnlyQuery = `
{
	"query": {
		"@context": ["https://www.w3.org/2018/credentials/v1","https://nuts.nl/credentials/v1"],
		"type": ["VerifiableCredential", "NutsOrganizationCredential"],
		"credentialSubject":{
			"id":"did:nuts:123",
			"organization": {
				"name": "*"
			}
		}
	}
}
`

		searchTerms := []vcr.SearchTerm{
			{IRIPath: jsonld.CredentialSubjectPath, Value: "did:nuts:123"},
			{IRIPath: jsonld.OrganizationNamePath, Type: vcr.NotNil},
		}

		ctx := newMockContext(t)
		request := SearchVCsJSONRequestBody{}
		err := json.Unmarshal([]byte(wildcardOnlyQuery), &request)
		require.NoError(t, err)
		// Not an organization VC, but doesn't matter
		actualVC := test.ValidNutsAuthorizationCredential(t)
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{actualVC}, nil)
		ctx.mockVerifier.EXPECT().GetRevocation(*actualVC.ID).Return(nil, nil)
		expectedResponse := SearchVCs200JSONResponse(SearchVCResults{[]SearchVCResult{{VerifiableCredential: actualVC}}})

		response, err := ctx.client.SearchVCs(ctx.requestCtx, SearchVCsRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})

	t.Run("ok - no results", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SearchVCsJSONRequestBody{}
		err := json.Unmarshal([]byte(organizationQuery), &request)
		require.NoError(t, err)
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{}, nil)
		expectedResponse := SearchVCs200JSONResponse(SearchVCResults{[]SearchVCResult{}})

		response, err := ctx.client.SearchVCs(ctx.requestCtx, SearchVCsRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})

	t.Run("ok - custom credential with @list terms", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SearchVCsJSONRequestBody{}
		err := json.Unmarshal([]byte(customQuery), &request)
		require.NoError(t, err)
		ctx.vcr.EXPECT().Search(ctx.requestCtx, gomock.Any(), false, gomock.Any()).Return([]vc.VerifiableCredential{}, nil).Do(func(f1 interface{}, f2 interface{}, f3 interface{}, f4 interface{}) {
			terms := f2.([]vcr.SearchTerm)
			if assert.Len(t, terms, 9) {
				count := 0

				// both telephone numbers should have been added as required param, only checking the count since ordering is not guaranteed
				for _, st := range terms {
					if len(st.IRIPath) > 0 && st.IRIPath[0] == "http://example.com/telephone" {
						count++
					}
				}
				assert.Equal(t, 2, count)
			}
		})
		expectedResponse := SearchVCs200JSONResponse(SearchVCResults{[]SearchVCResult{}})

		response, err := ctx.client.SearchVCs(ctx.requestCtx, SearchVCsRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})

	t.Run("ok - untrusted flag", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SearchVCsJSONRequestBody{}
		err := json.Unmarshal([]byte(untrustedOrganizationQuery), &request)
		require.NoError(t, err)
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, true, gomock.Any()).Return([]vc.VerifiableCredential{}, nil)
		expectedResponse := SearchVCs200JSONResponse(SearchVCResults{[]SearchVCResult{}})

		response, err := ctx.client.SearchVCs(ctx.requestCtx, SearchVCsRequestObject{Body: &request})

		assert.NoError(t, err)
		assert.Equal(t, expectedResponse, response)
	})

	t.Run("error - search returns error", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SearchVCsJSONRequestBody{}
		err := json.Unmarshal([]byte(organizationQuery), &request)
		require.NoError(t, err)
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return(nil, errors.New("custom"))

		response, err := ctx.client.SearchVCs(ctx.requestCtx, SearchVCsRequestObject{Body: &request})

		assert.Empty(t, response)
		assert.EqualError(t, err, "custom")
	})

	t.Run("error - multiple subjects", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SearchVCsJSONRequestBody{}
		err := json.Unmarshal([]byte(multiSubjectQuery), &request)
		require.NoError(t, err)

		response, err := ctx.client.SearchVCs(ctx.requestCtx, SearchVCsRequestObject{Body: &request})

		assert.Empty(t, response)
		assert.EqualError(t, err, "can't match on multiple VC subjects")
	})

	t.Run("error - query contains properties not defined in JSON-LD context returns error", func(t *testing.T) {
		const query = `
{
	"query": {
		"@context": ["https://www.w3.org/2018/credentials/v1","https://nuts.nl/credentials/v1"],
		"type": ["VerifiableCredential", "NutsOrganizationCredential"],
		"credentialSubject":{
			"id":"did:nuts:123",
			"organization": {
				"test": "bla"
			}
		}
	}
}`

		ctx := newMockContext(t)
		request := SearchVCsJSONRequestBody{}
		err := json.Unmarshal([]byte(query), &request)
		require.NoError(t, err)

		response, err := ctx.client.SearchVCs(ctx.requestCtx, SearchVCsRequestObject{Body: &request})

		assert.Empty(t, response)
		assert.EqualError(t, err, "failed to convert query to JSON-LD expanded form: invalid property: Dropping property that did not expand into an absolute IRI or keyword.")
	})

	t.Run("error - error retrieving revocation", func(t *testing.T) {
		ctx := newMockContext(t)
		request := SearchVCsJSONRequestBody{}
		err := json.Unmarshal([]byte(organizationQuery), &request)
		require.NoError(t, err)
		// Not an organization VC, but doesn't matter
		actualVC := test.ValidNutsAuthorizationCredential(t)
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{actualVC}, nil)
		ctx.mockVerifier.EXPECT().GetRevocation(*actualVC.ID).Return(nil, errors.New("failure"))

		response, err := ctx.client.SearchVCs(ctx.requestCtx, SearchVCsRequestObject{Body: &request})

		assert.Empty(t, response)
		assert.EqualError(t, err, "failure")
	})
}

func TestWrapper_ResolveVC(t *testing.T) {
	id := ssi.MustParseURI("did:nuts:some-did#some-vc")

	credential := vc.VerifiableCredential{
		ID: &id,
	}

	t.Run("ok", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Resolve(id, nil).Return(&credential, nil)

		response, err := ctx.client.ResolveVC(ctx.requestCtx, ResolveVCRequestObject{Id: id.String()})

		assert.NoError(t, err)
		assert.Equal(t, ResolveVC200JSONResponse(credential), response)
	})

	t.Run("ok (verify error, but still returned)", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.vcr.EXPECT().Resolve(id, nil).Return(&credential, errors.New("failed"))

		response, err := ctx.client.ResolveVC(ctx.requestCtx, ResolveVCRequestObject{Id: id.String()})

		assert.NoError(t, err)
		assert.Equal(t, ResolveVC200JSONResponse(credential), response)
	})

	t.Run("error", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.vcr.EXPECT().Resolve(id, nil).Return(nil, errors.New("failed"))

		response, err := ctx.client.ResolveVC(ctx.requestCtx, ResolveVCRequestObject{Id: id.String()})

		assert.Error(t, err)
		assert.Empty(t, response)
	})

	t.Run("error - invalid input ID", func(t *testing.T) {
		ctx := newMockContext(t)

		response, err := ctx.client.ResolveVC(ctx.requestCtx, ResolveVCRequestObject{Id: string([]byte{0x7f})})

		assert.Error(t, err)
		assert.Empty(t, response)
	})
}
