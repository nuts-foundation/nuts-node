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
	"net/http"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
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
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(organizationQuery), f)
		})
		// Not an organization VC, but doesn't matter
		actualVC := *credential.ValidNutsAuthorizationCredential()
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{actualVC}, nil)
		ctx.mockVerifier.EXPECT().GetRevocation(*actualVC.ID).Return(nil, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		err := ctx.client.SearchVCs(ctx.echo)

		assert.NoError(t, err)
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
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(prefixQuery), f)
		})
		// Not an organization VC, but doesn't matter
		actualVC := *credential.ValidNutsAuthorizationCredential()
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{actualVC}, nil)
		ctx.mockVerifier.EXPECT().GetRevocation(*actualVC.ID).Return(nil, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		err := ctx.client.SearchVCs(ctx.echo)

		assert.NoError(t, err)
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
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(wildcardOnlyQuery), f)
		})
		// Not an organization VC, but doesn't matter
		actualVC := *credential.ValidNutsAuthorizationCredential()
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{actualVC}, nil)
		ctx.mockVerifier.EXPECT().GetRevocation(*actualVC.ID).Return(nil, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, gomock.Any())

		err := ctx.client.SearchVCs(ctx.echo)

		assert.NoError(t, err)
	})

	t.Run("ok - no results", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(organizationQuery), f)
		})
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{}, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, SearchVCResults{[]SearchVCResult{}})

		err := ctx.client.SearchVCs(ctx.echo)

		assert.NoError(t, err)
	})

	t.Run("ok - custom credential with @list terms", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(customQuery), f)
		})
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
		ctx.echo.EXPECT().JSON(http.StatusOK, SearchVCResults{[]SearchVCResult{}})

		err := ctx.client.SearchVCs(ctx.echo)

		assert.NoError(t, err)
	})

	t.Run("ok - untrusted flag", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(untrustedOrganizationQuery), f)
		})
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, true, gomock.Any()).Return([]vc.VerifiableCredential{}, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, SearchVCResults{[]SearchVCResult{}})

		err := ctx.client.SearchVCs(ctx.echo)

		assert.NoError(t, err)
	})

	t.Run("error - search returns error", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(organizationQuery), f)
		})
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return(nil, errors.New("custom"))

		err := ctx.client.SearchVCs(ctx.echo)

		assert.EqualError(t, err, "custom")
	})

	t.Run("error - multiple subjects", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(multiSubjectQuery), f)
		})

		err := ctx.client.SearchVCs(ctx.echo)

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
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(query), f)
		})

		err := ctx.client.SearchVCs(ctx.echo)

		assert.EqualError(t, err, "failed to convert query to JSON-LD expanded form: invalid property: Dropping property that did not expand into an absolute IRI or keyword.")
	})

	t.Run("error - error retrieving revocation", func(t *testing.T) {
		ctx := newMockContext(t)
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(organizationQuery), f)
		})
		// Not an organization VC, but doesn't matter
		actualVC := *credential.ValidNutsAuthorizationCredential()
		ctx.vcr.EXPECT().Search(ctx.requestCtx, searchTerms, false, gomock.Any()).Return([]vc.VerifiableCredential{actualVC}, nil)
		ctx.mockVerifier.EXPECT().GetRevocation(*actualVC.ID).Return(nil, errors.New("failure"))

		err := ctx.client.SearchVCs(ctx.echo)

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
		ctx.echo.EXPECT().JSON(http.StatusOK, credential)

		err := ctx.client.ResolveVC(ctx.echo, id.String())

		assert.NoError(t, err)
	})

	t.Run("ok (verify error, but still returned)", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.vcr.EXPECT().Resolve(id, nil).Return(&credential, errors.New("failed"))
		ctx.echo.EXPECT().JSON(http.StatusOK, credential)

		err := ctx.client.ResolveVC(ctx.echo, id.String())

		assert.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		ctx := newMockContext(t)

		ctx.vcr.EXPECT().Resolve(id, nil).Return(nil, errors.New("failed"))

		err := ctx.client.ResolveVC(ctx.echo, id.String())

		assert.Error(t, err)
	})

	t.Run("error - invalid input ID", func(t *testing.T) {
		ctx := newMockContext(t)

		err := ctx.client.ResolveVC(ctx.echo, string([]byte{0x7f}))
		assert.Error(t, err)
	})
}
