/*
 * Nuts node
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
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	"gopkg.in/yaml.v2"

	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/stretchr/testify/assert"
)

var organizationQuery = `
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

var untrustedOrganizationQuery = `
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

var authorizationQuery = `
{
	"query": {
		"@context": ["https://www.w3.org/2018/credentials/v1","https://nuts.nl/credentials/v1"],
		"type": ["VerifiableCredential", "NutsAuthorizationCredential"],
		"credentialSubject":{
			"id": "did:nuts:123",
			"purposeOfUse": "eOverdracht-receiver",
			"resources": {
				"path":"/Task/123"
			},
			"subject": "urn:oid:2.16.840.1.113883.2.4.6.3:123456782"
		}
	}
}
`

func TestWrapper_SearchVCs(t *testing.T) {
	registry := concept.NewRegistry()
	loadTemplates(t, registry)

	t.Run("ok - organization", func(t *testing.T) {
		ctx := newMockContext(t)
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx.echo.EXPECT().Request().Return(req)
		ctx.vcr.EXPECT().Registry().Return(registry)
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(organizationQuery), f)
		})
		var capturedQuery concept.Query
		ctx.vcr.EXPECT().Search(context.Background(), gomock.Any(), false, nil).DoAndReturn(
			func(_ interface{}, arg1 interface{}, _ interface{}, _ interface{}) ([]VerifiableCredential, error) {
				capturedQuery = arg1.(concept.Query)
				return []VerifiableCredential{}, nil
			},
		)
		ctx.echo.EXPECT().JSON(http.StatusOK, []VerifiableCredential{})

		err := ctx.client.SearchVCs(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, concept.OrganizationConcept, capturedQuery.Concept())
		parts := capturedQuery.Parts()
		if !assert.Len(t, parts, 1) {
			return
		}
		clauses := parts[0].Clauses
		if !assert.Len(t, clauses, 3) {
			return
		}
		assert.Equal(t, "prefix", clauses[0].Type())
		assert.Equal(t, "organization.name", clauses[0].Key())
		assert.Equal(t, "Zorggroep de Nootjes", clauses[0].Seek())
		assert.Equal(t, "prefix", clauses[1].Type())
		assert.Equal(t, "organization.city", clauses[1].Key())
		assert.Equal(t, "Amandelmere", clauses[1].Seek())
		assert.Equal(t, "eq", clauses[2].Type())
		assert.Equal(t, "credentialSubject.id", clauses[2].Key())
		assert.Equal(t, "did:nuts:123", clauses[2].Seek())
	})

	t.Run("ok - untrusted flag", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Registry().Return(registry)
		ctx.echo.EXPECT().Request().Return(req)
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(untrustedOrganizationQuery), f)
		})
		ctx.vcr.EXPECT().Search(context.Background(), gomock.Any(), true, nil).Return([]VerifiableCredential{}, nil)
		ctx.echo.EXPECT().JSON(http.StatusOK, []VerifiableCredential{})

		err := ctx.client.SearchVCs(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
	})

	t.Run("error - search returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Registry().Return(registry)
		ctx.echo.EXPECT().Request().Return(req)
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(organizationQuery), f)
		})
		ctx.vcr.EXPECT().Search(context.Background(), gomock.Any(), false, nil).Return(nil, errors.New("custom"))

		err := ctx.client.SearchVCs(ctx.echo)

		assert.EqualError(t, err, "custom")
	})

	t.Run("ok - authorization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Registry().Return(registry)
		ctx.echo.EXPECT().Request().Return(req)
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(authorizationQuery), f)
		})
		var capturedQuery concept.Query
		ctx.vcr.EXPECT().Search(context.Background(), gomock.Any(), false, nil).DoAndReturn(
			func(_ interface{}, arg1 interface{}, _ interface{}, _ interface{}) ([]VerifiableCredential, error) {
				capturedQuery = arg1.(concept.Query)
				return []VerifiableCredential{}, nil
			},
		)
		ctx.echo.EXPECT().JSON(http.StatusOK, []VerifiableCredential{})

		err := ctx.client.SearchVCs(ctx.echo)

		if !assert.NoError(t, err) {
			return
		}
		assert.Equal(t, concept.AuthorizationConcept, capturedQuery.Concept())
		parts := capturedQuery.Parts()
		if !assert.Len(t, parts, 1) {
			return
		}
		clauses := parts[0].Clauses
		if !assert.Len(t, clauses, 4) {
			return
		}
		assert.Equal(t, "eq", clauses[0].Type())
		assert.Equal(t, "credentialSubject.id", clauses[0].Key())
		assert.Equal(t, "did:nuts:123", clauses[0].Seek())
		assert.Equal(t, "eq", clauses[1].Type())
		assert.Equal(t, "credentialSubject.purposeOfUse", clauses[1].Key())
		assert.Equal(t, "eOverdracht-receiver", clauses[1].Seek())
		assert.Equal(t, "eq", clauses[2].Type())
		assert.Equal(t, "credentialSubject.subject", clauses[2].Key())
		assert.Equal(t, "urn:oid:2.16.840.1.113883.2.4.6.3:123456782", clauses[2].Seek())
		assert.Equal(t, "eq", clauses[3].Type())
		assert.Equal(t, "credentialSubject.resources.#.path", clauses[3].Key())
		assert.Equal(t, "/Task/123", clauses[3].Seek())
	})

	t.Run("error - search auth returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		ctx := newMockContext(t)
		ctx.vcr.EXPECT().Registry().Return(registry)
		ctx.echo.EXPECT().Request().Return(req)
		ctx.echo.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(authorizationQuery), f)
		})
		ctx.vcr.EXPECT().Search(context.Background(), gomock.Any(), false, nil).Return(nil, errors.New("custom"))

		err := ctx.client.SearchVCs(ctx.echo)

		assert.EqualError(t, err, "custom")
	})
}

func loadTemplates(t *testing.T, registry concept.Registry) {
	list, err := fs.Glob(assets.Assets, "**/*.config.yaml")
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range list {
		bytes, err := assets.Assets.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		config := concept.Config{}
		err = yaml.Unmarshal(bytes, &config)
		if err != nil {
			t.Fatal(err)
		}

		if err = registry.Add(config); err != nil {
			t.Fatal(err)
		}
	}
}
