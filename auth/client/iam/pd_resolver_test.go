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
	"github.com/nuts-foundation/nuts-node/http/client"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"time"
)

var testPD = pe.PresentationDefinition{
	Id: "test-pd",
	InputDescriptors: []*pe.InputDescriptor{
		{Id: "id1"},
	},
}

func TestPresentationDefinitionResolver_Resolve(t *testing.T) {
	t.Run("remote PD endpoint exists - fetches from remote and returns full scope", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/presentation_definition", r.URL.Path)
			assert.Equal(t, "profile-scope extra-scope", r.URL.Query().Get("scope"))
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(testPD)
		}))
		defer server.Close()

		resolver := &PresentationDefinitionResolver{
			httpClient: HTTPClient{
				strictMode: false,
				httpClient: client.New(10 * time.Second),
			},
		}
		metadata := oauth.AuthorizationServerMetadata{
			PresentationDefinitionEndpoint: server.URL + "/presentation_definition",
		}

		result, err := resolver.Resolve(context.Background(), "profile-scope extra-scope", metadata)

		require.NoError(t, err)
		assert.Equal(t, "test-pd", result.PresentationDefinition.Id)
		assert.Equal(t, "profile-scope extra-scope", result.Scope)
	})
}
