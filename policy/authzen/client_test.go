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

package authzen

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Evaluate(t *testing.T) {
	t.Run("successful evaluation returns scope decisions", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/access/v1/evaluations", r.URL.Path)
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			var req EvaluationsRequest
			err := json.NewDecoder(r.Body).Decode(&req)
			require.NoError(t, err)
			assert.Equal(t, "organization", req.Subject.Type)
			assert.Len(t, req.Evaluations, 2)

			resp := EvaluationsResponse{
				Evaluations: []EvaluationResult{
					{Decision: true},
					{Decision: false},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, server.Client())
		decisions, err := client.Evaluate(context.Background(), EvaluationsRequest{
			Subject: Subject{Type: "organization", ID: "did:web:example.com"},
			Action:  Action{Name: "request_scope"},
			Context: EvaluationContext{Policy: "test-profile"},
			Evaluations: []Evaluation{
				{Resource: Resource{Type: "scope", ID: "scope-a"}},
				{Resource: Resource{Type: "scope", ID: "scope-b"}},
			},
		})

		require.NoError(t, err)
		assert.Equal(t, map[string]bool{
			"scope-a": true,
			"scope-b": false,
		}, decisions)
	})
}
