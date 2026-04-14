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
		var receivedReq EvaluationsRequest
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/access/v1/evaluations", r.URL.Path)
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "application/json", r.Header.Get("Accept"))
			json.NewDecoder(r.Body).Decode(&receivedReq)

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
		assert.Equal(t, "organization", receivedReq.Subject.Type)
		assert.Len(t, receivedReq.Evaluations, 2)
		assert.Equal(t, map[string]bool{
			"scope-a": true,
			"scope-b": false,
		}, decisions)
	})
	t.Run("partial denial - some scopes approved, some denied", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := EvaluationsResponse{
				Evaluations: []EvaluationResult{
					{Decision: true},
					{Decision: false, Context: &EvaluationResultContext{Reason: "not permitted"}},
					{Decision: true},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, server.Client())
		decisions, err := client.Evaluate(context.Background(), EvaluationsRequest{
			Evaluations: []Evaluation{
				{Resource: Resource{Type: "scope", ID: "read"}},
				{Resource: Resource{Type: "scope", ID: "write"}},
				{Resource: Resource{Type: "scope", ID: "notify"}},
			},
		})

		require.NoError(t, err)
		assert.True(t, decisions["read"])
		assert.False(t, decisions["write"])
		assert.True(t, decisions["notify"])
	})
	t.Run("HTTP error from PDP", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte("internal error"))
		}))
		defer server.Close()

		client := NewClient(server.URL, server.Client())
		_, err := client.Evaluate(context.Background(), EvaluationsRequest{
			Evaluations: []Evaluation{
				{Resource: Resource{Type: "scope", ID: "test"}},
			},
		})

		assert.ErrorContains(t, err, "PDP returned HTTP 500")
	})
	t.Run("PDP unreachable", func(t *testing.T) {
		client := NewClient("http://localhost:1", http.DefaultClient)
		_, err := client.Evaluate(context.Background(), EvaluationsRequest{
			Evaluations: []Evaluation{
				{Resource: Resource{Type: "scope", ID: "test"}},
			},
		})

		assert.ErrorContains(t, err, "authzen: execute request")
	})
	t.Run("evaluation count mismatch", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := EvaluationsResponse{
				Evaluations: []EvaluationResult{
					{Decision: true},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}))
		defer server.Close()

		client := NewClient(server.URL, server.Client())
		_, err := client.Evaluate(context.Background(), EvaluationsRequest{
			Evaluations: []Evaluation{
				{Resource: Resource{Type: "scope", ID: "a"}},
				{Resource: Resource{Type: "scope", ID: "b"}},
			},
		})

		assert.ErrorContains(t, err, "expected 2 evaluations, got 1")
	})
	t.Run("malformed response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not json"))
		}))
		defer server.Close()

		client := NewClient(server.URL, server.Client())
		_, err := client.Evaluate(context.Background(), EvaluationsRequest{
			Evaluations: []Evaluation{
				{Resource: Resource{Type: "scope", ID: "test"}},
			},
		})

		assert.ErrorContains(t, err, "authzen: decode response")
	})
	t.Run("cancelled context returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		client := NewClient(server.URL, server.Client())
		_, err := client.Evaluate(ctx, EvaluationsRequest{
			Evaluations: []Evaluation{
				{Resource: Resource{Type: "scope", ID: "test"}},
			},
		})

		assert.ErrorContains(t, err, "authzen: execute request")
	})
	t.Run("duplicate resource ID in request returns error", func(t *testing.T) {
		client := NewClient("http://unused", http.DefaultClient)
		_, err := client.Evaluate(context.Background(), EvaluationsRequest{
			Evaluations: []Evaluation{
				{Resource: Resource{Type: "scope", ID: "same"}},
				{Resource: Resource{Type: "scope", ID: "same"}},
			},
		})

		assert.ErrorContains(t, err, "duplicate resource ID in request: same")
	})
}
