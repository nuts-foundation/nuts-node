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
 */

package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	v1 "github.com/nuts-foundation/nuts-node/didman/api/v1"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/stretchr/testify/assert"
)

func TestCmd_AddService(t *testing.T) {
	t.Run("add compound service", func(t *testing.T) {
		serviceEndpoint := map[string]string{
			"foo": "bar",
		}

		cmd := Cmd()
		response := did.Service{
			Type:            "type",
			ServiceEndpoint: serviceEndpoint,
		}
		handler := &http2.Handler{StatusCode: http.StatusOK, ResponseData: response}
		s := httptest.NewServer(handler)
		t.Setenv("NUTS_ADDRESS", s.URL)
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

		defer s.Close()

		endpointAsJSON, _ := json.Marshal(serviceEndpoint)
		cmd.SetArgs([]string{"svc", "add", "did:nuts:1234", "type", string(endpointAsJSON)})
		err := cmd.Execute()

		assert.NoError(t, err)
	})
	t.Run("add service with string endpoint", func(t *testing.T) {
		serviceEndpoint := "https://nuts.nl"

		cmd := Cmd()
		response := v1.Endpoint{
			Type:            "type",
			ServiceEndpoint: serviceEndpoint,
		}
		handler := &http2.Handler{StatusCode: http.StatusOK, ResponseData: response}
		s := httptest.NewServer(handler)
		t.Setenv("NUTS_ADDRESS", s.URL)
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		defer s.Close()

		cmd.SetArgs([]string{"svc", "add", "did:nuts:1234", "type", serviceEndpoint})
		err := cmd.Execute()

		assert.NoError(t, err)
	})
	t.Run("it handles an http error", func(t *testing.T) {
		cmd := Cmd()
		cmd.SetArgs([]string{"svc", "add", "did:nuts:1234", "type", "http://example.com/foo"})
		assert.EqualError(t, cmd.Execute(), "unable to register service: Post \"http:///internal/didman/v1/did/did:nuts:1234/endpoint\": http: no Host in request URL")
	})
}

func TestCmd_DeleteService(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cmd := Cmd()
		handler := &http2.Handler{StatusCode: http.StatusNoContent, ResponseData: ""}
		s := httptest.NewServer(handler)
		t.Setenv("NUTS_ADDRESS", s.URL)
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		defer s.Close()

		cmd.SetArgs([]string{"svc", "delete", "did:nuts:1234", "type"})
		err := cmd.Execute()

		assert.NoError(t, err)
	})
	t.Run("it handles an http error", func(t *testing.T) {
		cmd := Cmd()
		cmd.SetArgs([]string{"svc", "delete", "did:nuts:1234", "type"})
		assert.EqualError(t, cmd.Execute(), "unable to delete service: Delete \"http:///internal/didman/v1/did/did:nuts:1234/endpoint/type\": http: no Host in request URL")
	})
}
