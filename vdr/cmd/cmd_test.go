/*
 * Nuts node
 * Copyright (C) 2021. Nuts community
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
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	v1 "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	"github.com/stretchr/testify/assert"
)

func Test_flagSet(t *testing.T) {
	assert.NotNil(t, FlagSet())
}

func TestEngine_Command(t *testing.T) {
	exampleID, _ := did.ParseDID("did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
	exampleDIDDocument := did.Document{
		ID:         *exampleID,
		Controller: []did.DID{*exampleID},
	}

	exampleDIDRsolution := v1.DIDResolutionResult{
		Document:         exampleDIDDocument,
		DocumentMetadata: v1.DIDDocumentMetadata{},
	}

	t.Run("create-did", func(t *testing.T) {
		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd := Cmd()
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewServerConfig().Load(cmd)
			defer s.Close()

			buf := new(bytes.Buffer)
			cmd.SetArgs([]string{"create-did"})
			cmd.SetOut(buf)
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "Created DID document")
			assert.Contains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
		})

		t.Run("error - server error", func(t *testing.T) {
			cmd := Cmd()
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: "b00m!"})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewServerConfig().Load(cmd)
			defer s.Close()

			buf := new(bytes.Buffer)
			cmd.SetArgs([]string{"create-did"})
			cmd.SetOut(buf)
			err := cmd.Execute()

			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "unable to create new DID")
			assert.Contains(t, buf.String(), "b00m!")
		})
	})

	t.Run("resolve", func(t *testing.T) {
		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd := Cmd()
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDRsolution})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewServerConfig().Load(cmd)
			defer s.Close()

			buf := new(bytes.Buffer)
			cmd.SetArgs([]string{"resolve", "did"})
			cmd.SetOut(buf)
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.Contains(t, buf.String(), "version")
		})

		t.Run("error - not found", func(t *testing.T) {
			cmd := Cmd()
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNotFound, ResponseData: "not found"})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewServerConfig().Load(cmd)
			defer s.Close()

			buf := new(bytes.Buffer)
			cmd.SetArgs([]string{"resolve", "did"})
			cmd.SetOut(buf)
			err := cmd.Execute()

			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "failed to resolve DID document")
			assert.Contains(t, buf.String(), "not found")
		})
	})

	t.Run("update", func(t *testing.T) {
		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd := Cmd()
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewServerConfig().Load(cmd)
			defer s.Close()

			buf := new(bytes.Buffer)
			cmd.SetArgs([]string{"update", "did", "hash", "../test/diddocument.json"})
			cmd.SetOut(buf)
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "DID document updated")
		})

		t.Run("error - incorrect input", func(t *testing.T) {
			cmd := Cmd()
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewServerConfig().Load(cmd)
			defer s.Close()

			buf := new(bytes.Buffer)
			cmd.SetArgs([]string{"update", "did", "hash", "../test/syntax_error.json"})
			cmd.SetOut(buf)
			err := cmd.Execute()

			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "failed to parse DID document")
		})

		t.Run("error - server error", func(t *testing.T) {
			cmd := Cmd()
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: "invalid"})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewServerConfig().Load(cmd)
			defer s.Close()

			buf := new(bytes.Buffer)
			cmd.SetArgs([]string{"update", "did", "hash", "../test/diddocument.json"})
			cmd.SetOut(buf)
			err := cmd.Execute()

			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "failed to update DID document")
			assert.Contains(t, buf.String(), "invalid")
		})
	})
}

func Test_httpClient(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		client := httpClient()
		assert.Equal(t, "http://localhost:1323", client.ServerAddress)
	})
	t.Run("invalid address", func(t *testing.T) {
		client := httpClient()
		assert.Equal(t, "http://localhost:1323", client.ServerAddress)
	})
}
