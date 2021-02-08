/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
package engine

import (
	"bytes"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vdr"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/nuts-foundation/go-did"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	http2 "github.com/nuts-foundation/nuts-node/test/http"
	v1 "github.com/nuts-foundation/nuts-node/vdr/api/v1"

	core "github.com/nuts-foundation/nuts-node/core"
)

func Test_flagSet(t *testing.T) {
	assert.NotNil(t, flagSet())
}

func TestNewRegistryEngine(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	cryptoInstance := crypto.NewTestCryptoInstance(testDirectory)
	networkInstance := network.NewTestNetworkInstance(testDirectory)
	vdrInstance := vdr.NewVDR(vdr.DefaultConfig(), cryptoInstance, networkInstance)
	t.Run("instance", func(t *testing.T) {
		assert.NotNil(t, NewVDREngine(vdrInstance))
	})

	t.Run("configuration", func(t *testing.T) {
		e := NewVDREngine(vdrInstance)
		cfg := core.NewNutsConfig()
		cfg.RegisterFlags(e.Cmd, e)
		assert.NoError(t, cfg.InjectIntoEngine(e))
	})
}

func TestEngine_Command(t *testing.T) {
	core.NewNutsConfig().Load(&cobra.Command{})
	testDirectory := io.TestDirectory(t)
	cryptoInstance := crypto.NewTestCryptoInstance(testDirectory)
	networkInstance := network.NewTestNetworkInstance(testDirectory)
	vdrInstance := vdr.NewVDR(vdr.DefaultConfig(), cryptoInstance, networkInstance)
	createCmd := func(t *testing.T) *cobra.Command {
		return NewVDREngine(vdrInstance).Cmd
	}

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
			cmd := createCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			os.Setenv("NUTS_ADDRESS", s.URL)
			core.NewNutsConfig().Load(cmd)
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
			cmd := createCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: "b00m!"})
			os.Setenv("NUTS_ADDRESS", s.URL)
			core.NewNutsConfig().Load(cmd)
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
			cmd := createCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDRsolution})
			os.Setenv("NUTS_ADDRESS", s.URL)
			core.NewNutsConfig().Load(cmd)
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
			cmd := createCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNotFound, ResponseData: "not found"})
			os.Setenv("NUTS_ADDRESS", s.URL)
			core.NewNutsConfig().Load(cmd)
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
			cmd := createCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			os.Setenv("NUTS_ADDRESS", s.URL)
			core.NewNutsConfig().Load(cmd)
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
			cmd := createCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			os.Setenv("NUTS_ADDRESS", s.URL)
			core.NewNutsConfig().Load(cmd)
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
			cmd := createCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: "invalid"})
			os.Setenv("NUTS_ADDRESS", s.URL)
			core.NewNutsConfig().Load(cmd)
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
	t.Run("address has http prefix", func(t *testing.T) {
		os.Setenv("NUTS_ADDRESS", "https://localhost")
		cmd := &cobra.Command{}
		core.NewNutsConfig().Load(cmd)
		client := httpClient(cmd)
		assert.Equal(t, "https://localhost", client.ServerAddress)
	})
	t.Run("address has no http prefix", func(t *testing.T) {
		os.Setenv("NUTS_ADDRESS", "localhost")
		cmd := &cobra.Command{}
		core.NewNutsConfig().Load(cmd)
		client := httpClient(cmd)
		assert.Equal(t, "http://localhost", client.ServerAddress)
	})
}
