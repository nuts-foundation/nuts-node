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
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	v1 "github.com/nuts-foundation/nuts-node/vdr/api/v1"
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

	buf := new(bytes.Buffer)
	inBuf := new(bytes.Buffer)

	newCmd := func(t *testing.T) *cobra.Command {
		t.Helper()
		buf.Reset()
		inBuf.Reset()
		command := Cmd()
		command.SetOut(buf)
		command.SetErr(buf)
		command.SetIn(inBuf)
		return command
	}

	t.Run("create-did", func(t *testing.T) {
		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd := newCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewClientConfig().Load(cmd.Flags())
			defer s.Close()

			cmd.SetArgs([]string{"create-did"})
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			if !assert.Contains(t, buf.String(), "did:nuts:") {
				return
			}
			document := did.Document{}
			err = json.Unmarshal(buf.Bytes(), &document)
			assert.NoError(t, err)
		})

		t.Run("error - server error", func(t *testing.T) {
			cmd := newCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: "b00m!"})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewClientConfig().Load(cmd.Flags())
			defer s.Close()

			cmd.SetArgs([]string{"create-did"})
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
			cmd := newCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDRsolution})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewClientConfig().Load(cmd.Flags())
			defer s.Close()

			cmd.SetArgs([]string{"resolve", "did"})
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.Contains(t, buf.String(), "version")
		})

		t.Run("ok - print metadata only", func(t *testing.T) {
			cmd := newCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDRsolution})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewClientConfig().Load(cmd.Flags())
			defer s.Close()

			cmd.SetArgs([]string{"resolve", "did", "--metadata"})
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.NotContains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.Contains(t, buf.String(), "version")
		})

		t.Run("ok - print document only", func(t *testing.T) {
			cmd := newCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDRsolution})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewClientConfig().Load(cmd.Flags())
			defer s.Close()

			cmd.SetArgs([]string{"resolve", "did", "--document"})
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.NotContains(t, buf.String(), "version")
		})

		t.Run("error - not found", func(t *testing.T) {
			cmd := newCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNotFound, ResponseData: "not found"})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewClientConfig().Load(cmd.Flags())
			defer s.Close()

			cmd.SetArgs([]string{"resolve", "did"})
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
			cmd := newCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewClientConfig().Load(cmd.Flags())
			defer s.Close()

			cmd.SetArgs([]string{"update", "did", "hash", "../test/diddocument.json"})
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "DID document updated")
		})

		t.Run("error - incorrect input", func(t *testing.T) {
			cmd := newCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewClientConfig().Load(cmd.Flags())
			defer s.Close()
			cmd.SetArgs([]string{"update", "did", "hash", "../test/syntax_error.json"})

			err := cmd.Execute()
			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "failed to parse DID document")
		})

		t.Run("error - server error", func(t *testing.T) {
			cmd := newCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: "invalid"})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewClientConfig().Load(cmd.Flags())
			defer s.Close()

			cmd.SetArgs([]string{"update", "did", "hash", "../test/diddocument.json"})

			err := cmd.Execute()
			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "failed to update DID document")
			assert.Contains(t, buf.String(), "invalid")
		})
	})

	t.Run("deactivate", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			cmd := newCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewClientConfig().Load(cmd.Flags())
			defer s.Close()

			inBuf.Write([]byte{'y', '\n'})
			cmd.SetArgs([]string{"deactivate", "did"})
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "This will delete the DID document, are you sure?")
			assert.Contains(t, buf.String(), "DID document deactivated\n")
		})
		t.Run("ok - stops when the user does not confirm", func(t *testing.T) {
			cmd := newCmd(t)

			inBuf.Write([]byte{'n', '\n'})
			cmd.SetArgs([]string{"deactivate", "did"})

			err := cmd.Execute()
			if !assert.Nil(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "Deactivation cancelled")
		})

		t.Run("error - did document not found", func(t *testing.T) {
			cmd := newCmd(t)
			s := httptest.NewServer(http2.Handler{StatusCode: http.StatusNotFound})
			os.Setenv("NUTS_ADDRESS", s.URL)
			defer os.Unsetenv("NUTS_ADDRESS")
			core.NewClientConfig().Load(cmd.Flags())
			defer s.Close()

			inBuf.Write([]byte{'y', '\n'})
			cmd.SetArgs([]string{"deactivate", "did"})

			err := cmd.Execute()
			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "failed to deactivate DID document: VDR returned HTTP 404 (expected: 200)")
		})
	})
}

func Test_httpClient(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		client := httpClient(core.ClientConfigFlags())
		assert.Equal(t, "http://localhost:1323", client.ServerAddress)
	})
	t.Run("invalid address", func(t *testing.T) {
		client := httpClient(core.ClientConfigFlags())
		assert.Equal(t, "http://localhost:1323", client.ServerAddress)
	})
}

func Test_askYesNo(t *testing.T) {
	question := "do you believe that the earth is a convex sphere?"
	cmd := Cmd()
	inBuf := new(bytes.Buffer)
	outBuf := new(bytes.Buffer)

	cmd.SetIn(inBuf)
	cmd.SetErr(outBuf)
	cmd.SetOut(outBuf)

	t.Run("yes gives a true", func(t *testing.T) {
		inBuf.Reset()
		outBuf.Reset()
		inBuf.Write([]byte{'y', '\n'})

		answer := askYesNo(question, cmd)
		assert.True(t, answer)
		assert.Contains(t, outBuf.String(), question)
		assert.Contains(t, outBuf.String(), "[yes/no]:")
	})

	t.Run("no gives a false", func(t *testing.T) {
		inBuf.Reset()
		outBuf.Reset()
		inBuf.Write([]byte{'n', '\n'})

		answer := askYesNo(question, cmd)
		assert.False(t, answer)
		assert.Contains(t, outBuf.String(), question)
	})

	t.Run("something else tries again", func(t *testing.T) {
		inBuf.Reset()
		outBuf.Reset()
		inBuf.Write([]byte{'u', '\n', 'y', '\n'})

		answer := askYesNo(question, cmd)
		assert.True(t, answer)
		assert.Contains(t, outBuf.String(), question)
		assert.Contains(t, outBuf.String(), "invalid answer")
	})

	t.Run("end of input stops the loop with false", func(t *testing.T) {
		inBuf.Reset()
		outBuf.Reset()

		answer := askYesNo(question, cmd)
		assert.False(t, answer)
		assert.Contains(t, outBuf.String(), question)
	})
}
