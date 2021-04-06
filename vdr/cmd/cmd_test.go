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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vdr"
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
	errBuf := new(bytes.Buffer)
	inBuf := new(bytes.Buffer)

	newCmd := func(t *testing.T) *cobra.Command {
		t.Helper()
		t.Cleanup(func() {
			buf.Reset()
			inBuf.Reset()
			errBuf.Reset()
		})
		command := Cmd()
		command.SetOut(buf)
		command.SetErr(errBuf)
		command.SetIn(inBuf)
		return command
	}

	newCmdWithServer := func(t *testing.T, handler http2.Handler) *cobra.Command {
		cmd := newCmd(t)
		s := httptest.NewServer(handler)
		assert.NoError(t, os.Setenv("NUTS_ADDRESS", s.URL), "unable to set the NUTS_ADDRESS env var")
		t.Cleanup(func() {
			s.Close()
			assert.NoError(t, os.Unsetenv("NUTS_ADDRESS"))
		})

		return cmd
	}

	t.Run("create-did", func(t *testing.T) {
		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
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
			assert.Empty(t, errBuf.Bytes())
			assert.NoError(t, err)
		})

		t.Run("error - server error", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: "b00m!"})
			cmd.SetArgs([]string{"create-did"})

			err := cmd.Execute()
			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, errBuf.String(), "unable to create new DID")
			assert.Contains(t, errBuf.String(), "b00m!")
		})
	})

	t.Run("resolve", func(t *testing.T) {
		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDRsolution})
			cmd.SetArgs([]string{"resolve", "did"})

			err := cmd.Execute()
			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.Contains(t, buf.String(), "version")
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("ok - print metadata only", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDRsolution})
			cmd.SetArgs([]string{"resolve", "did", "--metadata"})

			err := cmd.Execute()
			if !assert.NoError(t, err) {
				return
			}
			assert.NotContains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.Contains(t, buf.String(), "version")
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("ok - print document only", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDRsolution})
			cmd.SetArgs([]string{"resolve", "did", "--document"})

			err := cmd.Execute()
			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.NotContains(t, buf.String(), "version")
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("error - not found", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusNotFound, ResponseData: "not found"})
			cmd.SetArgs([]string{"resolve", "did"})

			err := cmd.Execute()
			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, errBuf.String(), "failed to resolve DID document")
			assert.Contains(t, errBuf.String(), "not found")
		})
	})

	t.Run("update", func(t *testing.T) {
		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			cmd.SetArgs([]string{"update", "did", "hash", "../test/diddocument.json"})
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "DID document updated")
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("error - incorrect input", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			cmd.SetArgs([]string{"update", "did", "hash", "../test/syntax_error.json"})

			err := cmd.Execute()
			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, errBuf.String(), "failed to parse DID document")
		})

		t.Run("error - server error", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: "invalid"})
			cmd.SetArgs([]string{"update", "did", "hash", "../test/diddocument.json"})

			err := cmd.Execute()
			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, errBuf.String(), "failed to update DID document")
			assert.Contains(t, errBuf.String(), "invalid")
		})
	})

	t.Run("deactivate", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusOK})

			inBuf.Write([]byte{'y', '\n'})
			cmd.SetArgs([]string{"deactivate", "did"})
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "This will delete the DID document, are you sure?")
			assert.Contains(t, buf.String(), "DID document deactivated\n")
			assert.Empty(t, errBuf.Bytes())
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
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("error - did document not found", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusNotFound})

			inBuf.Write([]byte{'y', '\n'})
			cmd.SetArgs([]string{"deactivate", "did"})

			err := cmd.Execute()
			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, errBuf.String(), "failed to deactivate DID document: server returned HTTP 404 (expected: 200)")
		})
	})

	t.Run("addVerificationMethod", func(t *testing.T) {
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		verificationMethod, _ := did.NewVerificationMethod(*vdr.TestMethodDIDA, ssi.JsonWebKey2020, *vdr.TestDIDA, pair.PublicKey)

		t.Run("ok", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusOK, ResponseData: verificationMethod})

			cmd.SetArgs([]string{"addvm", vdr.TestDIDA.String()})
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			if !assert.Contains(t, buf.String(), vdr.TestMethodDIDA.String()) {
				return
			}
			resultingMethod := did.VerificationMethod{}
			err = json.Unmarshal(buf.Bytes(), &resultingMethod)
			assert.Equal(t, *verificationMethod, resultingMethod)
			assert.Empty(t, errBuf.Bytes())

		})

		t.Run("error - did document not found", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusNotFound})

			cmd.SetArgs([]string{"addvm", vdr.TestDIDA.String()})

			err := cmd.Execute()
			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, errBuf.String(), "failed to add a new verification method to DID document: server returned HTTP 404 (expected: 200), response: null")
		})
	})

	t.Run("deleteVerificationMethod", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusNoContent})
			cmd.SetArgs([]string{"delvm", vdr.TestDIDA.String(), vdr.TestMethodDIDA.String()})
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.Empty(t, errBuf.String())
		})

		t.Run("error - did document not found", func(t *testing.T) {
			cmd := newCmdWithServer(t, http2.Handler{StatusCode: http.StatusNotFound})

			cmd.SetArgs([]string{"delvm", vdr.TestDIDA.String(), vdr.TestMethodDIDA.String()})
			err := cmd.Execute()
			if !assert.Error(t, err) {
				return
			}
			assert.Contains(t, errBuf.String(), "failed to delete the verification method from DID document: server returned HTTP 404 (expected: 204), response: null")
		})
	})
}

func Test_httpClient(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		client := httpClient(core.DefaultClientConfig())
		assert.Equal(t, "http://localhost:1323", client.ServerAddress)
	})
	t.Run("invalid address", func(t *testing.T) {
		client := httpClient(core.DefaultClientConfig())
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
