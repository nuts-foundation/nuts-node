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
 */

package cmd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	v2 "github.com/nuts-foundation/nuts-node/vdr/api/v2"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/core"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/vdr"
	v1 "github.com/nuts-foundation/nuts-node/vdr/api/v1"
	"github.com/spf13/cobra"
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

	newCmdWithServer := func(t *testing.T, handler http.Handler) *cobra.Command {
		cmd := newCmd(t)
		s := httptest.NewServer(handler)
		t.Setenv("NUTS_ADDRESS", s.URL)
		t.Cleanup(s.Close)

		return cmd
	}

	t.Run("create-did", func(t *testing.T) {
		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			cmd.SetArgs([]string{"create-did"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()
			require.NoError(t, err)
			require.Contains(t, buf.String(), "did:nuts:")
			document := did.Document{}
			err = json.Unmarshal(buf.Bytes(), &document)
			assert.Empty(t, errBuf.Bytes())
			assert.NoError(t, err)
		})
		t.Run("ok - v2", func(t *testing.T) {
			cmd := newCmdWithServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				assert.Equal(t, "/internal/vdr/v2/subject", request.URL.Path)
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusOK)
				bytes, _ := json.Marshal(v2.CreateDID200JSONResponse{Documents: []did.Document{exampleDIDDocument}})
				_, _ = writer.Write(bytes)
			}))
			cmd.SetArgs([]string{"create-did", "--v2"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()
			require.NoError(t, err)
			documents := make([]did.Document, 0)
			err = json.Unmarshal(buf.Bytes(), &documents)
			assert.Empty(t, errBuf.Bytes())
			assert.NoError(t, err)
		})
		t.Run("error - server error", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: "b00m!"})
			cmd.SetArgs([]string{"create-did"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.Error(t, err)
			assert.Contains(t, errBuf.String(), "unable to create new DID")
		})
	})

	t.Run("resolve", func(t *testing.T) {
		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDRsolution})
			cmd.SetArgs([]string{"resolve", "did"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.NoError(t, err)
			assert.Contains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("ok - print metadata only", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDRsolution})
			cmd.SetArgs([]string{"resolve", "did", "--metadata"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.NoError(t, err)
			assert.NotContains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("ok - print document only", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDRsolution})
			cmd.SetArgs([]string{"resolve", "did", "--document"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.NoError(t, err)
			assert.Contains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.NotContains(t, buf.String(), "version")
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("error - not found", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusNotFound, ResponseData: "not found"})
			cmd.SetArgs([]string{"resolve", "did"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.Error(t, err)
			assert.Contains(t, errBuf.String(), "failed to resolve DID document")
		})
	})

	t.Run("conflicted", func(t *testing.T) {
		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: []v1.DIDResolutionResult{exampleDIDRsolution}})
			cmd.SetArgs([]string{"conflicted"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.NoError(t, err)
			assert.Contains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("ok - print metadata only", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: []v1.DIDResolutionResult{exampleDIDRsolution}})
			cmd.SetArgs([]string{"conflicted", "--metadata"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.NoError(t, err)
			assert.NotContains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("ok - print document only", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: []v1.DIDResolutionResult{exampleDIDRsolution}})
			cmd.SetArgs([]string{"conflicted", "--document"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.NoError(t, err)
			assert.Contains(t, buf.String(), "did:nuts:Fx8kamg7Bom4gyEzmJc9t9QmWTkCwSxu3mrp3CbkehR7")
			assert.NotContains(t, buf.String(), "version")
			assert.Empty(t, errBuf.Bytes())
		})
	})

	t.Run("update", func(t *testing.T) {
		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			cmd.SetArgs([]string{"update", "did", "hash", "../test/diddocument.json"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.NoError(t, err)
			assert.Contains(t, buf.String(), "DID document updated")
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("error - incorrect input", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: exampleDIDDocument})
			cmd.SetArgs([]string{"update", "did", "hash", "../test/syntax_error.json"})

			err := cmd.Execute()

			assert.Error(t, err)
			assert.Contains(t, errBuf.String(), "failed to parse DID document")
		})

		t.Run("error - server error", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: "invalid"})
			cmd.SetArgs([]string{"update", "did", "hash", "../test/diddocument.json"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.Error(t, err)
			assert.Contains(t, errBuf.String(), "failed to update DID document")
		})
	})

	t.Run("deactivate", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK})

			inBuf.Write([]byte{'y', '\n'})
			cmd.SetArgs([]string{"deactivate", "did"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.NoError(t, err)
			assert.Contains(t, buf.String(), "This will delete the DID document, are you sure?")
			assert.Contains(t, buf.String(), "DID document deactivated\n")
			assert.Empty(t, errBuf.Bytes())
		})
		t.Run("ok - stops when the user does not confirm", func(t *testing.T) {
			cmd := newCmd(t)

			inBuf.Write([]byte{'n', '\n'})
			cmd.SetArgs([]string{"deactivate", "did"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.Nil(t, err)
			assert.Contains(t, buf.String(), "Deactivation cancelled")
			assert.Empty(t, errBuf.Bytes())
		})

		t.Run("error - DID document not found", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusNotFound})

			inBuf.Write([]byte{'y', '\n'})
			cmd.SetArgs([]string{"deactivate", "did"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()

			assert.Error(t, err)
			assert.Contains(t, errBuf.String(), "failed to deactivate DID document: server returned HTTP 404 (expected: 200)")
		})
	})

	t.Run("addVerificationMethod", func(t *testing.T) {
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		verificationMethod, _ := did.NewVerificationMethod(vdr.TestMethodDIDA, ssi.JsonWebKey2020, vdr.TestDIDA, pair.PublicKey)

		t.Run("ok", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: verificationMethod})

			cmd.SetArgs([]string{"addvm", vdr.TestDIDA.String()})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
			err := cmd.Execute()

			require.NoError(t, err)
			require.Contains(t, buf.String(), vdr.TestMethodDIDA.String())
			resultingMethod := did.VerificationMethod{}
			err = json.Unmarshal(buf.Bytes(), &resultingMethod)
			assert.NoError(t, err)
			assert.Equal(t, *verificationMethod, resultingMethod)
			assert.Empty(t, errBuf.Bytes())

		})

		t.Run("error - DID document not found", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusNotFound})

			cmd.SetArgs([]string{"addvm", vdr.TestDIDA.String()})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, errBuf.String(), "failed to add a new verification method to DID document: server returned HTTP 404 (expected: 200)")
		})
	})

	t.Run("deleteVerificationMethod", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusNoContent})
			cmd.SetArgs([]string{"delvm", vdr.TestDIDA.String(), vdr.TestMethodDIDA.String()})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
			err := cmd.Execute()

			require.NoError(t, err)
			assert.Empty(t, errBuf.String())
		})

		t.Run("error - DID document not found", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusNotFound})

			cmd.SetArgs([]string{"delvm", vdr.TestDIDA.String(), vdr.TestMethodDIDA.String()})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
			err := cmd.Execute()
			require.Error(t, err)
			assert.Contains(t, errBuf.String(), "failed to delete the verification method from DID document: server returned HTTP 404 (expected: 204)")
		})
	})

	t.Run("addKeyAgreement", func(t *testing.T) {
		pair, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		verificationMethod, _ := did.NewVerificationMethod(vdr.TestMethodDIDA, ssi.JsonWebKey2020, vdr.TestDIDA, pair.PublicKey)

		kid := verificationMethod.ID

		t.Run("ok", func(t *testing.T) {
			document := did.Document{}
			document.ID = vdr.TestDIDA
			document.VerificationMethod.Add(verificationMethod)
			resolution := v1.DIDResolutionResult{
				Document:         document,
				DocumentMetadata: v1.DIDDocumentMetadata{},
			}
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: resolution})

			cmd.SetArgs([]string{"add-keyagreement", kid.String()})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
			err := cmd.Execute()

			assert.NoError(t, err)
		})

		t.Run("error - DID document is deactivated", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: v1.DIDResolutionResult{
				Document:         did.Document{ID: vdr.TestDIDA},
				DocumentMetadata: v1.DIDDocumentMetadata{Deactivated: true},
			}})

			cmd.SetArgs([]string{"add-keyagreement", kid.String()})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
			err := cmd.Execute()

			assert.Error(t, err)
			assert.Contains(t, errBuf.String(), "Error: DID document is deactivated")
		})

		t.Run("error - KID is not a DID URL", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK})

			cmd.SetArgs([]string{"add-keyagreement", "not a DID"})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
			err := cmd.Execute()

			assert.Error(t, err)
			assert.Contains(t, errBuf.String(), "Error: invalid key ID 'not a DID'")
		})

		t.Run("error - KID does not refer to an existing verification method key", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusOK, ResponseData: did.Document{}})

			cmd.SetArgs([]string{"add-keyagreement", kid.String()})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
			err := cmd.Execute()

			assert.Error(t, err)
			assert.Contains(t, errBuf.String(), "specified KID is not a verification method in the resolved DID document")
		})

		t.Run("error - DID document not found", func(t *testing.T) {
			cmd := newCmdWithServer(t, &http2.Handler{StatusCode: http.StatusNotFound})

			cmd.SetArgs([]string{"add-keyagreement", kid.String()})
			cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
			err := cmd.Execute()

			assert.Error(t, err)
			assert.Contains(t, errBuf.String(), "Error: server returned HTTP 404")
		})
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
