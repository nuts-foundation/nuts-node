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

package cmd

import (
	"bytes"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/json"
	v2 "github.com/nuts-foundation/nuts-node/vcr/api/vcr/v2"
	"github.com/stretchr/testify/require"
	"net/http"
	"net/http/httptest"
	"testing"

	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

// TestCmd_Trust tests the nuts vcr trust related commands
func TestCmd_Trust(t *testing.T) {
	didString := "did:nuts:1"
	credentialType := "type"

	buf := new(bytes.Buffer)

	// Setup new VCR commands with output to a bytes buffer
	newCmd := func(t *testing.T) *cobra.Command {
		t.Helper()
		buf.Reset()
		command := Cmd()
		command.SetOut(buf)
		return command
	}

	cmds := []string{
		"list-trusted",
		"list-untrusted",
	}

	for _, c := range cmds {
		t.Run(c, func(t *testing.T) {
			t.Run("ok", func(t *testing.T) {
				cmd := newCmd(t)
				_ = setupServer(t, http.StatusOK, []string{didString})

				cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

				cmd.SetArgs([]string{c, credentialType})
				err := cmd.Execute()

				require.NoError(t, err)
				assert.Contains(t, buf.String(), didString)
			})

			t.Run("error - server error", func(t *testing.T) {
				cmd := newCmd(t)
				_ = setupServer(t, http.StatusInternalServerError, nil)
				cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

				cmd.SetArgs([]string{c, credentialType})
				err := cmd.Execute()

				assert.ErrorContains(t, err, "server returned HTTP 500")
			})

			t.Run("error - not enough args", func(t *testing.T) {
				cmd := newCmd(t)

				cmd.SetArgs([]string{c})
				err := cmd.Execute()

				assert.Error(t, err)
			})

			t.Run("it handles an http error", func(t *testing.T) {
				cmd := Cmd()
				cmd.SetArgs([]string{c, credentialType})
				err := cmd.Execute()
				assert.Contains(t, err.Error(), "no Host in request URL")
			})
		})
	}

	cmds2 := []string{
		"trust",
		"untrust",
	}

	for _, c := range cmds2 {
		t.Run(c, func(t *testing.T) {
			t.Run("ok", func(t *testing.T) {
				cmd := newCmd(t)
				_ = setupServer(t, http.StatusNoContent, nil)
				cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

				cmd.SetArgs([]string{c, credentialType, didString})
				err := cmd.Execute()

				require.NoError(t, err)
				assert.Contains(t, buf.String(), didString)
				assert.Contains(t, buf.String(), credentialType)
			})

			t.Run("error - server error", func(t *testing.T) {
				cmd := newCmd(t)
				_ = setupServer(t, http.StatusInternalServerError, nil)
				cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

				cmd.SetArgs([]string{c, credentialType, didString})
				err := cmd.Execute()

				assert.ErrorContains(t, err, "server returned HTTP 500")
			})

			t.Run("error - not enough args", func(t *testing.T) {
				cmd := newCmd(t)

				cmd.SetArgs([]string{c})
				err := cmd.Execute()

				assert.Error(t, err)
			})

			t.Run("it handles an http error", func(t *testing.T) {
				cmd := Cmd()
				cmd.SetArgs([]string{c, credentialType, didString})
				err := cmd.Execute()
				assert.Contains(t, err.Error(), "no Host in request URL")
			})

		})
	}
}

func TestCmd_Issue(t *testing.T) {
	const issuerDID = "did:nuts:1"
	const credentialType = "VCType"
	var credentialTypeAPI v2.IssueVCRequest_Type
	require.NoError(t, credentialTypeAPI.FromIssueVCRequestType0(credentialType))
	const credentialSubject = `{"ID": "did:nuts:subject"}`
	var contextURI = "http://context"
	var contextURIAPI v2.IssueVCRequest_Context
	require.NoError(t, contextURIAPI.FromIssueVCRequestContext0(contextURI))
	var visibility = v2.IssueVCRequestVisibility("private")
	truep := func() *bool { t := true; return &t }

	buf := new(bytes.Buffer)

	// Setup new VCR commands with output to a bytes buffer
	newCmd := func(t *testing.T) *cobra.Command {
		t.Helper()
		buf.Reset()
		command := Cmd()
		command.SetOut(buf)
		return command
	}

	t.Run("ok", func(t *testing.T) {
		cmd := newCmd(t)
		handler := setupServer(t, http.StatusOK, "{}")
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		cmd.SetArgs([]string{"issue", contextURI, credentialType, issuerDID, credentialSubject})

		err := cmd.Execute()

		assert.NoError(t, err)
		var request = v2.IssueVCRequest{
			Context: &contextURIAPI,
			CredentialSubject: map[string]interface{}{
				"ID": "did:nuts:subject",
			},
			Issuer:           issuerDID,
			PublishToNetwork: truep(),
			Type:             credentialTypeAPI,
			Visibility:       &visibility,
		}
		expected, _ := json.Marshal(request)
		assert.JSONEq(t, string(expected), string(handler.RequestData))
	})
	t.Run("ok - plural parameters", func(t *testing.T) {
		otherContextURI := "http://other-context"
		var contextURIsAPI v2.IssueVCRequest_Context
		require.NoError(t, contextURIsAPI.FromIssueVCRequestContext1([]string{contextURI, otherContextURI}))
		otherCredentialType := "other-type"
		var credentialTypesAPI v2.IssueVCRequest_Type
		require.NoError(t, credentialTypesAPI.FromIssueVCRequestType1([]string{credentialType, otherCredentialType}))
		cmd := newCmd(t)
		handler := setupServer(t, http.StatusOK, "{}")
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		cmd.SetArgs([]string{"issue", fmt.Sprintf("%s,%s", contextURI, otherContextURI), fmt.Sprintf("%s,%s", credentialType, otherCredentialType), issuerDID, credentialSubject})

		err := cmd.Execute()

		assert.NoError(t, err)
		var request = v2.IssueVCRequest{
			Context: &contextURIsAPI,
			CredentialSubject: map[string]interface{}{
				"ID": "did:nuts:subject",
			},
			Issuer:           issuerDID,
			PublishToNetwork: truep(),
			Type:             credentialTypesAPI,
			Visibility:       &visibility,
		}
		expected, _ := json.Marshal(request)
		assert.JSONEq(t, string(expected), string(handler.RequestData))
	})
	t.Run("ok - with expiration date", func(t *testing.T) {
		var expirationDate = "2022-09-15T20:03:53.8489928Z"
		cmd := newCmd(t)
		handler := setupServer(t, http.StatusOK, "{}")
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		cmd.SetArgs([]string{"issue", "--expiration=" + expirationDate, contextURI, credentialType, issuerDID, credentialSubject})

		err := cmd.Execute()

		assert.NoError(t, err)
		var request = v2.IssueVCRequest{
			Context: &contextURIAPI,
			CredentialSubject: map[string]interface{}{
				"ID": "did:nuts:subject",
			},
			Issuer:           issuerDID,
			PublishToNetwork: truep(),
			Type:             credentialTypeAPI,
			Visibility:       &visibility,
			ExpirationDate:   &expirationDate,
		}
		expected, _ := json.Marshal(request)
		assert.JSONEq(t, string(expected), string(handler.RequestData))
	})
	t.Run("ok - do not publish", func(t *testing.T) {
		cmd := newCmd(t)
		handler := setupServer(t, http.StatusOK, "{}")
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		cmd.SetArgs([]string{"issue", "--publish=false", contextURI, credentialType, issuerDID, credentialSubject})

		err := cmd.Execute()

		assert.NoError(t, err)
		var request = v2.IssueVCRequest{
			Context: &contextURIAPI,
			CredentialSubject: map[string]interface{}{
				"ID": "did:nuts:subject",
			},
			Issuer:           issuerDID,
			PublishToNetwork: new(bool),
			Type:             credentialTypeAPI,
		}
		expected, _ := json.Marshal(request)
		assert.JSONEq(t, string(expected), string(handler.RequestData))
	})
	t.Run("error - invalid subject", func(t *testing.T) {
		cmd := newCmd(t)
		_ = setupServer(t, http.StatusOK, "{}")
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		cmd.SetArgs([]string{"issue", contextURI, credentialType, issuerDID, `""`})

		err := cmd.Execute()

		assert.ErrorContains(t, err, "invalid credential subject")
	})
	t.Run("error - server error", func(t *testing.T) {
		cmd := newCmd(t)
		_ = setupServer(t, http.StatusInternalServerError, "{}")
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		cmd.SetArgs([]string{"issue", contextURI, credentialType, issuerDID, `{}`})

		err := cmd.Execute()

		assert.ErrorContains(t, err, "server returned HTTP 500")
	})
}

func setupServer(t *testing.T, statusCode int, responseData interface{}) *http2.Handler {
	handler := &http2.Handler{StatusCode: statusCode, ResponseData: responseData}
	s := httptest.NewServer(handler)
	t.Setenv("NUTS_ADDRESS", s.URL)
	t.Cleanup(s.Close)
	return handler
}
