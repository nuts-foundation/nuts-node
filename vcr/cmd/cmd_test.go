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
	"encoding/json"
	"github.com/nuts-foundation/nuts-node/core"
	v2 "github.com/nuts-foundation/nuts-node/vcr/api/v2"
	"net/http"
	"net/http/httptest"
	"os"
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
				s, _ := setupServer(http.StatusOK, []string{didString})
				defer reset(s)

				cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

				cmd.SetArgs([]string{c, credentialType})
				err := cmd.Execute()

				if !assert.NoError(t, err) {
					return
				}
				assert.Contains(t, buf.String(), didString)
			})

			t.Run("error - server error", func(t *testing.T) {
				cmd := newCmd(t)
				s, _ := setupServer(http.StatusInternalServerError, nil)
				defer reset(s)
				cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

				cmd.SetArgs([]string{c, credentialType})
				err := cmd.Execute()

				if !assert.Error(t, err) {
					return
				}

				assert.Contains(t, err.Error(), "server returned HTTP 500")
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
				s, _ := setupServer(http.StatusNoContent, nil)
				defer reset(s)
				cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

				cmd.SetArgs([]string{c, credentialType, didString})
				err := cmd.Execute()

				if !assert.NoError(t, err) {
					return
				}
				assert.Contains(t, buf.String(), didString)
				assert.Contains(t, buf.String(), credentialType)
			})

			t.Run("error - server error", func(t *testing.T) {
				cmd := newCmd(t)
				s, _ := setupServer(http.StatusInternalServerError, nil)
				defer reset(s)
				cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())

				cmd.SetArgs([]string{c, credentialType, didString})
				err := cmd.Execute()

				if !assert.Error(t, err) {
					return
				}

				assert.Contains(t, err.Error(), "server returned HTTP 500")
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
	const credentialSubject = `{"ID": "did:nuts:subject"}`
	var contextURI = "http://context"
	var visibility = v2.IssueVCRequestVisibility("private")
	var boolFalse = false
	var boolTrue = true

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
		s, handler := setupServer(http.StatusOK, "{}")
		defer reset(s)
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		cmd.SetArgs([]string{"issue", contextURI, credentialType, issuerDID, credentialSubject})

		err := cmd.Execute()

		assert.NoError(t, err)
		var request = v2.IssueVCRequest{
			Context: &contextURI,
			CredentialSubject: map[string]interface{}{
				"ID": "did:nuts:subject",
			},
			Issuer:           issuerDID,
			PublishToNetwork: &boolTrue,
			Type:             credentialType,
			Visibility:       &visibility,
		}
		expected, _ := json.Marshal(request)
		assert.JSONEq(t, string(expected), string(handler.RequestData))
	})
	t.Run("ok - with expiration date", func(t *testing.T) {
		var expirationDate = "2022-09-15T20:03:53.8489928Z"
		cmd := newCmd(t)
		s, handler := setupServer(http.StatusOK, "{}")
		defer reset(s)
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		cmd.SetArgs([]string{"issue", "--expiration=" + expirationDate, contextURI, credentialType, issuerDID, credentialSubject})

		err := cmd.Execute()

		assert.NoError(t, err)
		var request = v2.IssueVCRequest{
			Context: &contextURI,
			CredentialSubject: map[string]interface{}{
				"ID": "did:nuts:subject",
			},
			Issuer:           issuerDID,
			PublishToNetwork: &boolTrue,
			Type:             credentialType,
			Visibility:       &visibility,
			ExpirationDate:   &expirationDate,
		}
		expected, _ := json.Marshal(request)
		assert.JSONEq(t, string(expected), string(handler.RequestData))
	})
	t.Run("ok - do not publish", func(t *testing.T) {
		cmd := newCmd(t)
		s, handler := setupServer(http.StatusOK, "{}")
		defer reset(s)
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		cmd.SetArgs([]string{"issue", "--publish=false", contextURI, credentialType, issuerDID, credentialSubject})

		err := cmd.Execute()

		assert.NoError(t, err)
		var request = v2.IssueVCRequest{
			Context: &contextURI,
			CredentialSubject: map[string]interface{}{
				"ID": "did:nuts:subject",
			},
			Issuer:           issuerDID,
			PublishToNetwork: &boolFalse,
			Type:             credentialType,
		}
		expected, _ := json.Marshal(request)
		assert.JSONEq(t, string(expected), string(handler.RequestData))
	})
	t.Run("error - invalid subject", func(t *testing.T) {
		cmd := newCmd(t)
		s, _ := setupServer(http.StatusOK, "{}")
		defer reset(s)
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		cmd.SetArgs([]string{"issue", contextURI, credentialType, issuerDID, `""`})

		err := cmd.Execute()

		assert.ErrorContains(t, err, "invalid credential subject")
	})
	t.Run("error - server error", func(t *testing.T) {
		cmd := newCmd(t)
		s, _ := setupServer(http.StatusInternalServerError, "{}")
		defer reset(s)
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		cmd.SetArgs([]string{"issue", contextURI, credentialType, issuerDID, `{}`})

		err := cmd.Execute()

		assert.ErrorContains(t, err, "server returned HTTP 500")
	})
}

func setupServer(statusCode int, responseData interface{}) (*httptest.Server, *http2.Handler) {
	handler := &http2.Handler{StatusCode: statusCode, ResponseData: responseData}
	s := httptest.NewServer(handler)
	os.Setenv("NUTS_ADDRESS", s.URL)
	return s, handler
}

func reset(httpServer *httptest.Server) {
	os.Unsetenv("NUTS_ADDRESS")
	httpServer.Close()
}
