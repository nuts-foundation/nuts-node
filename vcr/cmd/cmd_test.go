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
	"github.com/nuts-foundation/nuts-node/core"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestFlagSet(t *testing.T) {
	t.Run("it returns something", func(t *testing.T) {
		flagSet := FlagSet()
		assert.NotNil(t, flagSet)
		value, err := flagSet.GetBool("vcr.overrideissueallpublic")
		assert.NoError(t, err)
		assert.True(t, value)
	})
}

// TestCmd test the nuts vcr * commands
func TestCmd(t *testing.T) {
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
				s := setupServer(cmd, http.StatusOK, []string{didString})
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
				s := setupServer(cmd, http.StatusInternalServerError, nil)
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
				s := setupServer(cmd, http.StatusNoContent, nil)
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
				s := setupServer(cmd, http.StatusInternalServerError, nil)
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

func setupServer(cmd *cobra.Command, statusCode int, responseData interface{}) *httptest.Server {
	s := httptest.NewServer(http2.Handler{StatusCode: statusCode, ResponseData: responseData})
	os.Setenv("NUTS_ADDRESS", s.URL)
	return s
}

func reset(httpServer *httptest.Server) {
	os.Unsetenv("NUTS_ADDRESS")
	httpServer.Close()
}
