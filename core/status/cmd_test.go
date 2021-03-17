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

package status

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/stretchr/testify/assert"
)

func TestEngine_Command(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cmd := Cmd()
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: "diagnostics"})
		os.Setenv("NUTS_ADDRESS", s.URL)
		defer os.Unsetenv("NUTS_ADDRESS")
		core.NewServerConfig().Load(cmd)
		defer s.Close()

		buf := new(bytes.Buffer)
		cmd.SetArgs([]string{"status"})
		cmd.SetOut(buf)
		err := cmd.Execute()
		assert.NoError(t, err)
		assert.Equal(t, "diagnostics\n", buf.String())
	})
	t.Run("unexpected status code", func(t *testing.T) {
		cmd := Cmd()
		s := httptest.NewServer(http2.Handler{StatusCode: http.StatusInternalServerError, ResponseData: ""})
		os.Setenv("NUTS_ADDRESS", s.URL)
		defer os.Unsetenv("NUTS_ADDRESS")
		core.NewServerConfig().Load(cmd)
		defer s.Close()

		buf := new(bytes.Buffer)
		cmd.SetArgs([]string{"status"})
		cmd.SetOut(buf)
		err := cmd.Execute()
		assert.Error(t, err)
	})
}
