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
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/stretchr/testify/assert"
)

func TestFlagSet(t *testing.T) {
	assert.NotNil(t, FlagSet())
}

func TestCmd_List(t *testing.T) {
	cmd := Cmd()
	response := []interface{}{string(dag.CreateTestDocumentWithJWK(1).Data()), string(dag.CreateTestDocumentWithJWK(2).Data())}
	s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: response})
	os.Setenv("NUTS_ADDRESS", s.URL)
	core.NewNutsConfig().Load(cmd)
	defer s.Close()

	cmd.SetArgs([]string{"list"})
	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestCmd_Get(t *testing.T) {
	cmd := Cmd()
	response := dag.CreateTestDocumentWithJWK(1)
	handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: string(response.Data())}
	s := httptest.NewServer(handler)
	os.Setenv("NUTS_ADDRESS", s.URL)
	core.NewNutsConfig().Load(cmd)
	defer s.Close()

	t.Run("ok", func(t *testing.T) {
		cmd.SetArgs([]string{"get", response.Ref().String()})
		err := cmd.Execute()
		assert.NoError(t, err)
	})
	t.Run("not found", func(t *testing.T) {
		handler.StatusCode = http.StatusNotFound
		handler.ResponseData = []byte("not found")
		cmd.SetArgs([]string{"get", response.Ref().String()})
		err := cmd.Execute()
		assert.NoError(t, err)
	})
}

func TestCmd_Payload(t *testing.T) {
	cmd := Cmd()
	handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: []byte("Hello, World!")}
	s := httptest.NewServer(handler)
	os.Setenv("NUTS_ADDRESS", s.URL)
	core.NewNutsConfig().Load(cmd)
	defer s.Close()

	t.Run("ok", func(t *testing.T) {
		h := hash.SHA256Sum([]byte{1, 2, 3})
		cmd.SetArgs([]string{"payload", h.String()})
		err := cmd.Execute()
		assert.NoError(t, err)
	})
	t.Run("not found", func(t *testing.T) {
		h := hash.SHA256Sum([]byte{1, 2, 3})
		cmd.SetArgs([]string{"payload", h.String()})
		err := cmd.Execute()
		assert.NoError(t, err)
	})
}
