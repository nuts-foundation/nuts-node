/*
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
 *
 */

package engine

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestNewEngine(t *testing.T) {
	testDirectory := io.TestDirectory(t)
	e, i := NewNetworkEngine(crypto.NewTestCryptoInstance(testDirectory))
	assert.NotNil(t, e)
	assert.NotNil(t, i)
}

func TestFlagSet(t *testing.T) {
	assert.NotNil(t, flagSet())
}

func TestCmd_List(t *testing.T) {
	cmd := createCmd(t)
	response := []interface{}{string(dag.CreateTestDocument(1).Data()), string(dag.CreateTestDocument(2).Data())}
	s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: response})
	os.Setenv("NUTS_ADDRESS", s.URL)
	core.NutsConfig().Load(cmd)
	defer s.Close()

	cmd.SetArgs([]string{"list"})
	err := cmd.Execute()
	assert.NoError(t, err)
}

func TestCmd_Get(t *testing.T) {
	cmd := createCmd(t)
	response := dag.CreateTestDocument(1)
	handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: string(response.Data())}
	s := httptest.NewServer(handler)
	os.Setenv("NUTS_ADDRESS", s.URL)
	core.NutsConfig().Load(cmd)
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
	cmd := createCmd(t)
	handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: []byte("Hello, World!")}
	s := httptest.NewServer(handler)
	os.Setenv("NUTS_ADDRESS", s.URL)
	core.NutsConfig().Load(cmd)
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

func createCmd(t *testing.T) *cobra.Command {
	core.NutsConfig().Load(&cobra.Command{})
	testDirectory := io.TestDirectory(t)
	cryptoInstance := crypto.NewTestCryptoInstance(testDirectory)
	engine, _ := NewNetworkEngine(cryptoInstance)
	return engine.Cmd
}
