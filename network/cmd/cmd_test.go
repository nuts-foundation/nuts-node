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
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	v1 "github.com/nuts-foundation/nuts-node/network/api/v1"

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
	t1 := dag.CreateSignedTestTransaction(1, time.Now().Add(time.Duration(0)*time.Second), "zfoo/bar", true)
	t2 := dag.CreateSignedTestTransaction(1, time.Now().Add(time.Duration(60)*time.Second), "bar/foo", true)
	t3 := dag.CreateSignedTestTransaction(1, time.Now().Add(time.Duration(30)*time.Second), "1foo/bar", true)
	response := []interface{}{string(t1.Data()), string(t2.Data()), string(t3.Data())}
	s := httptest.NewServer(http2.Handler{StatusCode: http.StatusOK, ResponseData: response})
	defer s.Close()

	t.Run("it lists sorted by time on default", func(t *testing.T) {
		outBuf := new(bytes.Buffer)
		cmd := Cmd()
		os.Setenv("NUTS_ADDRESS", s.URL)
		defer os.Unsetenv("NUTS_ADDRESS")
		core.NewServerConfig().Load(cmd)
		cmd.SetOut(outBuf)
		cmd.SetArgs([]string{"list"})

		err := cmd.Execute()
		assert.NoError(t, err)
		lines := strings.Split(outBuf.String(), "\n")
		assert.Len(t, lines, 5)
		hashStr1 := strings.Split(lines[1], "  ")[0]
		hashStr2 := strings.Split(lines[2], "  ")[0]
		hashStr3 := strings.Split(lines[3], "  ")[0]
		assert.Equal(t, t1.Ref().String(), hashStr1)
		assert.Equal(t, t3.Ref().String(), hashStr2)
		assert.Equal(t, t2.Ref().String(), hashStr3)
	})

	t.Run("it sorts by type", func(t *testing.T) {
		outBuf := new(bytes.Buffer)
		cmd := Cmd()
		os.Setenv("NUTS_ADDRESS", s.URL)
		defer os.Unsetenv("NUTS_ADDRESS")
		core.NewServerConfig().Load(cmd)
		cmd.SetOut(outBuf)
		cmd.SetArgs([]string{"list", "--sort", "type"})
		err := cmd.Execute()
		assert.NoError(t, err)
		lines := strings.Split(outBuf.String(), "\n")
		assert.Len(t, lines, 5)

		hashStr1 := strings.Split(lines[1], "  ")[0]
		hashStr2 := strings.Split(lines[2], "  ")[0]
		hashStr3 := strings.Split(lines[3], "  ")[0]
		assert.Equal(t, t3.Ref().String(), hashStr1)
		assert.Equal(t, t2.Ref().String(), hashStr2)
		assert.Equal(t, t1.Ref().String(), hashStr3)
	})
	sortTransactions([]dag.Transaction{}, "foo")
}

func TestCmd_Get(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cmd := Cmd()
		response := dag.CreateTestTransactionWithJWK(1, hash.SHA256Sum([]byte{1, 2, 3}))
		handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: string(response.Data())}
		s := httptest.NewServer(handler)
		os.Setenv("NUTS_ADDRESS", s.URL)
		defer os.Unsetenv("NUTS_ADDRESS")
		core.NewServerConfig().Load(cmd)
		defer s.Close()
		cmd.SetArgs([]string{"get", response.Ref().String()})
		err := cmd.Execute()
		assert.NoError(t, err)
	})
	t.Run("not found", func(t *testing.T) {
		cmd := Cmd()
		handler := http2.Handler{StatusCode: http.StatusNotFound, ResponseData: "not found"}
		s := httptest.NewServer(handler)
		os.Setenv("NUTS_ADDRESS", s.URL)
		defer os.Unsetenv("NUTS_ADDRESS")
		core.NewServerConfig().Load(cmd)
		defer s.Close()
		cmd.SetArgs([]string{"get", hash.SHA256Sum([]byte{1, 2, 3}).String()})
		err := cmd.Execute()
		assert.NoError(t, err)
	})
}

func TestCmd_Payload(t *testing.T) {
	cmd := Cmd()
	handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: []byte("Hello, World!")}
	s := httptest.NewServer(handler)
	os.Setenv("NUTS_ADDRESS", s.URL)
	defer os.Unsetenv("NUTS_ADDRESS")
	core.NewServerConfig().Load(cmd)
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

func TestCmd_Peers(t *testing.T) {
	cmd := Cmd()
	handler := http2.Handler{StatusCode: http.StatusOK, ResponseData: map[string]v1.PeerDiagnostics{"foo": {Uptime: 50 * time.Second}}}
	s := httptest.NewServer(handler)
	os.Setenv("NUTS_ADDRESS", s.URL)
	defer os.Unsetenv("NUTS_ADDRESS")
	core.NewServerConfig().Load(cmd)
	defer s.Close()

	outBuf := new(bytes.Buffer)
	cmd.SetOut(outBuf)

	expected := `Listing 1 peers:

foo
  SoftwareID:            
  SoftwareVersion:           
  Uptime:            50s
  Number of DAG TXs: 0
  Peers:             []`
	cmd.SetArgs([]string{"peers"})
	err := cmd.Execute()
	assert.Equal(t, strings.TrimSpace(expected), strings.TrimSpace(outBuf.String()))
	assert.NoError(t, err)
}
