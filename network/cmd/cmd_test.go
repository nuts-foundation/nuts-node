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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/nuts-foundation/nuts-node/network/api/v1"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/stretchr/testify/assert"
)

func TestFlagSet(t *testing.T) {
	t.Run("check if a at least some value is set", func(t *testing.T) {
		flagset := FlagSet()
		assert.NotNil(t, flagset)
		value, err := flagset.GetInt("network.connectiontimeout")
		assert.NoError(t, err)
		assert.Equal(t, 5000, value)
	})
}

func TestConvertRange(t *testing.T) {
	t.Run("it ignores empty ranges", func(t *testing.T) {
		assert.Nil(t, convertRange(""))
	})

	t.Run("it converts positive ints", func(t *testing.T) {
		i := convertRange("5")
		assert.NotNil(t, i)
		assert.Equal(t, *i, 5)
	})

	t.Run("it ignores negative ints", func(t *testing.T) {
		assert.Panics(t, func() { convertRange("-5") })
	})
}

// Test the 'nuts network list' command.
func TestCmd_List(t *testing.T) {
	// Create 3 transactions
	t1 := dag.CreateSignedTestTransaction(1, time.Now().Add(time.Duration(0)*time.Second), nil, "zfoo/bar", true)
	t2 := dag.CreateSignedTestTransaction(1, time.Now().Add(time.Duration(60)*time.Second), nil, "bar/foo", true)
	t3 := dag.CreateSignedTestTransaction(1, time.Now().Add(time.Duration(30)*time.Second), nil, "1foo/bar", true)
	// mock the sever response
	response := []interface{}{string(t1.Data()), string(t2.Data()), string(t3.Data())}
	// start the mock server
	s := httptest.NewServer(&http2.Handler{StatusCode: http.StatusOK, ResponseData: response})
	defer s.Close()

	t.Run("it lists sorted by time on default", func(t *testing.T) {
		// make sure the test connects to the mock server
		t.Setenv("NUTS_ADDRESS", s.URL)

		outBuf := new(bytes.Buffer)
		networkCmd := Cmd()
		networkCmd.SetOut(outBuf)
		networkCmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		networkCmd.SetArgs([]string{"list"})

		err := networkCmd.Execute()
		assert.NoError(t, err)
		lines := strings.Split(outBuf.String(), "\n")
		require.Len(t, lines, 5)
		hashStr1 := strings.Split(lines[1], "  ")[0]
		hashStr2 := strings.Split(lines[2], "  ")[0]
		hashStr3 := strings.Split(lines[3], "  ")[0]
		assert.Equal(t, t1.Ref().String(), hashStr1)
		assert.Equal(t, t3.Ref().String(), hashStr2)
		assert.Equal(t, t2.Ref().String(), hashStr3)
	})

	t.Run("it sorts by type", func(t *testing.T) {
		t.Setenv("NUTS_ADDRESS", s.URL)

		outBuf := new(bytes.Buffer)
		cmd := Cmd()
		cmd.SetOut(outBuf)
		cmd.SetArgs([]string{"list", "--sort", "type"})
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
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

	t.Run("it handles an http error", func(t *testing.T) {
		cmd := Cmd()
		cmd.SetArgs([]string{"list"})
		assert.EqualError(t, cmd.Execute(), "unable to list transactions: Get \"http:///internal/network/v1/transaction\": http: no Host in request URL")
	})

}

func TestCmd_Get(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cmd := Cmd()
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		response := dag.CreateTestTransactionWithJWK(1)
		handler := &http2.Handler{StatusCode: http.StatusOK, ResponseData: string(response.Data())}
		s := httptest.NewServer(handler)
		t.Setenv("NUTS_ADDRESS", s.URL)
		defer s.Close()
		cmd.SetArgs([]string{"get", response.Ref().String()})
		err := cmd.Execute()
		assert.NoError(t, err)
	})
	t.Run("not found", func(t *testing.T) {
		cmd := Cmd()
		outBuf := new(bytes.Buffer)
		cmd.SetOut(outBuf)
		cmd.SetErr(outBuf)

		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		handler := &http2.Handler{StatusCode: http.StatusNotFound, ResponseData: "not found"}
		s := httptest.NewServer(handler)
		t.Setenv("NUTS_ADDRESS", s.URL)
		defer s.Close()
		hashString := hash.SHA256Sum([]byte{1, 2, 3}).String()
		cmd.SetArgs([]string{"get", hashString})
		err := cmd.Execute()
		assert.NoError(t, err)
		expected := fmt.Sprintf("Transaction not found: %s", hashString)
		assert.Equal(t, expected, outBuf.String())
	})

	t.Run("it checks the hash format", func(t *testing.T) {
		cmd := Cmd()
		cmd.SetArgs([]string{"get", "invalid format"})
		assert.EqualError(t, cmd.Execute(), "encoding/hex: invalid byte: U+0069 'i'")
	})

	t.Run("it handles an http error", func(t *testing.T) {
		cmd := Cmd()
		cmd.SetArgs([]string{"get", hash.SHA256Sum([]byte{1, 2, 3}).String()})
		assert.EqualError(t, cmd.Execute(), "unable to get transaction: Get \"http:///internal/network/v1/transaction/039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81\": http: no Host in request URL")
	})
}

func TestCmd_Payload(t *testing.T) {

	t.Run("ok", func(t *testing.T) {
		cmd := Cmd()
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		handler := &http2.Handler{StatusCode: http.StatusOK, ResponseData: []byte("Hello, World!")}
		s := httptest.NewServer(handler)
		t.Setenv("NUTS_ADDRESS", s.URL)
		defer s.Close()
		h := hash.SHA256Sum([]byte{1, 2, 3})
		cmd.SetArgs([]string{"payload", h.String()})
		err := cmd.Execute()
		assert.NoError(t, err)
	})
	t.Run("not found", func(t *testing.T) {
		handler := &http2.Handler{StatusCode: http.StatusNotFound, ResponseData: []byte("Hello, World!")}
		s := httptest.NewServer(handler)
		t.Setenv("NUTS_ADDRESS", s.URL)
		defer s.Close()
		cmd := Cmd()
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		h := hash.SHA256Sum([]byte{1, 2, 3})
		cmd.SetArgs([]string{"payload", h.String()})
		err := cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("it checks the hash format", func(t *testing.T) {
		cmd := Cmd()
		cmd.SetArgs([]string{"payload", "invalid format"})
		assert.EqualError(t, cmd.Execute(), "encoding/hex: invalid byte: U+0069 'i'")
	})

	t.Run("it handles an http error", func(t *testing.T) {
		cmd := Cmd()
		h := hash.SHA256Sum([]byte{1, 2, 3})
		cmd.SetArgs([]string{"payload", h.String()})
		assert.EqualError(t, cmd.Execute(), "unable to get transaction payload: Get \"http:///internal/network/v1/transaction/039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81/payload\": http: no Host in request URL")
	})
}

func TestCmd_Peers(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cmd := Cmd()
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		handler := &http2.Handler{StatusCode: http.StatusOK, ResponseData: map[string]v1.PeerDiagnostics{"foo": {Uptime: 50 * time.Second}}}
		s := httptest.NewServer(handler)
		t.Setenv("NUTS_ADDRESS", s.URL)
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
	})

	t.Run("it handles an http error", func(t *testing.T) {
		cmd := Cmd()
		cmd.SetArgs([]string{"peers"})
		assert.EqualError(t, cmd.Execute(), "unable to get peer diagnostics: Get \"http:///internal/network/v1/diagnostics/peers\": http: no Host in request URL")
	})
}

func TestCmd_Reprocess(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cmd := Cmd()
		handler := &http2.Handler{StatusCode: http.StatusAccepted}
		s := httptest.NewServer(handler)
		t.Setenv("NUTS_ADDRESS", s.URL)
		cmd.PersistentFlags().AddFlagSet(core.ClientConfigFlags())
		defer s.Close()
		cmd.SetArgs([]string{"reprocess", "application/did+json"})
		err := cmd.Execute()
		assert.NoError(t, err)
	})

	t.Run("missing type", func(t *testing.T) {
		cmd := Cmd()
		handler := &http2.Handler{StatusCode: http.StatusBadRequest, ResponseData: "{\"detail\":\"missing type\"}"}
		s := httptest.NewServer(handler)
		t.Setenv("NUTS_ADDRESS", s.URL)
		defer s.Close()
		cmd.SetArgs([]string{"reprocess", "application/did+json"})
		expected := "Usage:\n  network reprocess [contentType]"

		outBuf := new(bytes.Buffer)
		cmd.SetOut(outBuf)

		_ = cmd.Execute()
		assert.Contains(t, outBuf.String(), expected)
	})

	t.Run("it handles an http error", func(t *testing.T) {
		cmd := Cmd()
		cmd.SetArgs([]string{"reprocess", "application/did+json"})
		assert.EqualError(t, cmd.Execute(), "unable to reprocess transactions: Post \"http:///internal/network/v1/reprocess?type=application%2Fdid%2Bjson\": http: no Host in request URL")
	})
}
