/*
 * Nuts crypto
 * Copyright (C) 2019. Nuts community
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

package engine

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/mock"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)

func TestNewCryptoEngine(t *testing.T) {
	t.Run("New returns an engine with Cmd and Routes", func(t *testing.T) {
		client := NewCryptoEngine()

		if client.Cmd == nil {
			t.Errorf("Expected Engine to have Cmd")
		}

		if client.Routes == nil {
			t.Errorf("Expected Engine to have Routes")
		}
	})
}

func TestNewCryptoEngine_Routes(t *testing.T) {
	t.Run("Registers the available routes", func(t *testing.T) {
		ce := NewCryptoEngine()
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockEchoRouter(ctrl)

		echo.EXPECT().POST("/internal/crypto/v1/sign_jwt", gomock.Any())
		echo.EXPECT().GET("/internal/crypto/v1/public_key/:kid", gomock.Any())

		ce.Routes(echo)
	})
}

type handler struct {
	statusCode   int
	responseData []byte
}

func (h handler) ServeHTTP(writer http.ResponseWriter, req *http.Request) {
	writer.WriteHeader(h.statusCode)
	writer.Write(h.responseData)
}

var jwkAsString = `
{
  "kty" : "RSA",
  "n"   : "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
  "e"   : "AQAB"
}`
var jwkAsBytes = []byte(jwkAsString)

func TestNewCryptoEngine_Cmd(t *testing.T) {
	core.NutsConfig().Load(&cobra.Command{})

	createCmd := func(t *testing.T) (*cobra.Command, *crypto.Crypto) {
		testDirectory := io.TestDirectory(t)
		instance := crypto.NewTestCryptoInstance(testDirectory)
		return NewCryptoEngine().Cmd, instance
	}

	t.Run("publicKey", func(t *testing.T) {
		t.Run("error - too few arguments", func(t *testing.T) {
			cmd, _ := createCmd(t)
			cmd.SetArgs([]string{"publicKey"})
			cmd.SetOut(ioutil.Discard)
			err := cmd.Execute()

			if assert.Error(t, err) {
				assert.Equal(t, "requires a kid argument", err.Error())
			}
		})

		t.Run("error - public key does not exist", func(t *testing.T) {
			cmd, _ := createCmd(t)
			buf := new(bytes.Buffer)
			cmd.SetArgs([]string{"publicKey", "unknown"})
			cmd.SetOut(buf)
			err := cmd.Execute()
			if !assert.NoError(t, err) {
				return
			}
		})

		t.Run("ok - write to stdout", func(t *testing.T) {
			cmd, _ := createCmd(t)
			s := httptest.NewServer(handler{statusCode: http.StatusOK, responseData: jwkAsBytes})
			os.Setenv("NUTS_ADDRESS", s.URL)
			core.NutsConfig().Load(cmd)
			defer s.Close()

			buf := new(bytes.Buffer)
			cmd.SetArgs([]string{"publicKey", "kid"})
			cmd.SetOut(buf)
			err := cmd.Execute()

			if !assert.NoError(t, err) {
				return
			}
			assert.Contains(t, buf.String(), "Public key in JWK")
			assert.Contains(t, buf.String(), "Public key in PEM")
		})
	})
}

func TestNewCryptoEngine_FlagSet(t *testing.T) {
	t.Run("Cobra help should list flags", func(t *testing.T) {
		e := NewCryptoEngine()
		cmd := newRootCommand()
		cmd.Flags().AddFlagSet(e.FlagSet)
		cmd.SetArgs([]string{"--help"})

		buf := new(bytes.Buffer)
		cmd.SetOut(buf)

		_, err := cmd.ExecuteC()

		if err != nil {
			t.Errorf("Expected no error, got %s", err.Error())
		}

		result := buf.String()

		if !strings.Contains(result, "--storage") {
			t.Errorf("Expected --storage to be command line flag")
		}

		if !strings.Contains(result, "--fspath") {
			t.Errorf("Expected --fspath to be command line flag")
		}

	})
}

func newRootCommand() *cobra.Command {
	testRootCommand := &cobra.Command{
		Use: "root",
		Run: func(cmd *cobra.Command, args []string) {

		},
	}

	return testRootCommand
}
