/*
 * Nuts go
 * Copyright (C) 2019 Nuts community
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

package core

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-go-core/mock"
	"github.com/stretchr/testify/assert"
)

func TestRegisterEngine(t *testing.T) {
	t.Run("adds an engine to the list", func(t *testing.T) {
		ctl := EngineControl{
			Engines: []*Engine{},
		}
		ctl.registerEngine(&Engine{})

		if len(ctl.Engines) != 1 {
			t.Errorf("Expected 1 registered engine, Got %d", len(ctl.Engines))
		}
	})
}

func TestNewStatusEngine_Routes(t *testing.T) {
	t.Run("Registers a single route for listing all engines", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockEchoRouter(ctrl)

		echo.EXPECT().GET("/status/diagnostics", gomock.Any())
		echo.EXPECT().GET("/status", gomock.Any())

		NewStatusEngine().Routes(echo)
	})
}

func TestNewStatusEngine_Cmd(t *testing.T) {
	t.Run("Cmd returns a cobra command", func(t *testing.T) {
		e := NewStatusEngine().Cmd
		assert.Equal(t, "diagnostics", e.Name())
	})

	t.Run("Executed Cmd writes diagnostics to prompt", func(t *testing.T) {
		rescueStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		NewStatusEngine().Cmd.Execute()

		w.Close()
		out, _ := ioutil.ReadAll(r)
		os.Stdout = rescueStdout

		assert.Equal(t, "", string(out))
	})
}

func TestNewStatusEngine_Diagnostics(t *testing.T) {
	RegisterEngine(NewStatusEngine())
	RegisterEngine(NewLoggerEngine())
	RegisterEngine(NewMetricsEngine())

	t.Run("diagnostics() returns engine list", func(t *testing.T) {
		ds := NewStatusEngine().Diagnostics()
		assert.Len(t, ds, 1)
		assert.Equal(t, "Registered engines", ds[0].Name())
		assert.Equal(t, "Status,Logging,Metrics", ds[0].String())
	})

	t.Run("diagnosticsOverview() renders text output of diagnostics", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echo := mock.NewMockContext(ctrl)

		echo.EXPECT().String(http.StatusOK, "Status\n\tRegistered engines: Status,Logging,Metrics\nLogging\n\tverbosity: ")

		diagnosticsOverview(echo)
	})
}

func TestStatusOK(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	echo := mock.NewMockContext(ctrl)

	echo.EXPECT().String(http.StatusOK, "OK")

	StatusOK(echo)
}

func TestDecodeURIPath(t *testing.T) {
	rawParam := "urn:oid:2.16.840.1.113883.2.4.6.1:87654321"
	encodedParam := "urn%3Aoid%3A2.16.840.1.113883.2.4.6.1%3A87654321"

	t.Run("without middleware, it returns the encoded param", func(t *testing.T) {
		e := echo.New()
		r := e.Router()
		r.Add(http.MethodGet, "/api/:someparam", func(context echo.Context) error {
			param := context.Param("someparam")
			return context.Blob(200, "text/plain", []byte(param))
		})

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/%v", encodedParam), nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		defer rec.Result().Body.Close()
		bodyBytes, _ := ioutil.ReadAll(rec.Result().Body)
		assert.Equal(t, encodedParam, string(bodyBytes))
	})

	t.Run("with middleware, it return the decoded param", func(t *testing.T) {
		e := echo.New()
		r := e.Router()
		e.Use(DecodeURIPath)
		r.Add(http.MethodGet, "/api/:someparam", func(context echo.Context) error {
			param := context.Param("someparam")
			return context.Blob(200, "text/plain", []byte(param))
		})

		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/%v", encodedParam), nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		defer rec.Result().Body.Close()
		bodyBytes, _ := ioutil.ReadAll(rec.Result().Body)
		assert.Equal(t, rawParam, string(bodyBytes))
	})
}
