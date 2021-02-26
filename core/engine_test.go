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

package core

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
)

func TestNewSystem(t *testing.T) {
	system := NewSystem()
	assert.NotNil(t, system)
	assert.Empty(t, system.engines)
}

func TestSystem_Start(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	r := NewMockRunnable(ctrl)
	r.EXPECT().Start()

	system := NewSystem()
	system.RegisterEngine(TestEngine{})
	system.RegisterEngine(r)
	assert.NoError(t, system.Start())
}

func TestSystem_Shutdown(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	r := NewMockRunnable(ctrl)
	r.EXPECT().Shutdown()

	system := NewSystem()
	system.RegisterEngine(TestEngine{})
	system.RegisterEngine(r)
	assert.Nil(t, system.Shutdown())
}

func TestSystem_Configure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		r := NewMockConfigurable(ctrl)
		r.EXPECT().Configure(gomock.Any())

		system := NewSystem()
		system.RegisterEngine(TestEngine{})
		system.RegisterEngine(r)
		assert.Nil(t, system.Configure())
	})
	t.Run("unable to create datadir", func(t *testing.T) {
		system := NewSystem()
		system.Config = &ServerConfig{Datadir: "engine_test.go"}
		assert.Error(t, system.Configure())
	})
}

func TestSystem_DefaultEchoServer(t *testing.T) {
	system := NewSystem()
	assert.NotNil(t, system.EchoCreator())
}

func TestSystem_Diagnostics(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	r := NewMockDiagnosable(ctrl)
	r.EXPECT().Diagnostics().Return([]DiagnosticResult{&GenericDiagnosticResult{Title: "Result"}})

	system := NewSystem()
	system.RegisterEngine(TestEngine{})
	system.RegisterEngine(r)
	assert.Len(t, system.Diagnostics(), 1)
}

func TestSystem_RegisterEngine(t *testing.T) {
	t.Run("adds an engine to the list", func(t *testing.T) {
		ctl := System{
			engines: []Engine{},
		}
		ctl.RegisterEngine(TestEngine{})

		if len(ctl.engines) != 1 {
			t.Errorf("Expected 1 registered engine, Got %d", len(ctl.engines))
		}
	})
}

func TestSystem_VisitEnginesE(t *testing.T) {
	ctl := System{
		engines: []Engine{},
	}
	ctl.RegisterEngine(&TestEngine{})
	ctl.RegisterEngine(&TestEngine{})
	expectedErr := errors.New("function should stop because an error occurred")
	timesCalled := 0
	actualErr := ctl.VisitEnginesE(func(engine Engine) error {
		timesCalled++
		return expectedErr
	})
	assert.Equal(t, 1, timesCalled)
	assert.Equal(t, expectedErr, actualErr)
}

func TestSystem_Load(t *testing.T) {
	cmd := &cobra.Command{}
	e := &TestEngine{
		flagSet:    &pflag.FlagSet{},
		TestConfig: TestEngineConfig{},
	}
	ctl := System{
		engines: []Engine{e},
		Config:  NewServerConfig(),
	}
	e.FlagSet().String("key", "", "")
	os.Args = []string{"command", "--key", "value"}
	cmd.PersistentFlags().AddFlagSet(e.FlagSet())
	cmd.PersistentFlags().AddFlagSet(FlagSet())

	t.Run("loads Config without error", func(t *testing.T) {
		assert.NoError(t, ctl.Load(cmd))
	})

	t.Run("calls inject into engine", func(t *testing.T) {
		ctl.Load(cmd)
		assert.Equal(t, "value", e.TestConfig.Key)
	})
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
