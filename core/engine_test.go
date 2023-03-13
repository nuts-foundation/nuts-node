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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/golang/mock/gomock"
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

	r := NewMockRunnable(ctrl)
	r.EXPECT().Start()

	system := NewSystem()
	system.RegisterEngine(TestEngine{})
	system.RegisterEngine(r)
	assert.NoError(t, system.Start())
}

func TestSystem_Shutdown(t *testing.T) {
	t.Run("returns error", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		r := NewMockRunnable(ctrl)
		r.EXPECT().Shutdown().Return(errors.New("failure"))

		system := NewSystem()
		system.RegisterEngine(r)

		assert.EqualError(t, system.Shutdown(), "failure")
	})
	t.Run("start and shutdown are called in opposite order", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		r1 := NewMockRunnable(ctrl)
		r2 := NewMockRunnable(ctrl)

		gomock.InOrder(
			r1.EXPECT().Start(),
			r2.EXPECT().Start(),
		)

		gomock.InOrder(
			r2.EXPECT().Shutdown(),
			r1.EXPECT().Shutdown(),
		)

		system := NewSystem()
		system.RegisterEngine(r1)
		system.RegisterEngine(r2)

		_ = system.Start()
		_ = system.Shutdown()
	})

}

func TestSystem_Configure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		r := NewMockConfigurable(ctrl)
		r.EXPECT().Configure(gomock.Any())

		system := NewSystem()
		system.RegisterEngine(TestEngine{})
		system.RegisterEngine(r)
		assert.NoError(t, system.Load(FlagSet()))
		assert.Nil(t, system.Configure())
	})
	t.Run("unable to create datadir", func(t *testing.T) {
		system := NewSystem()
		system.Config.Datadir = "engine_test.go"
		assert.Error(t, system.Configure())
	})
}

func TestSystem_Migrate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		r := NewMockMigratable(ctrl)
		system := NewSystem()
		system.RegisterEngine(r)

		r.EXPECT().Migrate()

		assert.NoError(t, system.Migrate())
	})
	t.Run("error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		r := NewMockMigratable(ctrl)
		system := NewSystem()
		system.RegisterEngine(r)

		r.EXPECT().Migrate().Return(errors.New("b00m!"))

		assert.Error(t, system.Migrate())
	})
}

func TestSystem_Diagnostics(t *testing.T) {
	ctrl := gomock.NewController(t)

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
	cmd := testCommand()
	e := &TestEngine{
		flagSet:    testFlagSet(),
		TestConfig: TestEngineConfig{},
	}
	ctl := System{
		engines: []Engine{e},
		Config:  NewServerConfig(),
	}
	e.FlagSet().String("key", "", "")
	cmd.Flags().AddFlagSet(FlagSet())
	cmd.Flags().AddFlagSet(e.flagSet)
	err := e.FlagSet().Parse([]string{"--testengine.key", "value"})
	require.NoError(t, err)

	t.Run("loads Config without error", func(t *testing.T) {
		assert.NoError(t, ctl.Load(cmd.Flags()))
	})

	t.Run("calls inject into engine", func(t *testing.T) {
		ctl.Load(cmd.Flags())
		assert.Equal(t, "value", e.TestConfig.Key)
	})

	t.Run("slice flags are loaded once", func(t *testing.T) {
		flagSet := pflag.NewFlagSet("test", pflag.PanicOnError)
		flagSet.StringSlice("f", []string{}, "")
		type Target struct {
			F []string `koanf:"f"`
		}
		var target Target

		assert.NoError(t, flagSet.Parse([]string{"command", "--f", "once"}))
		assert.NoError(t, ctl.Config.Load(flagSet))
		assert.NoError(t, loadConfigIntoStruct(&target, ctl.Config.configMap))
		require.Len(t, target.F, 1)
		assert.Equal(t, "once", target.F[0])
	})
}
