/*
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
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

const grpcListenAddressEnvKey = "NUTS_NETWORK_GRPCADDR"
const enableTLSEnvKey = "NUTS_NETWORK_ENABLETLS"

func Test_rootCmd(t *testing.T) {
	ctx := context.Background()

	t.Run("no args prints help", func(t *testing.T) {
		oldStdout := stdOutWriter
		buf := new(bytes.Buffer)
		stdOutWriter = buf
		defer func() {
			stdOutWriter = oldStdout
		}()
		os.Args = []string{"nuts"}
		err := Execute(ctx, core.NewSystem())
		assert.NoError(t, err)
		actual := buf.String()
		assert.Contains(t, actual, "Available Commands")
	})

	t.Run("config cmd prints config", func(t *testing.T) {
		oldStdout := stdOutWriter
		buf := new(bytes.Buffer)
		stdOutWriter = buf
		defer func() {
			stdOutWriter = oldStdout
		}()
		os.Args = []string{"nuts", "config"}
		err := Execute(ctx, core.NewSystem())
		assert.NoError(t, err)
		actual := buf.String()
		assert.Contains(t, actual, "Current system config")
		assert.Contains(t, actual, "address")
	})

	t.Run("server commands accepts default flags", func(t *testing.T) {
		oldStdout := stdOutWriter
		buf := new(bytes.Buffer)
		stdOutWriter = buf
		defer func() {
			stdOutWriter = oldStdout
		}()
		os.Args = []string{"nuts", "help", "server"}
		err := Execute(ctx, core.NewSystem())
		assert.NoError(t, err)
		actual := buf.String()
		assert.Contains(t, actual, "--configfile string")
		assert.Contains(t, actual, "--cpuprofile string")
		assert.Contains(t, actual, "--datadir")
		assert.Contains(t, actual, "--strictmode")
		assert.Contains(t, actual, "--verbosity")
	})
}

func Test_serverCmd(t *testing.T) {
	os.Setenv("NUTS_AUTH_CONTRACTVALIDATORS", "dummy")
	defer os.Unsetenv("NUTS_AUTH_CONTRACTVALIDATORS")

	ctx := context.Background()

	t.Run("start in server mode", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		os.Setenv("NUTS_DATADIR", testDirectory)
		defer os.Unsetenv("NUTS_DATADIR")
		os.Setenv("NUTS_TESTENGINE_KEY", testDirectory)
		defer os.Unsetenv("NUTS_TESTENGINE_KEY")
		os.Args = []string{"nuts", "server"}

		engine1 := &core.TestEngine{}
		engine2 := &core.TestEngine{}

		system := core.NewSystem()
		system.RegisterEngine(engine1)
		system.RegisterEngine(engine2)

		ctx, cancelFn := context.WithCancel(ctx)
		cancelFn()
		err := Execute(ctx, system)

		assert.NoError(t, err)
		// Assert global config contains overridden property
		assert.Equal(t, testDirectory, system.Config.Datadir)
		// Assert engine config is injected
		assert.Equal(t, testDirectory, engine1.TestConfig.Key)
	})
	t.Run("output cpuprofile", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		cpuprofile := path.Join(testDirectory, "profile.dmp")
		os.Setenv("NUTS_DATADIR", testDirectory)
		defer os.Unsetenv("NUTS_DATADIR")
		os.Args = []string{"nuts", "server", fmt.Sprintf("--cpuprofile=%s", cpuprofile)}
		defer func() {
			os.Args = []string{}
		}()

		system := core.NewSystem()

		ctx, cancelFn := context.WithCancel(ctx)
		cancelFn()
		err := Execute(ctx, system)

		assert.NoError(t, err)
		_, err = os.Stat(cpuprofile)
		assert.NoError(t, err)
	})
	t.Run("unable to configure system", func(t *testing.T) {
		system := core.NewSystem()
		system.Config = core.NewServerConfig()
		system.Config.Datadir = "root_test.go"
		err := startServer(ctx, system)
		assert.Error(t, err, "unable to start")
	})
	t.Run("migration fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		r := core.NewMockMigratable(ctrl)
		system := core.NewSystem()
		system.RegisterEngine(r)
		os.Args = []string{"nuts", "server"}
		assert.NoError(t, system.Load(core.FlagSet()))

		r.EXPECT().Migrate().Return(errors.New("b00m!"))

		assert.Error(t, startServer(ctx, system))
	})
}

func Test_CreateSystem(t *testing.T) {
	system := CreateSystem(func() {

	})
	assert.NotNil(t, system)
	numEngines := 0
	system.VisitEngines(func(engine core.Engine) {
		numEngines++
	})
	assert.Equal(t, 13, numEngines)
}
