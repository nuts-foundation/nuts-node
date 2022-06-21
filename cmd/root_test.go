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
	"net/http"
	"os"
	"testing"

	"github.com/nuts-foundation/nuts-node/test"

	http2 "github.com/nuts-foundation/nuts-node/test/http"
	"github.com/spf13/cobra"

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
		ctrl := gomock.NewController(t)
		echoServer := core.NewMockEchoServer(ctrl)
		echoServer.EXPECT().Add(http.MethodGet, gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().Add(http.MethodPost, gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().Add(http.MethodPut, gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().Start(gomock.Any())
		echoServer.EXPECT().Shutdown(gomock.Any())

		os.Setenv(grpcListenAddressEnvKey, fmt.Sprintf("localhost:%d", test.FreeTCPPort()))
		defer os.Unsetenv(grpcListenAddressEnvKey)

		testDirectory := io.TestDirectory(t)
		os.Setenv("NUTS_DATADIR", testDirectory)
		defer os.Unsetenv("NUTS_DATADIR")
		os.Args = []string{"nuts", "server"}

		engine1 := &core.TestEngine{}
		engine2 := &core.TestEngine{ShutdownError: true} // One engine's Shutdown() fails

		system := core.NewSystem()
		system.EchoCreator = func(_ core.HTTPConfig, _ bool) (core.EchoServer, error) {
			return echoServer, nil
		}
		system.RegisterEngine(engine1)
		system.RegisterEngine(engine2)

		err := Execute(ctx, system)
		assert.NoError(t, err)
		// Assert global config contains overridden property
		assert.Equal(t, testDirectory, system.Config.Datadir)
		// Assert engine config is injected
		assert.Equal(t, testDirectory, engine1.TestConfig.Datadir)
	})
	t.Run("defaults and alt binds are used", func(t *testing.T) {
		os.Setenv(grpcListenAddressEnvKey, fmt.Sprintf("localhost:%d", test.FreeTCPPort()))
		defer os.Unsetenv(grpcListenAddressEnvKey)
		os.Setenv(enableTLSEnvKey, "false")
		defer os.Unsetenv(enableTLSEnvKey)

		var echoServers []*http2.StubEchoServer
		system := CreateSystem()
		system.EchoCreator = func(_ core.HTTPConfig, _ bool) (core.EchoServer, error) {
			s := &http2.StubEchoServer{}
			echoServers = append(echoServers, s)
			return s, nil
		}
		cmd := testCommand()
		system.Load(cmd.Flags())
		system.Config.Datadir = io.TestDirectory(t)
		system.Config.HTTP.AltBinds["internal"] = core.HTTPConfig{Address: "localhost:7642"}
		err := startServer(ctx, system)
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, echoServers, 2)
		assert.Equal(t, system.Config.HTTP.Address, echoServers[0].BoundAddress)
		assert.Equal(t, "localhost:7642", echoServers[1].BoundAddress)
	})
	t.Run("unable to configure system", func(t *testing.T) {
		system := core.NewSystem()
		system.Config = core.NewServerConfig()
		system.Config.Datadir = "root_test.go"
		err := startServer(ctx, system)
		assert.Error(t, err, "unable to start")
	})
	t.Run("alt binds error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		echoServer := core.NewMockEchoServer(ctrl)
		echoServer.EXPECT().Start(gomock.Any()).Return(errors.New("unable to start")).Times(2)
		echoServer.EXPECT().Shutdown(gomock.Any()).Times(2)

		system := core.NewSystem()
		system.EchoCreator = func(_ core.HTTPConfig, _ bool) (core.EchoServer, error) {
			return echoServer, nil
		}
		system.Config = core.NewServerConfig()
		system.Config.Datadir = io.TestDirectory(t)
		system.Config.HTTP.AltBinds["internal"] = core.HTTPConfig{Address: "localhost:7642"}
		err := startServer(ctx, system)
		assert.EqualError(t, err, "unable to start")
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
	system := CreateSystem()
	assert.NotNil(t, system)
	numEngines := 0
	system.VisitEngines(func(engine core.Engine) {
		numEngines++
	})
	assert.Equal(t, 12, numEngines)
}

func testCommand() *cobra.Command {
	cmd := &cobra.Command{}
	fs := core.FlagSet()

	// this is done by the cobra command and may only be done once
	fs.Parse(os.Args)

	cmd.Flags().AddFlagSet(fs)
	return cmd
}
