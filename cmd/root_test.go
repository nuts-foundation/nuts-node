package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/test"
	"net/http"
	"os"
	"testing"

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
	t.Run("no args prints help", func(t *testing.T) {
		oldStdout := stdOutWriter
		buf := new(bytes.Buffer)
		stdOutWriter = buf
		defer func() {
			stdOutWriter = oldStdout
		}()
		os.Args = []string{"nuts"}
		Execute(core.NewSystem())
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
		Execute(core.NewSystem())
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
		Execute(core.NewSystem())
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

	t.Run("start in server mode", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoServer := core.NewMockEchoServer(ctrl)
		echoServer.EXPECT().Add(http.MethodGet, gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().Add(http.MethodPost, gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().Add(http.MethodPut, gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().Start(gomock.Any())

		os.Setenv(grpcListenAddressEnvKey, fmt.Sprintf("localhost:%d", test.FreeTCPPort()))
		defer os.Unsetenv(grpcListenAddressEnvKey)

		testDirectory := io.TestDirectory(t)
		os.Setenv("NUTS_DATADIR", testDirectory)
		defer os.Unsetenv("NUTS_DATADIR")
		os.Args = []string{"nuts", "server"}

		m := &core.TestEngine{}

		system := core.NewSystem()
		system.EchoCreator = func(_ core.HTTPConfig, _ bool) (core.EchoServer, error) {
			return echoServer, nil
		}
		system.RegisterEngine(m)

		Execute(system)
		// Assert global config contains overridden property
		assert.Equal(t, testDirectory, system.Config.Datadir)
		// Assert engine config is injected
		assert.Equal(t, testDirectory, m.TestConfig.Datadir)
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
		system.Load(cmd)
		system.Config = core.NewServerConfig()
		system.Config.Datadir = io.TestDirectory(t)
		system.Config.HTTP.AltBinds["internal"] = core.HTTPConfig{Address: "localhost:7642"}
		err := startServer(system)
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
		err := startServer(system)
		assert.Error(t, err, "unable to start")
	})
	t.Run("alt binds error", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		echoServer := core.NewMockEchoServer(ctrl)
		echoServer.EXPECT().Start(gomock.Any()).Return(errors.New("unable to start")).Times(2)

		system := core.NewSystem()
		system.EchoCreator = func(_ core.HTTPConfig, _ bool) (core.EchoServer, error) {
			return echoServer, nil
		}
		system.Config = core.NewServerConfig()
		system.Config.Datadir = io.TestDirectory(t)
		system.Config.HTTP.AltBinds["internal"] = core.HTTPConfig{Address: "localhost:7642"}
		err := startServer(system)
		assert.EqualError(t, err, "unable to start")
	})
}

func Test_CreateSystem(t *testing.T) {
	system := CreateSystem()
	assert.NotNil(t, system)
	numEngines := 0
	system.VisitEngines(func(engine core.Engine) {
		numEngines++
	})
	assert.Equal(t, 9, numEngines)
}

func testCommand() *cobra.Command {
	cmd := &cobra.Command{}
	fs := core.FlagSet()

	// this is done by the cobra command and may only be done once
	fs.Parse(os.Args)

	cmd.PersistentFlags().AddFlagSet(fs)
	return cmd
}
