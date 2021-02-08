package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

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

	t.Run("start in server mode", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		echoServer := core.NewMockEchoServer(ctrl)
		echoServer.EXPECT().GET(gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().POST(gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().PUT(gomock.Any(), gomock.Any()).AnyTimes()
		echoServer.EXPECT().Start(gomock.Any())
		echoCreator = func() core.EchoServer {
			return echoServer
		}

		testDirectory := io.TestDirectory(t)
		os.Setenv("NUTS_DATADIR", testDirectory)
		defer os.Unsetenv("NUTS_DATADIR")
		os.Args = []string{"nuts", "server"}

		m := &core.TestModule{}

		system := core.NewSystem()
		system.RegisterModule(m)

		Execute(system)
		// Assert global config contains overridden property
		assert.Equal(t, testDirectory, system.Config.Datadir)
		// Assert engine config is injected
		assert.Equal(t, testDirectory, m.TestConfig.Datadir)
	})
}

func Test_echoCreator(t *testing.T) {
	t.Run("creates an echo server", func(t *testing.T) {
		assert.NotNil(t, echoCreator())
	})
}

func Test_CreateSystem(t *testing.T) {
	system := CreateSystem()
	assert.NotNil(t, system)
	numEngines := 0
	system.VisitModules(func(engine core.Module) {
		numEngines++
	})
	assert.Equal(t,5, numEngines)
}