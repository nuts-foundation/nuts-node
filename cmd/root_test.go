package cmd

import (
	"bytes"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
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
		Execute()
		actual := buf.String()
		assert.Contains(t, actual, "Available Commands")
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
		os.Setenv("NUTS_NETWORK_DATABASEFILE", path.Join(testDirectory, "network.db"))
		defer os.Unsetenv("NUTS_NETWORK_DATABASEFILE")
		os.Setenv("NUTS_VDR_DATADIR", path.Join(testDirectory, "vdr"))
		defer os.Unsetenv("NUTS_VDR_DATADIR")
		os.Setenv("NUTS_CRYPTO_FSPATH", path.Join(testDirectory, "crypto"))
		defer os.Unsetenv("NUTS_CRYPTO_FSPATH")
		os.Args = []string{"nuts", "server"}
		Execute()
	})
}
