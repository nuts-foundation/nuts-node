package grpc

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"testing"
)

func Test_connector_doConnect(t *testing.T) {
	serverConfig := NewConfig(fmt.Sprintf("localhost:%d", test.FreeTCPPort()), "server")
	cm := NewGRPCConnectionManager(serverConfig)
	if !assert.NoError(t, cm.Start()) {
		return
	}
	defer cm.Stop()

	connector := outboundConnector{
		address: serverConfig.listenAddress,
		dialer:  grpc.DialContext,
	}
	grpcConn, err := connector.tryConnect()
	assert.NoError(t, err)
	assert.NotNil(t, grpcConn)
}
