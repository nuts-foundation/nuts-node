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
		shouldConnect: func() bool {
			return false
		},
	}
	grpcConn, err := connector.tryConnect()
	assert.NoError(t, err)
	assert.NotNil(t, grpcConn)
}
func Test_connector_loopConnect(t *testing.T) {
	t.Run("not connecting when already connected", func(t *testing.T) {
		calls := make(chan struct{}, 10)
		connector := createOutboundConnector("foo", nil, nil, func() bool {
			calls <- struct{}{}
			return false
		}, nil)
		connector.connectedBackoff = func() {
			// nothing
		}

		go connector.loopConnect()

		// Wait for 3 calls, should be enough to assert the connection isn't made
		for i := 0; i < 3; i++ {
			<-calls
		}
	})
}
