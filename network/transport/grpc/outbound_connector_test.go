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

package grpc

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"testing"
)

func Test_connector_doConnect(t *testing.T) {
	serverConfig := NewConfig(fmt.Sprintf("localhost:%d", test.FreeTCPPort()), "server")
	cm := NewGRPCConnectionManager(serverConfig, &stubNodeDIDReader{})
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
		connector.connectedBackoff = func(_ context.Context) {
			// nothing
		}

		connector.start()

		// Wait for 3 calls, should be enough to assert the connection isn't made
		for i := 0; i < 3; i++ {
			<-calls
		}
	})
}
