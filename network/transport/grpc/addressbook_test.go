// /*
// * Copyright (C) 2021 Nuts community
// *
// * This program is free software: you can redistribute it and/or modify
// * it under the terms of the GNU General Public License as published by
// * the Free Software Foundation, either version 3 of the License, or
// * (at your option) any later version.
// *
// * This program is distributed in the hope that it will be useful,
// * but WITHOUT ANY WARRANTY; without even the implied warranty of
// * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// * GNU General Public License for more details.
// *
// * You should have received a copy of the GNU General Public License
// * along with this program.  If not, see <https://www.gnu.org/licenses/>.
// *
// */
package grpc

//
//import (
//	"context"
//	"fmt"
//	"github.com/nuts-foundation/nuts-node/network/transport"
//	"github.com/nuts-foundation/nuts-node/test"
//	"github.com/stretchr/testify/assert"
//	"github.com/stretchr/testify/require"
//	"google.golang.org/grpc"
//	"google.golang.org/grpc/metadata"
//	"sync"
//	"sync/atomic"
//	"testing"
//	"time"
//)
//
//var testConnectorConfig = connectorConfig{
//	peer:              transport.Peer{Address: "unit-test-target"},
//	tls:               nil,
//	connectionTimeout: time.Second,
//}
//
//func Test_connector_tryConnect(t *testing.T) {
//	// Set up gRPC stream interceptor to capture headers sent by client
//	actualUserAgent := atomic.Value{}
//	defaultInterceptors = append(defaultInterceptors, func(_ interface{}, stream grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
//		m, _ := metadata.FromIncomingContext(stream.Context())
//		actualUserAgent.Store(m.Get("User-Agent")[0])
//		return nil
//	})
//
//	// Setup server
//	serverConfig := NewConfig(fmt.Sprintf("localhost:%d", test.FreeTCPPort()), "server")
//	cm := NewGRPCConnectionManager(serverConfig, createKVStore(t), &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{})
//	require.NoError(t, cm.Start())
//	defer cm.Stop()
//
//	// Setup contact to test
//	bo := &trackingBackoff{}
//	cfg := testConnectorConfig
//	cfg.peer = transport.Peer{Address: serverConfig.listenAddress}
//	contact := newContact(cfg, bo)
//
//	// Connect and call protocol function to set up streams, required to assert headers.
//	// Then wait for stream to be set up
//	grpcConn, err := contact.tryConnect()
//	require.NoError(t, err)
//	require.NotNil(t, grpcConn)
//	_, _ = (&TestProtocol{}).CreateClientStream(context.Background(), grpcConn)
//	test.WaitFor(t, func() (bool, error) {
//		return actualUserAgent.Load() != nil, nil
//	}, time.Second, "time-out while waiting for connection to be set up")
//
//	assert.Equal(t, uint32(1), contact.stats().Attempts)
//	assert.Contains(t, actualUserAgent.Load().(string), "nuts-node-refimpl/unknown")
//}
//
//func Test_connector_stats(t *testing.T) {
//	t.Run("no connect attempts", func(t *testing.T) {
//		contact := newContact(testConnectorConfig, newTestBackoff())
//
//		stats := contact.stats()
//
//		assert.Equal(t, uint32(0), stats.Attempts)
//		assert.Equal(t, "unit-test-target", stats.Address)
//		assert.Equal(t, time.Time{}, stats.LastAttempt)
//	})
//	t.Run("with connect attempts", func(t *testing.T) {
//		contact := newContact(testConnectorConfig, newTestBackoff())
//
//		contact.tryConnect()
//		stats := contact.stats()
//
//		now := time.Now().Add(time.Second * -1)
//		assert.Equal(t, uint32(1), stats.Attempts)
//		assert.Equal(t, "unit-test-target", stats.Address)
//		assert.True(t, stats.LastAttempt.After(now))
//	})
//}
//
//func Test_connector_start(t *testing.T) {
//	t.Run("ok", func(t *testing.T) {
//		connected := make(chan struct{}, 1)
//		bo := &trackingBackoff{mux: &sync.Mutex{}}
//		contact := newContact(testConnectorConfig, bo)
//		contact.connectedBackoff = func(_ context.Context) {
//			// nothing
//		}
//
//		contact.start()
//		defer contact.stop()
//
//		<-connected // wait for connected
//
//		resetCount, backoffCount := bo.counts()
//		assert.Equal(t, 0, resetCount)
//		assert.Equal(t, 0, backoffCount)
//	})
//	t.Run("not connecting when already connected", func(t *testing.T) {
//		calls := make(chan struct{}, 10)
//		bo := &trackingBackoff{mux: &sync.Mutex{}}
//		contact := newContact(testConnectorConfig, bo)
//		contact.connectedBackoff = func(_ context.Context) {
//			// nothing
//		}
//
//		contact.start()
//
//		// Wait for 3 calls, should be enough to assert the connection isn't made
//		for i := 0; i < 3; i++ {
//			<-calls
//		}
//	})
//	t.Run("backoff when callback fails", func(t *testing.T) {
//		bo := &trackingBackoff{mux: &sync.Mutex{}}
//		contact := newContact(testConnectorConfig, bo)
//		contact.connectedBackoff = func(_ context.Context) {
//			// nothing
//		}
//
//		contact.start()
//		defer contact.stop()
//
//		test.WaitFor(t, func() (bool, error) {
//			_, backoffCount := bo.counts()
//			return backoffCount >= 1, nil
//		}, time.Second, "time-out while waiting for backoff to be invoked")
//		resetCounts, backoffCounts := bo.counts()
//		assert.Equal(t, 0, resetCounts)
//		assert.GreaterOrEqual(t, backoffCounts, 1)
//	})
//}
//
//type trackingBackoff struct {
//	resetCount   int
//	backoffCount int
//	mux          *sync.Mutex
//}
//
//func (t *trackingBackoff) Expired() bool {
//	return true
//}
//
//func (t *trackingBackoff) Value() time.Duration {
//	return 0
//}
//
//func (t *trackingBackoff) counts() (int, int) {
//	t.mux.Lock()
//	defer t.mux.Unlock()
//	return t.resetCount, t.backoffCount
//}
//
//func (t *trackingBackoff) Reset(_ time.Duration) {
//	t.mux.Lock()
//	defer t.mux.Unlock()
//	t.resetCount++
//}
//
//func (t *trackingBackoff) Backoff() time.Duration {
//	t.mux.Lock()
//	defer t.mux.Unlock()
//	t.backoffCount++
//	return 10 * time.Millisecond // prevent spinwait
//}
