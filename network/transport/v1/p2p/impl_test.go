/* Copyright (C) 2021. Nuts community
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

package p2p

import (
	"crypto/x509"
	transport2 "github.com/nuts-foundation/nuts-node/network/transport"
	transport3 "github.com/nuts-foundation/nuts-node/network/transport/v1/transport"
	"google.golang.org/grpc"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func waitForGRPCStart() {
	time.Sleep(100 * time.Millisecond) // Wait a moment for gRPC server and bootstrap goroutines to run
}

func Test_adapter_Configure(t *testing.T) {
	t.Run("ok - ssl offloading", func(t *testing.T) {
		network := NewAdapter()
		err := network.Configure(AdapterConfig{
			PeerID:        "foo",
			ListenAddress: "127.0.0.1:0",
		})
		if !assert.NoError(t, err) {
			return
		}
		defer network.Stop()
		err = network.Start()
		if !assert.NoError(t, err) {
			return
		}
		waitForGRPCStart()
	})
	t.Run("error - no peer ID", func(t *testing.T) {
		network := NewAdapter()
		err := network.Configure(AdapterConfig{})
		assert.Error(t, err)
	})
}

func Test_adapter_Connect(t *testing.T) {
	const peerID = "abc"

	t.Run("ok (uses mocks to test behaviour)", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		adapter := NewAdapter().(*adapter)
		adapter.Configure(AdapterConfig{
			PeerID:        "foo",
			ListenAddress: "127.0.0.1:0",
		})
		adapter.acceptor = func(_ grpc.ServerStream) (accepted bool, peer transport2.Peer, closer chan struct{}) {
			accepted = true
			peer = transport2.Peer{ID: peerID}
			closer = nil
			return
		}

		recvWaiter := sync.WaitGroup{}
		recvWaiter.Add(1)
		mockConnection := func() *transport3.MockNetwork_ConnectServer {
			conn := transport3.NewMockNetwork_ConnectServer(ctrl)
			conn.EXPECT().Recv().DoAndReturn(func() (interface{}, error) {
				recvWaiter.Done()
				time.Sleep(time.Second)
				return nil, io.EOF
			})
			return conn
		}

		connectWaiter := sync.WaitGroup{}
		connectWaiter.Add(1)
		// Connect() is a blocking call, so we run it in a goroutine
		go func() {
			adapter.Connect(mockConnection())
			connectWaiter.Done()
		}()
		recvWaiter.Wait()
		// Connection is now live and receiving. Check that the connection is registered
		assert.Len(t, adapter.Peers(), 1)
		// Now close the connection and wait for the Connect() function to finish, indicating the connection is closed and cleaned up
		adapter.conns.close(peerID)
		connectWaiter.Wait()
		// Now we shouldn't have any connections left
		assert.Empty(t, adapter.Peers())
	})

	// TODO
	//t.Run("second connection from same peer, disconnect first (uses actual in-memory gRPC connection)", func(t *testing.T) {
	//	ctrl := gomock.NewController(t)
	//	defer ctrl.Finish()
	//
	//	network := NewAdapter().(*adapter)
	//	network.Configure(AdapterConfig{
	//		PeerID:        "foo",
	//		ListenAddress: "127.0.0.1:0",
	//	})
	//	// Use gRPC bufconn listener
	//	network.listener = bufconn.Listen(1024 * 1024)
	//	network.startServing(nil)
	//	dialFn := func(_ context.Context, _ string) (net.Conn, error) {
	//		return network.listener.(*bufconn.Listener).Dial()
	//	}
	//
	//	connect := func() (*grpc.ClientConn, *sync.WaitGroup) {
	//		// Perform connection in goroutine to force parallelism server-side, just like it would at run-time.
	//		wg := sync.WaitGroup{}
	//		wg.Add(1)
	//		var client transport2.Network_ConnectClient
	//		var conn *grpc.ClientConn
	//		go func() {
	//			defer wg.Done()
	//			ctx := metadata.NewOutgoingContext(context.Background(), constructMetadata(peerID))
	//			var err error
	//			conn, err = grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(dialFn), grpc.WithInsecure(), grpc.WithBlock())
	//			if !assert.NoError(t, err) {
	//				t.FailNow()
	//			}
	//
	//			service := transport2.NewNetworkClient(conn)
	//			client, err = service.Connect(ctx)
	//			if !assert.NoError(t, err) {
	//				t.FailNow()
	//			}
	//		}()
	//		wg.Wait()
	//
	//		// client.Recv() blocks until the connection is closed, so we call it in a goroutine which communicates
	//		// with a wait group to signal the caller.
	//		recvWatcher := &sync.WaitGroup{}
	//		recvWatcher.Add(1)
	//		go func() {
	//			client.Recv()
	//			recvWatcher.Done()
	//		}()
	//
	//		return conn, recvWatcher
	//	}
	//
	//	// 1. First connection
	//	conn1, conn1Recv := connect()
	//	<-network.peerConnectedChannel // Wait until connected
	//	assert.Equal(t, connectivity.Ready, conn1.GetState())
	//	// 2. Second connection, should close first connection
	//	conn2, _ := connect()
	//	<-network.peerDisconnectedChannel // Wait until first connection is marked closed
	//	conn1Recv.Wait()                  // Assert first connection is closed
	//	<-network.peerConnectedChannel    // Wait until connected
	//	assert.Equal(t, connectivity.Ready, conn2.GetState())
	//	// 3. Close second connection from client side
	//	log.Logger().Info("closing second connection")
	//	err := conn2.Close()
	//	if !assert.NoError(t, err) {
	//		return
	//	}
	//	<-network.peerDisconnectedChannel // Wait until second connection is marked closed
	//})
}

func Test_adapter_ConnectToPeer(t *testing.T) {
	t.Run("connect to self", func(t *testing.T) {
		network := NewAdapter().(*adapter)
		network.Configure(AdapterConfig{
			PeerID:        "foo",
			ListenAddress: "127.0.0.1:0",
		})
		network.Start()

		waitForGRPCStart()

		defer network.Stop()

		willConnect := network.ConnectToPeer(network.config.ListenAddress)

		assert.False(t, willConnect)
	})
}

func Test_adapter_Diagnostics(t *testing.T) {
	network := NewAdapter()
	assert.Len(t, network.Diagnostics(), 3)
}

func Test_adapter_GetLocalAddress(t *testing.T) {
	network := NewAdapter().(*adapter)
	err := network.Configure(AdapterConfig{
		PeerID:        "foo",
		ListenAddress: "127.0.0.1:0",
		TrustStore:    x509.NewCertPool(),
	})
	if !assert.NoError(t, err) {
		return
	}
	t.Run("ok - listen address fully qualified", func(t *testing.T) {
		assert.Equal(t, "127.0.0.1:0", network.getLocalAddress())
	})
	t.Run("ok - listen address contains only port", func(t *testing.T) {
		network.config.ListenAddress = ":555"
		assert.Equal(t, "localhost:555", network.getLocalAddress())
	})
}

func Test_adapter_Send(t *testing.T) {
	const peerID = "foobar"
	const addr = "foo"
	t.Run("ok", func(t *testing.T) {
		network := NewAdapter().(*adapter)
		conn := network.conns.register(transport2.Peer{ID: peerID, Address: addr}, nil, nil).(*managedConnection)
		err := network.Send(peerID, &transport3.NetworkMessage{})
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, conn.outMessages, 1)
	})
	t.Run("unknown peer", func(t *testing.T) {
		network := NewAdapter().(*adapter)
		err := network.Send(peerID, &transport3.NetworkMessage{})
		assert.EqualError(t, err, "unknown peer: foobar")
	})
	t.Run("concurrent call on closing connection", func(t *testing.T) {
		network := NewAdapter().(*adapter)
		conn := network.conns.register(transport2.Peer{ID: peerID, Address: addr}, nil, nil).(*managedConnection)
		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = network.Send(peerID, &transport3.NetworkMessage{})
		}()
		go func() {
			defer wg.Done()
			conn.close()
		}()
		wg.Wait()
	})
}

func Test_adapter_Broadcast(t *testing.T) {
	const peer1ID = "foobar1"
	const peer2ID = "foobar2"
	network := NewAdapter().(*adapter)
	peer1 := network.conns.register(transport2.Peer{ID: peer1ID, Address: addr}, nil, nil).(*managedConnection)
	peer2 := network.conns.register(transport2.Peer{ID: peer2ID, Address: addr}, nil, nil).(*managedConnection)
	t.Run("ok", func(t *testing.T) {
		network.Broadcast(&transport3.NetworkMessage{})
		for _, conn := range network.conns.conns {
			assert.Len(t, conn.outMessages, 1)
		}
	})
	t.Run("concurrent call on closing connection", func(t *testing.T) {
		peer2MsgCount := len(peer2.outMessages)
		wg := sync.WaitGroup{}
		wg.Add(2)
		go func() {
			defer wg.Done()
			network.Broadcast(&transport3.NetworkMessage{})
		}()
		go func() {
			defer wg.Done()
			peer1.close()
		}()
		wg.Wait()
		assert.Empty(t, peer1.outMessages)
		assert.Len(t, peer2.outMessages, peer2MsgCount+1)
	})
}

func Test_adapter_shouldConnectTo(t *testing.T) {
	sut := NewAdapter().(*adapter)
	sut.config.ListenAddress = "some-address:5555"
	sut.conns.register(transport2.Peer{
		ID:      "peer",
		Address: "peer:5555",
	}, nil, nil)
	t.Run("localhost", func(t *testing.T) {
		assert.False(t, sut.shouldConnectTo("some-address:5555", ""))
	})
	t.Run("localhost, but port differs", func(t *testing.T) {
		assert.True(t, sut.shouldConnectTo("some-address:1111", ""))
	})
	t.Run("peer already connected, address equal", func(t *testing.T) {
		assert.False(t, sut.shouldConnectTo("peer:5555", ""))
	})
	t.Run("peer already connected, address differs (but peer ID matches)", func(t *testing.T) {
		assert.False(t, sut.shouldConnectTo("1.2.3.4:5555", "peer"))
	})
	t.Run("not connected, peer ID provided", func(t *testing.T) {
		assert.True(t, sut.shouldConnectTo("4.3.2.1:5555", "other-peer"))
	})
}
