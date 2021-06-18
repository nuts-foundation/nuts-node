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
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func waitForGRPCStart() {
	time.Sleep(100 * time.Millisecond) // Wait a moment for gRPC server and bootstrap goroutines to run
}

func Test_interface_Configure(t *testing.T) {
	t.Run("ok - configure registers bootstrap nodes", func(t *testing.T) {
		network := NewAdapter()
		err := network.Configure(AdapterConfig{
			PeerID:         "foo",
			ListenAddress:  "127.0.0.1:0",
			BootstrapNodes: []string{"foo:555", "bar:5554"},
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, network.(*adapter).connectorAddChannel, 2)
		assert.True(t, network.Configured())
	})
	t.Run("ok - ssl offloading", func(t *testing.T) {
		network := NewAdapter()
		err := network.Configure(AdapterConfig{
			PeerID:         "foo",
			ListenAddress:  "127.0.0.1:0",
			BootstrapNodes: []string{"foo:555", "bar:5554"},
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, network.(*adapter).connectorAddChannel, 2)
		assert.True(t, network.Configured())
	})
	t.Run("error - no peer ID", func(t *testing.T) {
		network := NewAdapter()
		err := network.Configure(AdapterConfig{})
		assert.Error(t, err)
	})
}

func Test_interface_Start(t *testing.T) {
	t.Run("ok - gRPC server not bound", func(t *testing.T) {
		network := NewAdapter().(*adapter)
		err := network.Configure(AdapterConfig{
			PeerID:     "foo",
			TrustStore: x509.NewCertPool(),
		})
		if !assert.NoError(t, err) {
			return
		}
		err = network.Start()
		waitForGRPCStart()
		assert.Nil(t, network.listener)
		defer network.Stop()
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("ok - gRPC server bound, TLS enabled", func(t *testing.T) {
		network := NewAdapter().(*adapter)
		serverCert, _ := tls.LoadX509KeyPair("../../test/certificate-and-key.pem", "../../test/certificate-and-key.pem")
		err := network.Configure(AdapterConfig{
			PeerID:        "foo",
			ServerCert:    serverCert,
			ListenAddress: "127.0.0.1:0",
			TrustStore:    x509.NewCertPool(),
		})
		if !assert.NoError(t, err) {
			return
		}
		err = network.Start()
		waitForGRPCStart()
		assert.NotNil(t, network.listener)
		defer network.Stop()
		if !assert.NoError(t, err) {
			return
		}
	})
	t.Run("ok - gRPC server bound, TLS disabled", func(t *testing.T) {
		network := NewAdapter().(*adapter)
		err := network.Configure(AdapterConfig{
			PeerID:        "foo",
			ListenAddress: "127.0.0.1:0",
			TrustStore:    x509.NewCertPool(),
		})
		if !assert.NoError(t, err) {
			return
		}
		err = network.Start()
		waitForGRPCStart()
		assert.NotNil(t, network.listener)
		defer network.Stop()
		if !assert.NoError(t, err) {
			return
		}
	})
}

func Test_interface_Connect(t *testing.T) {
	const peerID = "abc"

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("ok", func(t *testing.T) {
		network := NewAdapter().(*adapter)
		network.Configure(AdapterConfig{
			PeerID:        "foo",
			ListenAddress: "127.0.0.1:0",
		})

		recvWaiter := sync.WaitGroup{}
		recvWaiter.Add(1)
		mockConnection := func() *transport.MockNetwork_ConnectServer {
			conn := transport.NewMockNetwork_ConnectServer(ctrl)
			ctx := metadata.NewIncomingContext(peer.NewContext(context.Background(), &peer.Peer{
				Addr: &net.IPAddr{
					IP: net.IPv4(127, 0, 0, 1),
				},
			}), metadata.Pairs(peerIDHeader, peerID))
			conn.EXPECT().Context().AnyTimes().Return(ctx)
			conn.EXPECT().SendHeader(gomock.Any())
			conn.EXPECT().Recv().DoAndReturn(func() (interface{}, error) {
				recvWaiter.Done()
				time.Sleep(time.Second)
				return nil, io.EOF
			})
			return conn
		}

		connectWaiter := sync.WaitGroup{}
		connectWaiter.Add(1)
		go func() {
			network.Connect(mockConnection())
			connectWaiter.Done()
		}()
		recvWaiter.Wait()
		// Connection is now live and receiving, close it
		// Check that the connection is registered
		assert.Len(t, network.conns, 1)
		assert.Len(t, network.peersByAddr, 1)
		assert.Len(t, network.Peers(), 1)
		// Now close the connection and wait for the Connect() function to finish, indicating the connection is closed and cleaned up
		network.conns[PeerID(peerID)].close()
		connectWaiter.Wait()
		// Now we shouldn't have any connections left
		assert.Empty(t, network.conns)
		assert.Empty(t, network.peersByAddr)
		assert.Empty(t, network.Peers())
	})

	t.Run("parallel connection from same peer", func(t *testing.T) {
		network := NewAdapter().(*adapter)
		network.Configure(AdapterConfig{
			PeerID:        "foo",
			ListenAddress: "127.0.0.1:0",
		})

		connectionsReceivingWaiter := sync.WaitGroup{}
		mockConnection := func() *transport.MockNetwork_ConnectServer {
			conn := transport.NewMockNetwork_ConnectServer(ctrl)
			ctx := metadata.NewIncomingContext(peer.NewContext(context.Background(), &peer.Peer{
				Addr: &net.IPAddr{
					IP: net.IPv4(127, 0, 0, 1),
				},
			}), metadata.Pairs(peerIDHeader, peerID))
			conn.EXPECT().Context().AnyTimes().Return(ctx)
			conn.EXPECT().SendHeader(gomock.Any())
			conn.EXPECT().Recv().DoAndReturn(func() (interface{}, error) {
				connectionsReceivingWaiter.Done()
				return nil, io.EOF
			})
			return conn
		}

		connsNum := 15
		connectionsReceivingWaiter.Add(connsNum)
		for i := 0; i < connsNum; i++ {
			go func() {
				err := network.Connect(mockConnection())
				if err != nil {
					t.Fatal(err)
				}
			}()
		}
		connectionsReceivingWaiter.Wait()
	})

	t.Run("peer connects twice", func(t *testing.T) {
		network := NewAdapter().(*adapter)
		network.Configure(AdapterConfig{
			PeerID:        "foo",
			ListenAddress: "127.0.0.1:0",
		})

		connectionsReceivingWaiter := sync.WaitGroup{}
		shutdownWaiter := sync.WaitGroup{}
		shutdownWaiter.Add(1)
		defer shutdownWaiter.Done()

		mockConnection := func() *transport.MockNetwork_ConnectServer {
			conn := transport.NewMockNetwork_ConnectServer(ctrl)
			ctx := metadata.NewIncomingContext(peer.NewContext(context.Background(), &peer.Peer{
				Addr: &net.IPAddr{
					IP: net.IPv4(127, 0, 0, 1),
				},
			}), metadata.Pairs(peerIDHeader, peerID))
			conn.EXPECT().Context().AnyTimes().Return(ctx)
			conn.EXPECT().SendHeader(gomock.Any())
			conn.EXPECT().Recv().DoAndReturn(func() (interface{}, error) {
				connectionsReceivingWaiter.Done()
				shutdownWaiter.Wait()
				return nil, io.EOF
			})
			return conn
		}

		// Create first connection and wait for it to be connected (Recv() is called blockingly)
		firstConnection := mockConnection()
		connectionsReceivingWaiter.Add(1)
		go func() {
			err := network.Connect(firstConnection)
			if !assert.NoError(t, err) {
				return
			}
		}()
		connectionsReceivingWaiter.Wait()
		assert.Len(t, network.peersByAddr, 1)
		assert.Len(t, network.peerConnectedChannel, 1)
		assert.Len(t, network.conns, 1)
		// First connection is established, now create second connection. This should disconnect and unregister the first connection.
		secondConnection := mockConnection()
		connectionsReceivingWaiter.Add(1)
		go func() {
			err := network.Connect(secondConnection)
			if !assert.NoError(t, err) {
				return
			}
		}()
		connectionsReceivingWaiter.Wait()
		// Second connection is established

	})

}

func Test_interface_ConnectToPeer(t *testing.T) {
	network := NewAdapter().(*adapter)
	network.Configure(AdapterConfig{
		PeerID:        "foo",
		ListenAddress: "127.0.0.1:0",
	})
	network.Start()
	defer network.Stop()
	waitForGRPCStart()
	t.Run("connect to self", func(t *testing.T) {
		willConnect := network.ConnectToPeer(network.config.ListenAddress)
		assert.False(t, willConnect)
	})
	t.Run("connect to peer", func(t *testing.T) {
		addr := network.config.ListenAddress
		network.config.ListenAddress = ":5555" // trick to make the server connect to itself
		willConnect := network.ConnectToPeer(addr)
		assert.True(t, willConnect)
		// Now wait for peer (self) to actually connect
		startTime := time.Now()
		for {
			if len(network.Peers()) > 0 {
				// OK
				break
			}
			if time.Now().Sub(startTime).Seconds() >= 2 {
				t.Fatal("time-out: expected 1 peer")
			}
		}
	})
}

func Test_interface_Diagnostics(t *testing.T) {
	network := NewAdapter()
	assert.Len(t, network.Diagnostics(), 3)
}

func Test_interface_GetLocalAddress(t *testing.T) {
	network := NewAdapter().(*adapter)
	err := network.Configure(AdapterConfig{
		PeerID:         "foo",
		ListenAddress:  "127.0.0.1:0",
		BootstrapNodes: []string{"foo:555", "bar:5554"},
		TrustStore:     x509.NewCertPool(),
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

//func Test_interface_Send(t *testing.T) {
//	const peerID = "foobar"
//	t.Run("ok", func(t *testing.T) {
//		network := NewAdapter().(*adapter)
//		conn := createConnection(Peer{ID: peerID}, nil)
//		assert.Empty(t, conn.outMessages)
//		network.conns[peerID] = conn
//		err := network.Send(peerID, &transport.NetworkMessage{})
//		if !assert.NoError(t, err) {
//			return
//		}
//		assert.Len(t, conn.outMessages, 1)
//	})
//	t.Run("unknown peer", func(t *testing.T) {
//		network := NewAdapter().(*adapter)
//		err := network.Send(peerID, &transport.NetworkMessage{})
//		assert.EqualError(t, err, "unknown peer: foobar")
//	})
//	t.Run("concurrent call on closing connection", func(t *testing.T) {
//		network := NewAdapter().(*adapter)
//		conn := createConnection(Peer{ID: peerID}, nil)
//		network.registerConnection(conn)
//		wg := sync.WaitGroup{}
//		wg.Add(2)
//		go func() {
//			defer wg.Done()
//			_ = network.Send(peerID, &transport.NetworkMessage{})
//		}()
//		go func() {
//			defer wg.Done()
//			conn.close()
//		}()
//		wg.Wait()
//	})
//}
//
//func Test_interface_Broadcast(t *testing.T) {
//	const peer1ID = "foobar1"
//	const peer2ID = "foobar2"
//	network := NewAdapter().(*adapter)
//	peer1 := createConnection(Peer{ID: peer1ID}, nil)
//	network.registerConnection(peer1)
//	peer2 := createConnection(Peer{ID: peer2ID}, nil)
//	network.registerConnection(peer2)
//	t.Run("ok", func(t *testing.T) {
//		network.Broadcast(&transport.NetworkMessage{})
//		for _, conn := range network.conns {
//			assert.Len(t, conn.outMessages, 1)
//		}
//	})
//	t.Run("concurrent call on closing connection", func(t *testing.T) {
//		peer2MsgCount := len(peer2.outMessages)
//		wg := sync.WaitGroup{}
//		wg.Add(2)
//		go func() {
//			defer wg.Done()
//			network.Broadcast(&transport.NetworkMessage{})
//		}()
//		go func() {
//			defer wg.Done()
//			peer1.close()
//		}()
//		wg.Wait()
//		assert.Empty(t, peer1.outMessages)
//		assert.Len(t, peer2.outMessages, peer2MsgCount+1)
//	})
//}
