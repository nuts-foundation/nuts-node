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
	"crypto/tls"
	"crypto/x509"
	"github.com/nuts-foundation/nuts-node/network/transport"
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
		assert.Len(t, network.(*a).connectorAddChannel, 2)
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
		assert.Len(t, network.(*a).connectorAddChannel, 2)
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
		network := NewAdapter().(*a)
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
		network := NewAdapter().(*a)
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
		network := NewAdapter().(*a)
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

func Test_interface_ConnectToPeer(t *testing.T) {
	network := NewAdapter().(*a)
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
	network := NewAdapter().(*a)
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

func Test_interface_Send(t *testing.T) {
	const peerID = "foobar"
	t.Run("ok", func(t *testing.T) {
		network := NewAdapter().(*a)
		conn := createConnection(Peer{ID: peerID}, nil)
		assert.Empty(t, conn.outMessages)
		network.conns[peerID] = conn
		err := network.Send(peerID, &transport.NetworkMessage{})
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, conn.outMessages, 1)
	})
	t.Run("unknown peer", func(t *testing.T) {
		network := NewAdapter().(*a)
		err := network.Send(peerID, &transport.NetworkMessage{})
		assert.EqualError(t, err, "unknown peer: foobar")
	})
}

func Test_interface_Broadcast(t *testing.T) {
	const peer1ID = "foobar1"
	const peer2ID = "foobar2"
	network := NewAdapter().(*a)
	network.conns[peer1ID] = createConnection(Peer{ID: peer1ID}, nil)
	network.conns[peer2ID] = createConnection(Peer{ID: peer2ID}, nil)
	network.Broadcast(&transport.NetworkMessage{})
	for _, conn := range network.conns {
		assert.Len(t, conn.outMessages, 1)
	}
}
