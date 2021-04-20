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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func waitForGRPCStart() {
	time.Sleep(100 * time.Millisecond) // Wait a moment for gRPC server and bootstrap goroutines to run
}

func Test_interface_Configure(t *testing.T) {
	t.Run("ok - configure registers bootstrap nodes", func(t *testing.T) {
		network := NewInterface()
		err := network.Configure(InterfaceConfig{
			PeerID:         "foo",
			ListenAddress:  "127.0.0.1:0",
			BootstrapNodes: []string{"foo:555", "bar:5554"},
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, network.(*grpcInterface).connectorAddChannel, 2)
		assert.True(t, network.Configured())
	})
	t.Run("ok - ssl offloading", func(t *testing.T) {
		network := NewInterface()
		err := network.Configure(InterfaceConfig{
			PeerID:         "foo",
			ListenAddress:  "127.0.0.1:0",
			BootstrapNodes: []string{"foo:555", "bar:5554"},
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, network.(*grpcInterface).connectorAddChannel, 2)
		assert.True(t, network.Configured())
	})
	t.Run("error - no peer ID", func(t *testing.T) {
		network := NewInterface()
		err := network.Configure(InterfaceConfig{})
		assert.Error(t, err)
	})
}

func Test_interface_Start(t *testing.T) {
	t.Run("ok - gRPC server not bound", func(t *testing.T) {
		network := NewInterface().(*grpcInterface)
		err := network.Configure(InterfaceConfig{
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
		network := NewInterface().(*grpcInterface)
		serverCert, _ := tls.LoadX509KeyPair("../../test/certificate-and-key.pem", "../../test/certificate-and-key.pem")
		err := network.Configure(InterfaceConfig{
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
		network := NewInterface().(*grpcInterface)
		err := network.Configure(InterfaceConfig{
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
	network := NewInterface().(*grpcInterface)
	network.Configure(InterfaceConfig{
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
	network := NewInterface()
	assert.Len(t, network.Diagnostics(), 3)
}

func Test_interface_GetLocalAddress(t *testing.T) {
	network := NewInterface().(*grpcInterface)
	err := network.Configure(InterfaceConfig{
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
