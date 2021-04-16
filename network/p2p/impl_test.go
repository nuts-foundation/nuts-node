/*
 * Copyright (C) 2021. Nuts community
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

func Test_interface_Configure(t *testing.T) {
	t.Run("ok - configure registers bootstrap nodes", func(t *testing.T) {
		network := NewInterface()
		err := network.Configure(InterfaceConfig{
			PeerID:         "foo",
			ListenAddress:  "0.0.0.0:555",
			BootstrapNodes: []string{"foo:555", "bar:5554"},
			TrustStore:     x509.NewCertPool(),
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, network.(*grpcInterface).connectorAddChannel, 2)
	})
	t.Run("ok - ssl offloading", func(t *testing.T) {
		network := NewInterface()
		err := network.Configure(InterfaceConfig{
			PeerID:         "foo",
			ListenAddress:  "0.0.0.0:555",
			BootstrapNodes: []string{"foo:555", "bar:5554"},
		})
		if !assert.NoError(t, err) {
			return
		}
		assert.Len(t, network.(*grpcInterface).connectorAddChannel, 2)
	})
}

func Test_interface_Start(t *testing.T) {
	waitForGRPCStart := func() {
		time.Sleep(100 * time.Millisecond) // Wait a moment for gRPC server setup goroutines to run
	}
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
			ListenAddress: ":5555",
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
			ListenAddress: ":5555",
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

func Test_interface_GetLocalAddress(t *testing.T) {
	network := NewInterface().(*grpcInterface)
	err := network.Configure(InterfaceConfig{
		PeerID:         "foo",
		ListenAddress:  "0.0.0.0:555",
		BootstrapNodes: []string{"foo:555", "bar:5554"},
		TrustStore:     x509.NewCertPool(),
	})
	if !assert.NoError(t, err) {
		return
	}
	t.Run("ok - public address not configured, listen address fully qualified", func(t *testing.T) {
		assert.Equal(t, "0.0.0.0:555", network.getLocalAddress())
	})
	t.Run("ok - public address not configured, listen address contains only port", func(t *testing.T) {
		network.config.ListenAddress = ":555"
		assert.Equal(t, "localhost:555", network.getLocalAddress())
	})
}
