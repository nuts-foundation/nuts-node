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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crl"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test"
	io2 "github.com/nuts-foundation/nuts-node/test/io"
	io_prometheus_client "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// newBufconnConfig creates a new Config like NewConfig, but configures an in-memory bufconn listener instead of a TCP listener.
func newBufconnConfig(peerID transport.PeerID, options ...ConfigOption) (Config, *bufconn.Listener) {
	bufnet := bufconn.Listen(1024 * 1024)
	return NewConfig("bufnet", peerID, append(options[:], func(config *Config) {
		config.listener = func(_ string) (net.Listener, error) {
			return bufnet, nil
		}
	})...), bufnet
}

// withBufconnDialer can be used to redirect outbound connections to a predetermined bufconn listener.
func withBufconnDialer(listener *bufconn.Listener) ConfigOption {
	return func(config *Config) {
		config.dialer = func(ctx context.Context, target string, opts ...grpc.DialOption) (conn *grpc.ClientConn, err error) {
			return grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
				return listener.Dial()
			}), grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
	}
}

func Test_grpcConnectionManager_Connect(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		p := &TestProtocol{}
		cm := NewGRPCConnectionManager(NewConfig("", "test"), createKVStore(t), &stubNodeDIDReader{}, nil, p).(*grpcConnectionManager)
		bo := &trackingBackoff{mux: &sync.Mutex{}}
		cm.addressBook.backoffCreator = func() Backoff { return bo }
		delayFn := func(delay time.Duration) *time.Duration { return &delay }

		// new contact sets backoff
		cm.Connect("address", did.MustParseDID("did:nuts:peer"), delayFn(time.Second))
		assert.Len(t, cm.addressBook.contacts, 1)
		assert.Equal(t, 1, bo.resetCount)
		assert.Equal(t, time.Second, bo.lastResetValue)

		// update contact sets backoff
		cm.Connect("updated address", did.MustParseDID("did:nuts:peer"), delayFn(time.Hour))
		assert.Len(t, cm.addressBook.contacts, 1)
		assert.Equal(t, 2, bo.resetCount)
		assert.Equal(t, time.Hour, bo.lastResetValue)

		// contact didn't change, so backoff doesn't eiter
		cm.Connect("updated address", did.MustParseDID("did:nuts:peer"), delayFn(0))
		assert.Len(t, cm.addressBook.contacts, 1)
		assert.Equal(t, 2, bo.resetCount)
		assert.Equal(t, time.Hour, bo.lastResetValue)
	})

	t.Run("ok - with TLS", func(t *testing.T) {
		p := &TestProtocol{}
		ts, _ := core.LoadTrustStore("../../test/truststore.pem")
		clientCert, _ := tls.LoadX509KeyPair("../../test/certificate-and-key.pem", "../../test/certificate-and-key.pem")
		config := NewConfig("", "test", WithTLS(clientCert, ts, 1))

		cm := NewGRPCConnectionManager(config, createKVStore(t), &stubNodeDIDReader{}, nil, p).(*grpcConnectionManager)

		cm.Connect(fmt.Sprintf("127.0.0.1:%d", test.FreeTCPPort()), did.DID{}, nil)

		// TODO: tlsConfig is now part of the cm.dialOptions. How should this be tested??
		//assert.Len(t, cm.connections.list, 1)
		//connector := cm.connections.list[0].(*conn).contact
		//assert.Equal(t, core.MinTLSVersion, connector.tlsConfig.MinVersion)
		//assert.NotEmpty(t, connector.tlsConfig.Certificates)
		//assert.NotEmpty(t, connector.tlsConfig.RootCAs.Subjects())
	})

	t.Run("duplicate connection", func(t *testing.T) {
		p := &TestProtocol{}
		cm := NewGRPCConnectionManager(NewConfig("", "test"), createKVStore(t), &stubNodeDIDReader{}, nil, p).(*grpcConnectionManager)

		peerAddress := fmt.Sprintf("127.0.0.1:%d", test.FreeTCPPort())
		cm.Connect(peerAddress, did.DID{}, nil)
		cm.Connect(peerAddress, did.DID{}, nil)
		assert.Len(t, cm.addressBook.contacts, 1)
	})

	t.Run("no address removes contacts", func(t *testing.T) {
		p := &TestProtocol{}
		cm := NewGRPCConnectionManager(NewConfig("", "test"), createKVStore(t), &stubNodeDIDReader{}, nil, p).(*grpcConnectionManager)
		cm.Connect("address", did.MustParseDID("did:nuts:abc"), nil)
		assert.Len(t, cm.addressBook.contacts, 1)

		cm.Connect("", did.MustParseDID("did:nuts:abc"), nil)

		assert.Len(t, cm.addressBook.contacts, 0)
	})
}

func Test_grpcConnectionManager_hasActiveConnection(t *testing.T) {
	cm := NewGRPCConnectionManager(NewConfig("", "test"), createKVStore(t), &stubNodeDIDReader{}, nil, &TestProtocol{}).(*grpcConnectionManager)
	// add 2 connections
	ctx := context.Background()
	bootstrap := transport.Peer{Address: "bootstrap"}
	peer1 := transport.Peer{Address: "peer1", NodeDID: did.MustParseDID("did:nuts:peer1")}
	peer1authenticated := transport.Peer{Address: "peer1", NodeDID: did.MustParseDID("did:nuts:peer1"), Authenticated: true}
	peer2 := transport.Peer{Address: "peer2", NodeDID: did.MustParseDID("did:nuts:peer2")}
	cm.connections.getOrRegister(ctx, bootstrap, true)
	cm.connections.getOrRegister(ctx, peer1authenticated, true)
	cm.connections.getOrRegister(ctx, peer2, true)

	// bootstrap connected
	assert.True(t, cm.hasActiveConnection(bootstrap))

	// bootstrap not connected
	assert.False(t, cm.hasActiveConnection(transport.Peer{Address: "not connected"}))

	// authenticated connection
	assert.True(t, cm.hasActiveConnection(peer1))

	// unauthenticated connection
	assert.False(t, cm.hasActiveConnection(peer2))
}

func Test_grpcConnectionManager_dialerLoop(t *testing.T) {
	// make sure connectLoop only returns after all of its goroutines are closed
	defer goleak.VerifyNone(t)

	targetAddress := "bootstrap"
	var capturedAddress string
	timeout := 2 * time.Second // connectLoop ticker takes 1 sec

	cm := NewGRPCConnectionManager(Config{connectionTimeout: 5 * timeout}, createKVStore(t), &stubNodeDIDReader{}, dummyAuthenticator{}, &TestProtocol{}).(*grpcConnectionManager)
	cm.dialer = func(ctx context.Context, target string, _ ...grpc.DialOption) (conn *grpc.ClientConn, err error) {
		capturedAddress = target
		<-ctx.Done()
		return nil, ctx.Err()
	}

	// add contact
	cont := newContact(transport.Peer{Address: targetAddress}, newTestBackoff())
	cm.addressBook.contacts = append(cm.addressBook.contacts, cont)
	done := make(chan struct{}, 0)
	go func() {
		cm.connectLoop()
		done <- struct{}{}
	}()

	// check that calling flag is set to true
	test.WaitFor(t, func() (bool, error) {
		return cont.calling.Load(), nil
	}, timeout, "timeout while waiting for contact.calling flag ot be set")

	// cancel context, this should stop the dialer and close all connections
	cm.ctxCancel()
	<-done

	assert.False(t, cont.calling.Load())            // calling flg should be reset to 0
	assert.Equal(t, targetAddress, capturedAddress) // calling the correct address
}

func Test_grpcConnectionManager_dial(t *testing.T) {
	t.Run("ok - user agent", func(t *testing.T) {
		// Set up gRPC stream interceptor to capture headers sent by client
		actualUserAgent := atomic.Value{}
		defaultInterceptors = append(defaultInterceptors, func(_ interface{}, stream grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			m, _ := metadata.FromIncomingContext(stream.Context())
			actualUserAgent.Store(m.Get("User-Agent")[0])
			return nil
		})
		defer func() { defaultInterceptors = defaultInterceptors[:0] }()

		// Setup server
		serverConfig := NewConfig(fmt.Sprintf("localhost:%d", test.FreeTCPPort()), "server")
		cm := NewGRPCConnectionManager(serverConfig, createKVStore(t), &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		require.NoError(t, cm.Start())
		defer cm.Stop()

		// Setup contact to test
		bo := &trackingBackoff{mux: &sync.Mutex{}}
		contact := newContact(transport.Peer{Address: serverConfig.listenAddress}, bo)

		// Connect and call protocol function to set up streams, required to assert headers.
		// Then wait for stream to be set up
		cm.connect(contact)
		test.WaitFor(t, func() (bool, error) {
			return actualUserAgent.Load() != nil, nil
		}, time.Second, "time-out while waiting for connection to be set up")

		assert.Equal(t, uint32(1), contact.stats().Attempts)
		assert.Contains(t, actualUserAgent.Load().(string), "nuts-node-refimpl/unknown")
	})
	t.Run("simultaneous call", func(t *testing.T) {
		backoff := &trackingBackoff{mux: &sync.Mutex{}}
		peer := transport.Peer{Address: "nuts.nl"}
		cont := newContact(peer, backoff)
		cm := NewGRPCConnectionManager(Config{}, createKVStore(t), &stubNodeDIDReader{}, dummyAuthenticator{}, &TestProtocol{}).(*grpcConnectionManager)
		cm.connections.list = append(cm.connections.list, createConnection(cm.ctx, peer)) // add existing connection

		cm.connect(cont)

		// contact not updated
		assert.Equal(t, uint32(0), cont.attempts.Load())

		// backoff not called
		assert.Equal(t, 0, backoff.backoffCount)
		assert.Equal(t, 0, backoff.resetCount)
	})
	t.Run("calling errors", func(t *testing.T) {
		t.Run("dialer context canceled", func(t *testing.T) {
			backoff := &trackingBackoff{mux: &sync.Mutex{}}
			cont := newContact(transport.Peer{Address: "nuts.nl"}, backoff)
			cm := NewGRPCConnectionManager(Config{connectionTimeout: time.Second}, createKVStore(t), &stubNodeDIDReader{}, dummyAuthenticator{}, &TestProtocol{}).(*grpcConnectionManager)
			cm.dialer = func(ctx context.Context, target string, _ ...grpc.DialOption) (conn *grpc.ClientConn, err error) {
				return nil, status.Error(codes.Canceled, "failed")
			}
			now := time.Now()

			cm.connect(cont)

			// contact updated
			assert.Equal(t, uint32(1), cont.attempts.Load())
			assert.Less(t, now, cont.stats().LastAttempt)

			// backoff not called
			assert.Equal(t, 0, backoff.backoffCount)
			assert.Equal(t, 0, backoff.resetCount)
		})
		t.Run("dialer error", func(t *testing.T) {
			backoff := &trackingBackoff{mux: &sync.Mutex{}}
			cont := newContact(transport.Peer{Address: "nuts.nl"}, backoff)
			cm := NewGRPCConnectionManager(Config{connectionTimeout: time.Second}, createKVStore(t), &stubNodeDIDReader{}, dummyAuthenticator{}, &TestProtocol{}).(*grpcConnectionManager)
			cm.dialer = func(ctx context.Context, target string, _ ...grpc.DialOption) (conn *grpc.ClientConn, err error) {
				return nil, errors.New("not a context calceled error")
			}
			now := time.Now()

			cm.connect(cont)

			// contact updated
			assert.Equal(t, uint32(1), cont.attempts.Load())
			assert.Less(t, now, cont.stats().LastAttempt)

			// backoff is called
			assert.Equal(t, 1, backoff.backoffCount)
			assert.Equal(t, 0, backoff.resetCount)
		})
	})
	t.Run("openOutboundStreams", func(t *testing.T) {
		t.Run("ok", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			authenticator := NewMockAuthenticator(ctrl)
			authenticator.EXPECT().Authenticate(*nodeDID, gomock.Any(), gomock.Any()).Return(transport.Peer{}, nil).Times(2)

			// server
			serverCfg, listener := newBufconnConfig(transport.PeerID(t.Name()))
			server := NewGRPCConnectionManager(serverCfg, createKVStore(t), &stubNodeDIDReader{}, authenticator, &TestProtocol{}).(*grpcConnectionManager)
			if err := server.Start(); err != nil {
				t.Fatal(err)
			}
			defer server.Stop()

			// client
			cfg, listener := newBufconnConfig(transport.PeerID(t.Name()), withBufconnDialer(listener))
			client := NewGRPCConnectionManager(cfg, createKVStore(t), &stubNodeDIDReader{}, authenticator, &TestProtocol{}).(*grpcConnectionManager)

			// contact
			cont := newContact(transport.Peer{Address: "bufnet", NodeDID: *nodeDID}, newTestBackoff())
			cont.backoff.Reset(time.Hour) // increase backoff, so we can see that it has been reset
			now := time.Now()

			// call peer
			done := make(chan struct{}, 0)
			go func() {
				client.connect(cont)
				done <- struct{}{}
			}()

			// wait for connection, close connection, wait until it is closed
			test.WaitFor(t, func() (bool, error) {
				return len(client.Peers()) > 0, nil
			}, time.Second*2, "waiting for peer 1 to connect")
			client.ctxCancel()
			<-done

			// contact updated
			assert.Equal(t, uint32(1), cont.attempts.Load())
			assert.Less(t, now, cont.stats().LastAttempt)

			// backoff is reset. this means a random value between 1 and 5 sec.
			assert.Less(t, cont.backoff.Value(), 5*time.Second)

			// connection is removed again
			assert.Empty(t, client.connections.list)
		})
		t.Run("error", func(t *testing.T) {
			//server
			serverCfg, serverListener := newBufconnConfig("server")
			server := NewGRPCConnectionManager(serverCfg, nil, &transport.FixedNodeDIDResolver{NodeDID: *nodeDID}, nil).(*grpcConnectionManager)
			if err := server.Start(); err != nil {
				t.Fatal(err)
			}
			defer server.Stop()

			//client
			clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
			client := NewGRPCConnectionManager(clientCfg, nil, &transport.FixedNodeDIDResolver{}, NewDummyAuthenticator(nil), &TestProtocol{}).(*grpcConnectionManager)

			// connection
			backoff := &trackingBackoff{mux: &sync.Mutex{}}
			cont := newContact(transport.Peer{Address: "server", NodeDID: did.MustParseDID("did:nuts:remote")}, backoff)

			// call peer
			ctx, cancel := context.WithTimeout(client.ctx, 2*time.Second)
			go func() {
				client.connect(cont)
				cancel()
			}()
			<-ctx.Done()
			assert.ErrorIs(t, ctx.Err(), context.Canceled, "context expired")

			// backoff is set to a ridiculously large value
			assert.Equal(t, 1, backoff.backoffCount)
			assert.Equal(t, 0, backoff.resetCount)

			// connection is removed again
			assert.Empty(t, client.connections.list)
		})
		t.Run("wrong DID answered call", func(t *testing.T) {
			serverCfg, serverListener := newBufconnConfig("server")
			server := NewGRPCConnectionManager(serverCfg, nil, &transport.FixedNodeDIDResolver{NodeDID: *nodeDID}, nil, &TestProtocol{}).(*grpcConnectionManager)
			if err := server.Start(); err != nil {
				t.Fatal(err)
			}
			defer server.Stop()

			clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
			ctrl := gomock.NewController(t)
			authenticator := NewMockAuthenticator(ctrl)
			client := NewGRPCConnectionManager(clientCfg, nil, &transport.FixedNodeDIDResolver{}, authenticator, &TestProtocol{}).(*grpcConnectionManager)
			cont := newContact(transport.Peer{Address: "server", NodeDID: did.MustParseDID("did:nuts:remote")}, newTestBackoff())

			// call peer
			ctx, cancel := context.WithTimeout(client.ctx, 2*time.Second)
			go func() {
				client.connect(cont)
				cancel()
			}()
			<-ctx.Done()
			assert.ErrorIs(t, ctx.Err(), context.Canceled, "context expired")

			// backoff is set to a large value
			assert.Less(t, 23*time.Hour, cont.backoff.Value())

			// connection is removed again
			assert.Empty(t, client.connections.list)
		})
	})
}

func Test_grpcConnectionManager_Peers(t *testing.T) {
	create := func(t *testing.T, opts ...ConfigOption) (*grpcConnectionManager, *MockAuthenticator, *TestProtocol, *bufconn.Listener) {
		ctrl := gomock.NewController(t)
		authenticator := NewMockAuthenticator(ctrl)
		proto := &TestProtocol{}
		cfg, listener := newBufconnConfig(transport.PeerID(t.Name()), opts...)
		db := createKVStore(t)
		cm := NewGRPCConnectionManager(cfg, db, &stubNodeDIDReader{}, authenticator, proto).(*grpcConnectionManager)
		if err := cm.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			cm.Stop()
		})
		return cm, authenticator, proto, listener
	}

	t.Run("no peers", func(t *testing.T) {
		cm, _, _, _ := create(t)
		assert.Empty(t, cm.Peers())
	})
	t.Run("1 peer (1 connection)", func(t *testing.T) {
		_, authenticator1, _, listener := create(t)
		authenticator1.EXPECT().Authenticate(*nodeDID, gomock.Any(), gomock.Any()).Return(transport.Peer{}, nil)
		cm2, authenticator2, _, _ := create(t, withBufconnDialer(listener))
		authenticator2.EXPECT().Authenticate(*nodeDID, gomock.Any(), gomock.Any()).Return(transport.Peer{}, nil)
		cm2.Connect("bufnet", *nodeDID, nil)
		test.WaitFor(t, func() (bool, error) {
			return len(cm2.Peers()) > 0, nil
		}, time.Second*2, "waiting for peer 1 to connect")
	})
	t.Run("outbound stream triggers observer", func(t *testing.T) {
		_, authenticator1, _, listener := create(t)
		cm2, authenticator2, _, _ := create(t, withBufconnDialer(listener))
		authenticator1.EXPECT().Authenticate(*nodeDID, gomock.Any(), gomock.Any()).Return(transport.Peer{ID: "1"}, nil)
		authenticator2.EXPECT().Authenticate(*nodeDID, gomock.Any(), gomock.Any()).Return(transport.Peer{ID: "2"}, nil)
		var capturedPeer atomic.Value
		var capturedState atomic.Value
		cm2.RegisterObserver(func(peer transport.Peer, state transport.StreamState, protocol transport.Protocol) {
			capturedPeer.Store(peer)
			capturedState.Store(state)
		})

		cm2.Connect("bufnet", *nodeDID, nil)

		test.WaitFor(t, func() (bool, error) {
			return capturedPeer.Load() != nil, nil
		}, time.Second*2, "waiting for peer 2 observers")
		assert.Equal(t, transport.Peer{ID: "2"}, capturedPeer.Load())
		assert.Equal(t, transport.StateConnected, capturedState.Load())

		cm2.Stop()

		test.WaitFor(t, func() (bool, error) {
			return capturedState.Load() == transport.StateDisconnected, nil
		}, time.Second*2, "waiting for peer 2 observers")
	})
	t.Run("inbound stream triggers observer", func(t *testing.T) {
		cm1, authenticator1, _, listener := create(t)
		cm2, authenticator2, _, _ := create(t, withBufconnDialer(listener))
		authenticator1.EXPECT().Authenticate(*nodeDID, gomock.Any(), gomock.Any()).Return(transport.Peer{ID: "1"}, nil)
		authenticator2.EXPECT().Authenticate(*nodeDID, gomock.Any(), gomock.Any()).Return(transport.Peer{ID: "2"}, nil)
		var capturedPeer atomic.Value
		var capturedState atomic.Value
		cm1.RegisterObserver(func(peer transport.Peer, state transport.StreamState, protocol transport.Protocol) {
			capturedPeer.Store(peer)
			capturedState.Store(state)
		})

		cm2.Connect("bufnet", *nodeDID, nil)

		test.WaitFor(t, func() (bool, error) {
			return capturedPeer.Load() != nil, nil
		}, time.Second*2, "waiting for peer 1 observers")
		assert.Equal(t, transport.Peer{ID: "1"}, capturedPeer.Load())
		assert.Equal(t, transport.StateConnected, capturedState.Load())

		cm2.Stop()

		test.WaitFor(t, func() (bool, error) {
			return capturedState.Load() == transport.StateDisconnected, nil
		}, time.Second*2, "waiting for peer 1 observers")
	})
	t.Run("0 peers (1 connection which failed)", func(t *testing.T) {
		cm, _, _, _ := create(t)
		cm.Connect("non-existing", did.DID{}, nil)
		assert.Empty(t, cm.Peers())
	})
}

func Test_grpcConnectionManager_Start(t *testing.T) {
	trustStore, _ := core.LoadTrustStore("../../test/truststore.pem")
	serverCert, _ := tls.LoadX509KeyPair("../../test/certificate-and-key.pem", "../../test/certificate-and-key.pem")

	t.Run("ok - gRPC server not bound", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{}, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		assert.NoError(t, cm.Start())
		assert.Nil(t, cm.listener)
	})

	t.Run("ok - gRPC server bound, TLS enabled", func(t *testing.T) {
		cfg := NewConfig(
			fmt.Sprintf("127.0.0.1:%d",
				test.FreeTCPPort()),
			"foo",
			WithTLS(serverCert, trustStore, 10),
		)
		cm := NewGRPCConnectionManager(cfg, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		err := cm.Start()
		require.NoError(t, err)
		defer cm.Stop()

		assert.NotNil(t, cm.listener)
	})

	t.Run("ok - gRPC server bound, incoming TLS offloaded", func(t *testing.T) {
		cfg := NewConfig(
			fmt.Sprintf("127.0.0.1:%d",
				test.FreeTCPPort()),
			"foo",
			WithTLS(serverCert, trustStore, 10),
			WithTLSOffloading("client-cert"),
		)
		cm := NewGRPCConnectionManager(cfg, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		err := cm.Start()
		require.NoError(t, err)
		defer cm.Stop()

		assert.NotNil(t, cm.listener)
	})
	t.Run("ok - gRPC server bound, incoming TLS offloaded (but HTTP client cert name is invalid)", func(t *testing.T) {
		cfg := NewConfig(
			fmt.Sprintf("127.0.0.1:%d",
				test.FreeTCPPort()),
			"foo",
			WithTLS(serverCert, trustStore, 10),
			WithTLSOffloading(""),
		)
		cm := NewGRPCConnectionManager(cfg, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		err := cm.Start()

		assert.EqualError(t, err, "tls.certheader must be configured to enable TLS offloading ")
	})

	t.Run("ok - gRPC server bound, TLS disabled", func(t *testing.T) {
		cm := NewGRPCConnectionManager(NewConfig(fmt.Sprintf("127.0.0.1:%d", test.FreeTCPPort()), "foo"), nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		err := cm.Start()
		require.NoError(t, err)
		defer cm.Stop()

		assert.NotNil(t, cm.listener)
	})

	t.Run("configures CRL check when TLS is enabled", func(t *testing.T) {
		p := &TestProtocol{}

		var tlsConfig *tls.Config

		validator := crl.NewMockValidator(gomock.NewController(t))
		validator.EXPECT().SyncLoop(gomock.Any())
		validator.EXPECT().Configure(gomock.Any(), 10).DoAndReturn(func(config *tls.Config, maxValidityDays int) {
			tlsConfig = config
		}).Times(2) // on inbound and outbound TLS config

		cm := NewGRPCConnectionManager(Config{
			listenAddress:      fmt.Sprintf(":%d", test.FreeTCPPort()),
			trustStore:         x509.NewCertPool(),
			serverCert:         &serverCert,
			clientCert:         &serverCert,
			crlValidator:       validator,
			maxCRLValidityDays: 10,
			listener:           tcpListenerCreator,
		}, nil, &stubNodeDIDReader{}, nil, p)

		assert.NoError(t, cm.Start())
		cm.Stop()

		assert.Equal(t, core.MinTLSVersion, tlsConfig.MinVersion)
	})
}

func Test_grpcConnectionManager_Stop(t *testing.T) {
	t.Run("closes open connections", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{peerID: "12345"}, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)

		go cm.handleInboundStream(&TestProtocol{}, newServerStream("1234", ""))
		test.WaitFor(t, func() (bool, error) {
			return len(cm.Peers()) == 1, nil
		}, 5*time.Second, "time-out while waiting for connection")

		cm.Stop()
		assert.Empty(t, cm.Peers())
	})
	t.Run("calling stop while accepting new connection", func(t *testing.T) {
		// This test simulates a slow or unfortunately timed shutdown, where there's an new inbound stream while shutting down.
		// This previously caused the Connection Manager to deadlock, being blocked by conn.waitUntilDisconnected() which blocks GRPCServer.GracefulStop().
		// Solved by having the context conn.waitUntilDisconnected() waits for, derive from a parent context supplied by ConnectionManager, which is cancelled when Stop() is called.
		cm := NewGRPCConnectionManager(Config{peerID: "12345"}, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)

		wg := sync.WaitGroup{}
		wg.Add(2)

		go func() {
			time.Sleep(10 * time.Millisecond) // make sure handleInboundStream is called after ConnectionManager.Stop()
			err := cm.handleInboundStream(&TestProtocol{}, newServerStream("1234", ""))
			if err != nil {
				panic(err) // can't use t.Fatal in goroutines
			}
			wg.Done()
		}()
		go func() {
			cm.Stop()
			wg.Done()
		}()

		// If all is OK, the test should just proceed
		wg.Wait()
	})
}

func Test_grpcConnectionManager_Diagnostics(t *testing.T) {
	const peerID = "server-peer-id"
	t.Run("no peers", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{peerID: peerID}, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		defer cm.Stop()
		assert.Equal(t, "0", cm.Diagnostics()[1].String()) // assert number_of_peers
	})
	t.Run("with peers", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{peerID: peerID}, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		defer cm.Stop()

		go cm.handleInboundStream(&TestProtocol{}, newServerStream("peer1", ""))
		go cm.handleInboundStream(&TestProtocol{}, newServerStream("peer2", ""))

		test.WaitFor(t, func() (bool, error) {
			return len(cm.Peers()) == 2, nil
		}, 5*time.Second, "time-out while waiting for peers to connect")

		assert.Equal(t, "2", cm.Diagnostics()[1].String())                                         // assert number_of_peers
		assert.Equal(t, "peer2@127.0.0.1:1028 peer1@127.0.0.1:6718", cm.Diagnostics()[2].String()) // assert peers
	})
}

func Test_grpcConnectionManager_openOutboundStreams(t *testing.T) {
	t.Run("client does not support gRPC protocol implementation", func(t *testing.T) {
		serverCfg, serverListener := newBufconnConfig("server")
		server := NewGRPCConnectionManager(serverCfg, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()

		clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
		client := NewGRPCConnectionManager(clientCfg, nil, &stubNodeDIDReader{}, nil, &TestProtocol{}).(*grpcConnectionManager)

		connection, _ := client.connections.getOrRegister(context.Background(), transport.Peer{Address: "server"}, false)
		grpcConn, err := clientCfg.dialer(context.Background(), "server")
		require.NoError(t, err)
		err = client.openOutboundStreams(connection, grpcConn)
		connection.disconnect()

		assert.EqualError(t, err, "could not use any of the supported protocols to communicate with peer (id=@server)")
	})
	t.Run("remote authentication fails", func(t *testing.T) {
		serverCfg, serverListener := newBufconnConfig("server")
		server := NewGRPCConnectionManager(serverCfg, nil, &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()

		clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
		client := NewGRPCConnectionManager(clientCfg, nil, &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		c := createConnection(context.Background(), transport.Peer{}).(*conn)
		c.status.Store(status.New(codes.Unauthenticated, "unauthenticated"))
		grpcConn, err := clientCfg.dialer(context.Background(), "server")
		require.NoError(t, err)
		connectedWG := sync.WaitGroup{}
		connectedWG.Add(1)
		disconnectedWG := sync.WaitGroup{}
		disconnectedWG.Add(1)
		client.RegisterObserver(func(peer transport.Peer, state transport.StreamState, protocol transport.Protocol) {
			if state == transport.StateConnected {
				connectedWG.Done()
			}
			if state == transport.StateDisconnected {
				disconnectedWG.Done()
			}
		})

		go func() {
			err = client.openOutboundStreams(c, grpcConn)
			assert.Error(t, err)
		}()

		connectedWG.Wait()

		// Explicitly disconnect to clear peer.
		c.disconnect()
		disconnectedWG.Wait()
	})
	t.Run("ok", func(t *testing.T) {
		// Bug: peer ID is empty when race condition with disconnect() and notify observers occurs.
		// See https://github.com/nuts-foundation/nuts-node/issues/978
		serverCfg, serverListener := newBufconnConfig("server")
		server := NewGRPCConnectionManager(serverCfg, nil, &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()

		clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
		client := NewGRPCConnectionManager(clientCfg, nil, &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		c := createConnection(context.Background(), transport.Peer{})
		grpcConn, err := clientCfg.dialer(context.Background(), "server")
		require.NoError(t, err)
		var capturedPeer atomic.Value
		connectedWG := sync.WaitGroup{}
		connectedWG.Add(1)
		disconnectedWG := sync.WaitGroup{}
		disconnectedWG.Add(1)
		client.RegisterObserver(func(peer transport.Peer, state transport.StreamState, protocol transport.Protocol) {
			if state == transport.StateConnected {
				connectedWG.Done()
			}
			if state == transport.StateDisconnected {
				capturedPeer.Store(peer)
				disconnectedWG.Done()
			}
		})

		go func() {
			err = client.openOutboundStreams(c, grpcConn)
			require.NoError(t, err)
		}()

		connectedWG.Wait()

		// Assert peer gauge is incremented
		metric := &io_prometheus_client.Metric{}
		test.WaitFor(t, func() (bool, error) {
			_ = client.peersCounter.Write(metric)
			return metric.Gauge.GetValue() == 1, nil
		}, time.Second, "Waiting for peer counter to be incremented")

		// Explicitly disconnect to clear peer.
		c.disconnect()
		disconnectedWG.Wait()

		// Assert peer gauge is decremented
		_ = client.peersCounter.Write(metric)
		assert.Equal(t, float64(0), *metric.Gauge.Value)

		// Assert that the peer is passed correctly to the observer
		assert.Equal(t, transport.Peer{ID: "server"}, capturedPeer.Load())
	})
}

func Test_grpcConnectionManager_openOutboundStream(t *testing.T) {
	protocol := &TestProtocol{}

	t.Run("ok", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		grpcPeer := &peer.Peer{}
		ctx := peer.NewContext(context.TODO(), grpcPeer)
		nodeDID, _ := did.ParseDID("did:nuts:test")

		peerInfo := transport.Peer{
			NodeDID: *nodeDID,
		}

		authenticator := NewMockAuthenticator(ctrl)
		authenticator.EXPECT().Authenticate(*nodeDID, *grpcPeer, peerInfo).Return(peerInfo, nil)

		cm := NewGRPCConnectionManager(Config{peerID: "server-peer-id"}, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		cm.authenticator = authenticator

		defer cm.Stop()

		meta, _ := cm.constructMetadata(false)

		grpcStream := NewMockClientStream(ctrl)
		grpcStream.EXPECT().Header().Return(meta, nil)
		grpcStream.EXPECT().Context().Return(ctx)

		grpcConn := NewMockConn(ctrl)
		grpcConn.EXPECT().NewStream(gomock.Any(), gomock.Any(), "/grpc.Test/DoStuff", gomock.Any()).Return(grpcStream, nil)

		conn := NewMockConnection(ctrl)
		conn.EXPECT().verifyOrSetPeerID(transport.PeerID("server-peer-id")).Return(true)
		conn.EXPECT().Peer().Return(peerInfo)
		conn.EXPECT().setPeer(peerInfo)
		conn.EXPECT().registerStream(gomock.Any(), gomock.Any()).Return(true)

		stream, err := cm.openOutboundStream(conn, protocol, grpcConn, metadata.MD{})

		assert.NoError(t, err)
		assert.NotNil(t, stream)
	})
	t.Run("server did not send ID", func(t *testing.T) {
		serverCfg, serverListener := newBufconnConfig("")
		server := NewGRPCConnectionManager(serverCfg, nil, &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()

		clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
		client := NewGRPCConnectionManager(clientCfg, nil, &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		c := createConnection(context.Background(), transport.Peer{})
		grpcConn, err := clientCfg.dialer(context.Background(), "server")
		require.NoError(t, err)
		md, _ := client.constructMetadata(false)

		outboundStream, err := client.openOutboundStream(c, &TestProtocol{}, grpcConn, md)
		assert.Nil(t, outboundStream)
		assert.EqualError(t, err, "failed to read peer ID header: peer sent empty peerID header")
	})
	t.Run("second stream over same connection sends different peer ID", func(t *testing.T) {
		serverCfg, serverListener := newBufconnConfig("server")
		server := NewGRPCConnectionManager(serverCfg, nil, &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()

		clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
		client := NewGRPCConnectionManager(clientCfg, nil, &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		c := createConnection(context.Background(), transport.Peer{})
		grpcConn, err := clientCfg.dialer(context.Background(), "server")
		require.NoError(t, err)
		md, _ := client.constructMetadata(false)

		// First stream
		outboundStream, err := client.openOutboundStream(c, &TestProtocol{}, grpcConn, md)
		assert.NotNil(t, outboundStream)
		assert.NoError(t, err)

		// Second stream with different peer ID
		server.config.peerID = "other-peer-id"
		outboundStream, err = client.openOutboundStream(c, &TestProtocol{}, grpcConn, md)
		assert.Nil(t, outboundStream)
		assert.EqualError(t, err, "peer sent invalid ID (id=other-peer-id)")
	})
	t.Run("already connected (same peer ID)", func(t *testing.T) {
		serverCfg, serverListener := newBufconnConfig("server")
		server := NewGRPCConnectionManager(serverCfg, nil, &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()

		clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
		client := NewGRPCConnectionManager(clientCfg, nil, &transport.FixedNodeDIDResolver{}, nil, &TestProtocol{}).(*grpcConnectionManager)
		c := createConnection(context.Background(), transport.Peer{})
		grpcConn, err := clientCfg.dialer(context.Background(), "server")
		require.NoError(t, err)

		md, _ := client.constructMetadata(false)
		// Initial connection should be OK
		_, err = client.openOutboundStream(c, &TestProtocol{}, grpcConn, md)
		require.NoError(t, err)

		// Second connection should error out
		clientStream, err := client.openOutboundStream(c, &TestProtocol{}, grpcConn, md)
		assert.ErrorIs(t, err, ErrAlreadyConnected)
		assert.Nil(t, clientStream)
	})
	t.Run("peer authentication fails", func(t *testing.T) {
		serverCfg, serverListener := newBufconnConfig("server")
		server := NewGRPCConnectionManager(serverCfg, nil, &transport.FixedNodeDIDResolver{NodeDID: *nodeDID}, nil, &TestProtocol{}).(*grpcConnectionManager)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()

		clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
		ctrl := gomock.NewController(t)
		authenticator := NewMockAuthenticator(ctrl)
		authenticator.EXPECT().Authenticate(*nodeDID, gomock.Any(), gomock.Any()).Return(transport.Peer{}, ErrNodeDIDAuthFailed)
		client := NewGRPCConnectionManager(clientCfg, nil, &transport.FixedNodeDIDResolver{}, authenticator, &TestProtocol{}).(*grpcConnectionManager)
		c := createConnection(context.Background(), transport.Peer{NodeDID: *nodeDID})
		grpcConn, err := clientCfg.dialer(context.Background(), "server")
		require.NoError(t, err)

		md, _ := client.constructMetadata(false)
		clientStream, err := client.openOutboundStream(c, &TestProtocol{}, grpcConn, md)
		assert.ErrorIs(t, err, ErrNodeDIDAuthFailed)
		assert.Nil(t, clientStream)
	})
	t.Run("wrong DID answered call", func(t *testing.T) {
		serverCfg, serverListener := newBufconnConfig("server")
		server := NewGRPCConnectionManager(serverCfg, nil, &transport.FixedNodeDIDResolver{NodeDID: *nodeDID}, nil, &TestProtocol{}).(*grpcConnectionManager)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()

		clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
		ctrl := gomock.NewController(t)
		authenticator := NewMockAuthenticator(ctrl)
		client := NewGRPCConnectionManager(clientCfg, nil, &transport.FixedNodeDIDResolver{}, authenticator, &TestProtocol{}).(*grpcConnectionManager)
		c := createConnection(context.Background(), transport.Peer{NodeDID: did.MustParseDID("did:nuts:remote")})
		grpcConn, err := clientCfg.dialer(context.Background(), "server")
		require.NoError(t, err)

		md, _ := client.constructMetadata(false)
		clientStream, err := client.openOutboundStream(c, &TestProtocol{}, grpcConn, md)
		assert.ErrorIs(t, err, ErrUnexpectedNodeDID)
		assert.Nil(t, clientStream)
	})
	t.Run("peer did not send DID", func(t *testing.T) {
		serverCfg, serverListener := newBufconnConfig("server")
		server := NewGRPCConnectionManager(serverCfg, nil, &transport.FixedNodeDIDResolver{NodeDID: did.DID{}}, nil, &TestProtocol{}).(*grpcConnectionManager)
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Stop()

		clientCfg, _ := newBufconnConfig("client", withBufconnDialer(serverListener))
		ctrl := gomock.NewController(t)
		authenticator := NewMockAuthenticator(ctrl) // is not called
		client := NewGRPCConnectionManager(clientCfg, nil, &transport.FixedNodeDIDResolver{}, authenticator, &TestProtocol{}).(*grpcConnectionManager)
		c := createConnection(context.Background(), transport.Peer{NodeDID: did.MustParseDID("did:nuts:remote")})
		grpcConn, err := clientCfg.dialer(context.Background(), "server")
		require.NoError(t, err)

		md, _ := client.constructMetadata(false)
		clientStream, err := client.openOutboundStream(c, &TestProtocol{}, grpcConn, md)
		assert.ErrorIs(t, err, ErrNodeDIDAuthFailed)
		assert.Nil(t, clientStream)
	})
}

func Test_grpcConnectionManager_handleInboundStream(t *testing.T) {
	protocol := &TestProtocol{}
	t.Run("new client", func(t *testing.T) {
		expectedPeer := transport.Peer{
			ID:      "client-peer-id",
			Address: "127.0.0.1:9522",
			NodeDID: did.DID{},
		}
		clientDID, _ := did.ParseDID("did:nuts:client")
		expectedPeer.NodeDID = *clientDID
		serverStream := newServerStream(expectedPeer.ID, expectedPeer.NodeDID.String())
		ctrl := gomock.NewController(t)
		authenticator := NewMockAuthenticator(ctrl)
		authenticator.EXPECT().Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedPeer, nil)
		cm := NewGRPCConnectionManager(Config{peerID: "server-peer-id"}, nil, &stubNodeDIDReader{}, authenticator).(*grpcConnectionManager)
		defer cm.Stop()

		handlerExited := &sync.WaitGroup{}
		handlerExited.Add(1)
		go func() {
			_ = cm.handleInboundStream(protocol, serverStream)
			handlerExited.Done()
		}()
		test.WaitFor(t, func() (bool, error) {
			return len(cm.Peers()) == 1, nil
		}, 5*time.Second, "time-out while waiting for peer")

		peerInfo := cm.Peers()[0]
		assert.Equal(t, transport.PeerID("client-peer-id"), peerInfo.ID)
		assert.Equal(t, "127.0.0.1:9522", peerInfo.Address)
		assert.Equal(t, "did:nuts:client", peerInfo.NodeDID.String())

		// Assert headers sent to client
		assert.Equal(t, "server-peer-id", serverStream.sentHeaders.Get("peerID")[0])
		assert.Equal(t, "did:nuts:test", serverStream.sentHeaders.Get("nodeDID")[0])

		// Assert connection was registered
		assert.Len(t, cm.connections.list, 1)

		// Assert peer counter is incremented
		metric := &io_prometheus_client.Metric{}
		_ = cm.peersCounter.Write(metric)
		assert.Equal(t, float64(1), *metric.Gauge.Value)

		// Close the stream
		serverStream.cancelFunc()
		handlerExited.Wait()

		// Assert peer counter is decremented
		_ = cm.peersCounter.Write(metric)
		assert.Equal(t, float64(0), *metric.Gauge.Value)
	})
	t.Run("peer didn't send ID", func(t *testing.T) {
		expectedPeer := transport.Peer{
			ID:      "", // Empty
			Address: "127.0.0.1:9522",
		}
		serverStream := newServerStream(expectedPeer.ID, expectedPeer.NodeDID.String())
		cm := NewGRPCConnectionManager(Config{peerID: "server-peer-id"}, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)

		err := cm.handleInboundStream(protocol, serverStream)
		assert.EqualError(t, err, "unable to read peer ID")
		assert.Empty(t, cm.connections.list)
	})
	t.Run("authentication failed", func(t *testing.T) {
		expectedPeer := transport.Peer{
			ID:      "client-peer-id",
			Address: "127.0.0.1:9522",
			NodeDID: did.DID{},
		}
		clientDID, _ := did.ParseDID("did:nuts:client")
		expectedPeer.NodeDID = *clientDID
		serverStream := newServerStream(expectedPeer.ID, expectedPeer.NodeDID.String())
		ctrl := gomock.NewController(t)
		authenticator := NewMockAuthenticator(ctrl)
		authenticator.EXPECT().Authenticate(gomock.Any(), gomock.Any(), gomock.Any()).Return(expectedPeer, errors.New("failed"))
		cm := NewGRPCConnectionManager(Config{peerID: "server-peer-id"}, nil, &stubNodeDIDReader{}, authenticator).(*grpcConnectionManager)

		err := cm.handleInboundStream(protocol, serverStream)
		assert.Equal(t, err, ErrNodeDIDAuthFailed)
		assert.Empty(t, cm.connections.list)
	})
	t.Run("already connected client", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{peerID: "server-peer-id"}, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		defer cm.Stop()

		go cm.handleInboundStream(protocol, newServerStream("client-peer-id", ""))
		test.WaitFor(t, func() (bool, error) {
			return len(cm.Peers()) == 1, nil
		}, 5*time.Second, "time-out while waiting for peer")

		// Second connection with same peer ID is rejected
		err := cm.handleInboundStream(protocol, newServerStream("client-peer-id", ""))
		assert.ErrorIs(t, err, ErrAlreadyConnected)

		// Assert only first connection was registered
		assert.Len(t, cm.connections.list, 1)
	})
	t.Run("closing connection removes it from list", func(t *testing.T) {
		cm := NewGRPCConnectionManager(Config{peerID: "server-peer-id"}, nil, &stubNodeDIDReader{}, nil).(*grpcConnectionManager)
		defer cm.Stop()

		stream := newServerStream("client-peer-id", "")
		go cm.handleInboundStream(protocol, stream)
		test.WaitFor(t, func() (bool, error) {
			return len(cm.Peers()) == 1, nil
		}, 5*time.Second, "time-out while waiting for peer")

		// Simulate a stream close
		stream.cancelFunc()

		test.WaitFor(t, func() (bool, error) {
			cm.connections.mux.Lock()
			defer cm.connections.mux.Unlock()
			return len(cm.connections.list) == 0, nil
		}, time.Second*2, "time-out while waiting for closed inbound connection to be removed")
	})
}

func newServerStream(clientPeerID transport.PeerID, nodeDID string) *stubServerStream {
	md := metadata.New(map[string]string{peerIDHeader: clientPeerID.String()})
	if nodeDID != "" {
		md.Set(nodeDIDHeader, nodeDID)
	}
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = peer.NewContext(ctx, &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(crc32.ChecksumIEEE([]byte(clientPeerID))%9000 + 1000)}})
	ctx = grpc.NewContextWithServerTransportStream(ctx, &stubServerTransportStream{method: "/unit/test"})
	ctx, cancelFunc := context.WithCancel(ctx)

	return &stubServerStream{
		ctx:        ctx,
		cancelFunc: cancelFunc,
	}
}

var nodeDID, _ = did.ParseDID("did:nuts:test")

type stubServerStream struct {
	sentHeaders metadata.MD
	cancelFunc  context.CancelFunc
	ctx         context.Context
}

func (s stubServerStream) SetHeader(md metadata.MD) error {
	panic("implement me")
}

func (s *stubServerStream) SendHeader(md metadata.MD) error {
	s.sentHeaders = md
	return nil
}

func (s stubServerStream) SetTrailer(md metadata.MD) {
	panic("implement me")
}

func (s stubServerStream) Context() context.Context {
	return s.ctx
}

func (s stubServerStream) SendMsg(m interface{}) error {
	panic("implement me")
}

func (s stubServerStream) RecvMsg(m interface{}) error {
	<-s.ctx.Done() // just block
	return io.EOF
}

type stubServerTransportStream struct {
	method string
}

func (s stubServerTransportStream) Method() string {
	return s.method
}

func (s stubServerTransportStream) SetHeader(md metadata.MD) error {
	panic("implement me")
}

func (s stubServerTransportStream) SendHeader(md metadata.MD) error {
	panic("implement me")
}

func (s stubServerTransportStream) SetTrailer(md metadata.MD) error {
	panic("implement me")
}

type stubNodeDIDReader struct {
}

func (s stubNodeDIDReader) Resolve() (did.DID, error) {
	return *nodeDID, nil
}

func createKVStore(t *testing.T) stoabs.KVStore {
	return storage.CreateTestBBoltStore(t, filepath.Join(io2.TestDirectory(t), "grpc.db"))
}
