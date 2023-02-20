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
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	grpcLib "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"sync"
	"sync/atomic"
	"time"
)

type dialer func(ctx context.Context, target string, opts ...grpcLib.DialOption) (conn *grpcLib.ClientConn, err error)

type connectorConfig struct {
	address           string
	tls               *tls.Config
	connectionTimeout time.Duration
}

// createOutboundConnector connects to a remote server in a loop, taking into account a given backoff.
// When the connection succeeds it calls the given callback. The caller is responsible to reset the backoff after optional application-level checks succeed (e.g. authentication).
func createOutboundConnector(config connectorConfig, dialer dialer, shouldConnect func() bool, connectedCallback func(conn *grpcLib.ClientConn) bool, backoff Backoff) *outboundConnector {
	var attempts uint32
	return &outboundConnector{
		backoff:           backoff,
		address:           config.address,
		dialer:            dialer,
		tlsConfig:         config.tls,
		shouldConnect:     shouldConnect,
		connectedCallback: connectedCallback,
		connectLoopActive: &sync.WaitGroup{},
		lastAttempt:       &atomic.Value{},
		attempts:          &attempts,
		connectionTimeout: config.connectionTimeout,
		connectedBackoff: func(cancelCtx context.Context) {
			sleepWithCancel(cancelCtx, 2*time.Second)
		},
	}
}

type outboundConnector struct {
	dialer
	address           string
	connectionTimeout time.Duration
	backoff           Backoff
	tlsConfig         *tls.Config
	// connectedCallback is called when the outbound connection was successful and application-level operations can be performed.
	// If these fail and the connector should backoff before retrying, the callback should return 'false'.
	connectedCallback func(conn *grpcLib.ClientConn) bool
	// shouldConnect returns whether the connector must try to connect. If it returns false, it backs off.
	shouldConnect    func() bool
	connectedBackoff func(cancelCtx context.Context)
	// cancelFunc is used to signal the async connector loop (and specifically waits/sleeps) to abort.
	cancelFunc        func()
	connectLoopActive *sync.WaitGroup
	attempts          *uint32
	lastAttempt       *atomic.Value
}

func (c *outboundConnector) start() {
	var cancelCtx context.Context
	cancelCtx, c.cancelFunc = context.WithCancel(context.Background())
	c.connectLoopActive.Add(1)
	go func() {
		defer c.connectLoopActive.Done()
		// Take into account initial backoff
		sleepWithCancel(cancelCtx, c.backoff.Value())
		for {
			if cancelCtx.Err() == context.Canceled {
				return
			}
			if !c.shouldConnect() {
				c.connectedBackoff(cancelCtx)
				continue
			}
			stream, err := c.tryConnect(cancelCtx)
			if err == nil {
				// Invoke callback, blocks until the peer disconnects
				if !c.connectedCallback(stream) {
					err = errors.New("protocol connection failure")
				} else {
					// Connection was OK, but now disconnected
					// When the peer's reconnection timing is very close to the local node's (because they're running the same software),
					// they might reconnect to each other at the same time after a disconnect.
					// So we add a bit of randomness before reconnecting, making the chance they reconnect at the same time a lot smaller.
					sleepWithCancel(cancelCtx, RandomBackoff(time.Second, 5*time.Second))
				}
			}
			if err != nil {
				// either tryConnect or connectedCallback returned an error
				waitPeriod := c.backoff.Backoff()
				log.Logger().
					WithField(core.LogFieldPeerAddr, c.address).
					WithError(err).
					Infof("Couldn't connect to peer, reconnecting in %d seconds", int(waitPeriod.Seconds()))
				sleepWithCancel(cancelCtx, waitPeriod)
			}
		}
	}()
}

func (c *outboundConnector) stop() {
	// Signal connect loop to stop
	if c.cancelFunc != nil {
		c.cancelFunc()
	}
	// Wait for connect loop to stop
	println("waiting...", c.address)
	c.connectLoopActive.Wait()
	println("done!")
}

func (c *outboundConnector) tryConnect(ctx context.Context) (*grpcLib.ClientConn, error) {
	log.Logger().
		WithField(core.LogFieldPeerAddr, c.address).
		Info("Connecting to peer")
	atomic.AddUint32(c.attempts, 1)
	c.lastAttempt.Store(time.Now())

	dialContext, cancel := context.WithTimeout(ctx, c.connectionTimeout)
	defer cancel()

	dialOptions := []grpcLib.DialOption{
		grpcLib.WithBlock(),                 // Dial should block until connection succeeded (or time-out expired)
		grpcLib.WithReturnConnectionError(), // This option causes underlying errors to be returned when connections fail, rather than just "context deadline exceeded"
		grpcLib.WithDefaultCallOptions(
			grpcLib.MaxCallRecvMsgSize(MaxMessageSizeInBytes),
			grpcLib.MaxCallSendMsgSize(MaxMessageSizeInBytes),
		),
		grpcLib.WithUserAgent(core.UserAgent()),
	}
	if c.tlsConfig != nil {
		dialOptions = append(dialOptions, grpcLib.WithTransportCredentials(credentials.NewTLS(c.tlsConfig))) // TLS authentication
	} else {
		dialOptions = append(dialOptions, grpcLib.WithTransportCredentials(insecure.NewCredentials())) // No TLS, requires 'insecure' flag
	}
	grpcConn, err := c.dialer(dialContext, c.address, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect: %w", err)
	}
	log.Logger().
		WithField(core.LogFieldPeerAddr, c.address).
		Info("Connected to peer (outbound)")
	return grpcConn, nil
}

func (c outboundConnector) stats() transport.ConnectorStats {
	lastAttempt, _ := c.lastAttempt.Load().(time.Time)
	return transport.ConnectorStats{
		Address:     c.address,
		Attempts:    atomic.LoadUint32(c.attempts),
		LastAttempt: lastAttempt,
	}
}
