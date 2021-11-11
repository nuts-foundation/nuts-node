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
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/network/transport"
	grpcLib "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"time"
)

type dialer func(ctx context.Context, target string, opts ...grpcLib.DialOption) (conn *grpcLib.ClientConn, err error)

func createOutboundConnector(address string, dialer dialer, tlsConfig *tls.Config, shouldConnect func() bool, connectedCallback func(conn *grpcLib.ClientConn)) *outboundConnector {
	return &outboundConnector{
		address:           address,
		dialer:            dialer,
		tlsConfig:         tlsConfig,
		shouldConnect:     shouldConnect,
		connectedCallback: connectedCallback,
		connectedBackoff: func() {
			time.Sleep(time.Second)
		},
	}
}

type outboundConnector struct {
	address string
	dialer
	backoff
	tlsConfig         *tls.Config
	localPeerID       transport.PeerID
	connectedCallback func(conn *grpcLib.ClientConn)
	// shouldConnect returns whether the connector must try to connect. If it returns false, it backs off.
	shouldConnect    func() bool
	connectedBackoff func()
}

func (c *outboundConnector) loopConnect() {
	for {
		if !c.shouldConnect() {
			c.connectedBackoff()
			continue
		}
		if stream, err := c.tryConnect(); err != nil {
			waitPeriod := c.backoff.Backoff()
			log.Logger().Infof("Couldn't connect to peer, reconnecting in %d seconds (peer=%s,err=%v)", int(waitPeriod.Seconds()), c.address, err)
			time.Sleep(waitPeriod)
		} else {
			c.backoff.Reset()

			// Invoke callback, blocks until the peer disconnects
			c.connectedCallback(stream)

			// When the peer's reconnection timing is very close to the local node's (because they're running the same software),
			// they might reconnect to each other at the same time after a disconnect.
			// So we add a bit of randomness before reconnecting, making the chance they reconnect at the same time a lot smaller.
			time.Sleep(RandomBackoff(time.Second, 5*time.Second))
		}
	}
}

func (c *outboundConnector) tryConnect() (*grpcLib.ClientConn, error) {
	log.Logger().Infof("Connecting to peer: %s", c.address)

	dialContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dialOptions := []grpcLib.DialOption{
		grpcLib.WithBlock(),                 // Dial should block until connection succeeded (or time-out expired)
		grpcLib.WithReturnConnectionError(), // This option causes underlying errors to be returned when connections fail, rather than just "context deadline exceeded"
		grpcLib.WithDefaultCallOptions(
			grpcLib.MaxCallRecvMsgSize(MaxMessageSizeInBytes),
			grpcLib.MaxCallSendMsgSize(MaxMessageSizeInBytes),
		),
	}
	if c.tlsConfig != nil {
		dialOptions = append(dialOptions, grpcLib.WithTransportCredentials(credentials.NewTLS(c.tlsConfig))) // TLS authentication
	} else {
		dialOptions = append(dialOptions, grpcLib.WithInsecure()) // No TLS, requires 'insecure' flag
	}
	grpcConn, err := c.dialer(dialContext, c.address, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("unable to connect: %w", err)
	}
	log.Logger().Infof("Connected to peer (outbound): %s", c.address)
	return grpcConn, nil
}
