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

type outboundConnector struct {
	address string
	dialer
	backoff
	tlsConfig         *tls.Config
	localPeerID       transport.PeerID
	connectedCallback func(conn *grpcLib.ClientConn)
}

func (c *outboundConnector) loopConnect() {
	for {
		// TODO: What if we received an inbound connection at the same time?
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
	log.Logger().Infof("Connecting to peer: %v", c.address)

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
	return grpcConn, nil
}
