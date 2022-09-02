package grpc

import (
	"context"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"net"
	"strings"
	"testing"
)

func Test_ipInterceptor(t *testing.T) {
	var peerInfo *peer.Peer
	var success bool
	serverStream := &stubServerStream{}

	contextWithMD := func(xff string) context.Context {
		md := metadata.New(map[string]string{
			headerXForwardedFor: xff,
		})
		return metadata.NewIncomingContext(context.Background(), md)
	}

	var internalIPs = []string{
		"127.0.0.1",
		"::1",
		"169.254.0.0",
		"192.168.6.29",
		"10.1.2.3",
		"fc00::",
	}

	t.Run("XFF header", func(t *testing.T) {
		externalXFFAddr, _ := net.ResolveIPAddr("ip", "8.8.4.4")
		internalXFFAddr, _ := net.ResolveIPAddr("ip", internalIPs[0])
		peerNoAddres := net.Addr(nil)

		tests := []struct {
			xffIPs   []string
			expected net.Addr
		}{
			{append([]string{"8.8.8.8", "8.8.4.4"}, internalIPs...), externalXFFAddr},    // should be read right to left, so this is the first external IP
			{internalIPs, internalXFFAddr},                                               // all are internal, so select the IP the furthest away from server
			{append([]string{"invalid IP", "8.8.4.4"}, internalIPs...), externalXFFAddr}, // should be read right to left, so this is accepted
			{append([]string{"8.8.4.4", "invalid IP"}, internalIPs...), peerNoAddres},    // should be read right to left, so this is NOT accepted
			{append([]string{"8.8.8.8", "localhost"}, internalIPs...), peerNoAddres},     // localhost is not accepted
			{append([]string{"8.8.8.8", " 8.8.4.4 "}, internalIPs...), externalXFFAddr},  // spaces are trimmed
			{[]string{}, peerNoAddres},                                                   // empty header
		}

		for _, tc := range tests {
			serverStream.ctx = contextWithMD(strings.Join(tc.xffIPs, ","))
			_ = ipInterceptor(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
				peerInfo, success = peer.FromContext(wrappedStream.Context())
				return nil
			})

			if success {
				assert.Equal(t, tc.expected.String(), peerInfo.Addr.String())
			} else {
				assert.Nil(t, tc.expected)
			}
		}
	})
	t.Run("no XXF header", func(t *testing.T) {
		serverStream.ctx = metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{}))
		_ = ipInterceptor(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
			peerInfo, success = peer.FromContext(wrappedStream.Context())
			return nil
		})
		assert.False(t, success)
		assert.Nil(t, peerInfo)
	})
	t.Run("no metadata in context", func(t *testing.T) {
		serverStream.ctx = context.Background()
		_ = ipInterceptor(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
			peerInfo, success = peer.FromContext(wrappedStream.Context())
			return nil
		})
		assert.False(t, success)
		assert.Nil(t, peerInfo)
	})
}
