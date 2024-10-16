/*
 * Copyright (C) 2022 Nuts community
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"net"
	"net/netip"
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
		externalIPv4XFFAddr := &net.IPAddr{IP: []byte{8, 8, 4, 4}}
		ipv6 := "2001:4860:4860::8844"
		ipAddr, err := netip.ParseAddr(ipv6)
		require.NoError(t, err, "failed to parse IPv6")
		externalIPv6XFFAddr := &net.IPAddr{
			IP:   ipAddr.AsSlice(),
			Zone: ipAddr.Zone(),
		}
		ipv6 = "[" + ipv6 + "]" // trims brackets from ipv6
		internalXFFAddr, _ := net.ResolveIPAddr("ip", internalIPs[0])
		peerNoAddres := net.Addr(nil)

		tests := []struct {
			xffIPs   []string
			expected net.Addr
		}{
			{append([]string{"8.8.8.8", "8.8.4.4"}, internalIPs...), externalIPv4XFFAddr},    // should be read right to left, so this is the first external IP
			{append([]string{"8.8.8.8", ipv6}, internalIPs...), externalIPv6XFFAddr},         // should be read right to left, so this is the first external IP
			{internalIPs, internalXFFAddr},                                                   // all are internal, so select the IP the furthest away from server
			{append([]string{"invalid IP", "8.8.4.4"}, internalIPs...), externalIPv4XFFAddr}, // should be read right to left, so this is accepted
			{append([]string{"8.8.4.4", "invalid IP"}, internalIPs...), peerNoAddres},        // should be read right to left, so this is NOT accepted
			{append([]string{"8.8.8.8", "localhost"}, internalIPs...), peerNoAddres},         // localhost is not accepted
			{append([]string{"8.8.8.8", " 8.8.4.4 "}, internalIPs...), externalIPv4XFFAddr},  // spaces are trimmed
			{[]string{}, peerNoAddres}, // empty header
		}

		for _, tc := range tests {
			ran := false
			serverStream.ctx = contextWithMD(strings.Join(tc.xffIPs, ","))
			_ = ipInterceptor(headerXForwardedFor)(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
				peerInfo, success = peer.FromContext(wrappedStream.Context())
				ran = true
				return nil
			})

			require.True(t, ran, "test logic was not executed")
			if success {
				assert.Equal(t, tc.expected.String(), peerInfo.Addr.String())
			} else {
				assert.Nil(t, tc.expected)
			}
		}
	})
	t.Run("no XXF header", func(t *testing.T) {
		ran := false
		serverStream.ctx = metadata.NewIncomingContext(context.Background(), metadata.New(map[string]string{}))
		_ = ipInterceptor(headerXForwardedFor)(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
			peerInfo, success = peer.FromContext(wrappedStream.Context())
			ran = true
			return nil
		})
		require.True(t, ran, "test logic was not executed")
		assert.False(t, success)
		assert.Nil(t, peerInfo)
	})
	t.Run("no metadata in context", func(t *testing.T) {
		ran := false
		serverStream.ctx = context.Background()
		_ = ipInterceptor(headerXForwardedFor)(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
			peerInfo, success = peer.FromContext(wrappedStream.Context())
			ran = true
			return nil
		})
		require.True(t, ran, "test logic was not executed")
		assert.False(t, success)
		assert.Nil(t, peerInfo)
	})
	t.Run("custom header", func(t *testing.T) {
		header := "X-Custom-Header"
		expectedIP := "1.2.3.4"
		t.Run("ok", func(t *testing.T) {
			ran := false
			md := metadata.New(map[string]string{header: expectedIP})
			serverStream.ctx = metadata.NewIncomingContext(context.Background(), md)
			_ = ipInterceptor(header)(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
				peerInfo, success = peer.FromContext(wrappedStream.Context())
				ran = true
				return nil
			})

			require.True(t, ran, "test logic was not executed")
			assert.True(t, success)
			assert.Equal(t, expectedIP, peerInfo.Addr.String())
		})
		t.Run("empty header", func(t *testing.T) {
			ran := false
			md := metadata.New(map[string]string{header: ""})
			serverStream.ctx = metadata.NewIncomingContext(context.Background(), md)
			_ = ipInterceptor(header)(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
				peerInfo, success = peer.FromContext(wrappedStream.Context())
				ran = true
				return nil
			})

			require.True(t, ran, "test logic was not executed")
			assert.False(t, success)
			assert.Nil(t, peerInfo)
		})
		t.Run("empty header", func(t *testing.T) {
			ran := false
			md := metadata.New(map[string]string{header: strings.Join([]string{expectedIP, expectedIP}, ",")})
			serverStream.ctx = metadata.NewIncomingContext(context.Background(), md)
			_ = ipInterceptor(header)(nil, serverStream, nil, func(srv interface{}, wrappedStream grpc.ServerStream) error {
				peerInfo, success = peer.FromContext(wrappedStream.Context())
				ran = true
				return nil
			})

			require.True(t, ran, "test logic was not executed")
			assert.False(t, success)
			assert.Nil(t, peerInfo)
		})
	})
}
