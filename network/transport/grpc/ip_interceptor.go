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
	"net"
	"net/netip"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

const headerXForwardedFor = "X-Forwarded-For"

// ipInterceptor tries to extract the IP from the X-Forwarded-For header and sets this as the peers address.
// No address is set if the header is unavailable.
func ipInterceptor(ipHeader string) grpc.StreamServerInterceptor {
	var extractIPHeader func(serverStream grpc.ServerStream) string
	switch ipHeader {
	case headerXForwardedFor:
		extractIPHeader = extractIPFromXFFHeader
	case "":
		extractIPHeader = func(_ grpc.ServerStream) string {
			return ""
		}
	default:
		extractIPHeader = extractIPFromCustomHeader(ipHeader)
	}
	return func(srv interface{}, serverStream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		addr := addrFrom(extractIPHeader(serverStream))
		if addr == nil {
			// Exit without change if there is no X-Forwarded-For in the http header,
			// or if no IP could be extracted from the header.
			// This will default to the IP found in lvl 4 header.
			return handler(srv, serverStream)
		}

		peerInfo, _ := peer.FromContext(serverStream.Context())
		if peerInfo == nil {
			peerInfo = &peer.Peer{}
		}
		peerInfo.Addr = addr
		ctx := peer.NewContext(serverStream.Context(), peerInfo)
		return handler(srv, &wrappedServerStream{ctx: ctx, ServerStream: serverStream})
	}
}

// extractIPFromXFFHeader tries to retrieve the address from X-Forward-For header. Returns an empty string if non found.
// Implementation is based on echo.ExtractIPFromXFFHeader().
func extractIPFromXFFHeader(serverStream grpc.ServerStream) string {
	ipUnknown := ""
	md, ok := metadata.FromIncomingContext(serverStream.Context())
	if !ok {
		return ipUnknown
	}
	xffs := md.Get(headerXForwardedFor)
	if len(xffs) == 0 {
		return ipUnknown
	}
	ips := strings.Split(strings.Join(xffs, ","), ",")
	for i := len(ips) - 1; i >= 0; i-- {
		ip := net.ParseIP(trimIP(ips[i]))
		if ip == nil {
			// Unable to parse IP; cannot trust entire records
			return ipUnknown
		}
		// Return first non-internal address
		if !isInternal(ip) {
			return ip.String()
		}
	}

	// All IPs are trusted; return first element because it is furthest from server (best effort strategy).
	return strings.TrimSpace(ips[0])
}

// addrFrom returns nil if ip is not a valid IP
func addrFrom(ip string) net.Addr {
	if ip == "" {
		return nil
	}
	ipAddr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil
	}
	return &net.IPAddr{
		IP:   ipAddr.AsSlice(),
		Zone: ipAddr.Zone(),
	}
}

func isInternal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

// extractIPFromCustomHeader extracts an IP address from any custom header.
// This is an altered version of echo.ExtractIPFromRealIPHeader() that does not check for trusted IPs.
func extractIPFromCustomHeader(ipHeader string) func(serverStream grpc.ServerStream) string {
	return func(serverStream grpc.ServerStream) string {
		ipUnknown := ""
		md, ok := metadata.FromIncomingContext(serverStream.Context())
		if !ok {
			return ipUnknown
		}
		header := md.Get(ipHeader)
		if len(header) != 1 {
			return ipUnknown
		}
		return trimIP(header[0])
	}
}

func trimIP(ip string) string {
	ip = strings.TrimSpace(ip)
	// trim brackets from IPv6
	ip = strings.TrimPrefix(ip, "[")
	ip = strings.TrimSuffix(ip, "]")
	return ip
}
