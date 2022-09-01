package grpc

import (
	"net"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// ipExtractor tries to extract the IP from the X-Forwarded-For header and sets this as the peers address.
// No address is set if the header is unavailable.
func ipInterceptor(srv interface{}, serverStream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	peerInfo, _ := peer.FromContext(serverStream.Context())
	if peerInfo == nil {
		peerInfo = &peer.Peer{}
	}
	if addr := addrFrom(extractIPFromXFFHeader(serverStream)); addr != nil {
		peerInfo.Addr = addr
	}
	ctx := peer.NewContext(serverStream.Context(), peerInfo)
	return handler(srv, &wrappedServerStream{ctx: ctx, ServerStream: serverStream})
}

// extractIPFromXFFHeader tries to retrieve the address from X-Forward-For header.
// Implementation is based on echo.ExtractIPFromXFFHeader().
func extractIPFromXFFHeader(serverStream grpc.ServerStream) string {
	ipUnknown := ""
	md, ok := metadata.FromIncomingContext(serverStream.Context())
	if !ok {
		return ipUnknown
	}
	xffs := md.Get("X-Forwarded-For")
	if len(xffs) == 0 {
		return ipUnknown
	}
	ips := append(strings.Split(strings.Join(xffs, ","), ","))
	for i := len(ips) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(ips[i]))
		if ip == nil {
			// Unable to parse IP; cannot trust entire records
			return ipUnknown
		}
		if !isInternal(ip) {
			return ip.String()
		}
	}

	// All of the IPs are trusted; return first element because it is furthest from server (best effort strategy).
	return strings.TrimSpace(ips[0])
}

// addrFrom returns nil if ip is not a valid IP
func addrFrom(ip string) net.Addr {
	addr, err := net.ResolveIPAddr("ip", ip)
	if err != nil {
		return nil
	}
	return addr
}

func isInternal(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}
