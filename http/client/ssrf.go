/*
 * Copyright (C) 2026 Nuts community
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

package client

import (
	"fmt"
	"net/netip"
	"slices"
	"syscall"
)

// This file implements the strict-mode SSRF dial guard: it decides, per connection and based on
// the resolved IP address, whether an outbound request may proceed. The public/non-public split
// follows the IANA special-purpose address registries; the prefix sets mirror those maintained by
// github.com/daenney/ssrf, generated from the same registries.

// allowedNonPublicNets holds IP networks that outbound requests may connect to even in strict
// mode, despite being on a non-public network. It is configured through SetAllowedNonPublicCIDRs
// from http.client.allowedinternalcidrs, for closed deployments that legitimately federate over a
// private network (e.g. an internal OAuth or credential flow).
var allowedNonPublicNets []netip.Prefix

// SetAllowedNonPublicCIDRs parses the given CIDR strings and replaces the set of non-public
// networks that strict mode permits. It returns an error on the first invalid CIDR, leaving the
// previous value unchanged.
func SetAllowedNonPublicCIDRs(cidrs []string) error {
	nets, err := parseCIDRs(cidrs)
	if err != nil {
		return err
	}
	allowedNonPublicNets = nets
	return nil
}

// deniedNets holds IP networks that outbound requests must never connect to in strict mode,
// regardless of the allowlist. It always contains deniedCloudMetadataPrefixes; operator-configured
// ranges from http.client.deniedcidrs (SetDeniedCIDRs) are appended, for deployments whose
// infrastructure uses publicly routable ranges that are internal-only.
var deniedNets = slices.Clone(deniedCloudMetadataPrefixes)

// SetDeniedCIDRs parses the given CIDR strings and replaces the operator-configured part of the
// denied networks; the built-in cloud metadata prefixes are always retained. It returns an error
// on the first invalid CIDR, leaving the previous value unchanged.
func SetDeniedCIDRs(cidrs []string) error {
	nets, err := parseCIDRs(cidrs)
	if err != nil {
		return err
	}
	deniedNets = append(slices.Clone(deniedCloudMetadataPrefixes), nets...)
	return nil
}

// parseCIDRs parses CIDR strings into masked prefixes, failing on the first invalid entry.
func parseCIDRs(cidrs []string) ([]netip.Prefix, error) {
	nets := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		nets = append(nets, prefix.Masked())
	}
	return nets, nil
}

// isAllowedNonPublic reports whether ip falls within one of the configured allowlisted networks.
func isAllowedNonPublic(ip netip.Addr) bool {
	for _, n := range allowedNonPublicNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// deniedCloudMetadataPrefixes are cloud provider metadata endpoints that sit on public address
// space, which the non-public check cannot cover. Blocking cloud metadata endpoints follows the
// OWASP SSRF prevention cheat sheet
// (https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html):
// metadata services hand out credentials and instance configuration, making them the primary SSRF
// target in cloud deployments. Of the endpoints OWASP lists, only Azure's needs an entry here; the
// others (169.254.169.254 used by AWS/GCP/Azure/OpenStack, Alibaba's 100.100.100.200, AWS's
// fd00:ec2::254) already fall in blocked non-public ranges (link-local, CGNAT, ULA). Kept separate
// from the IANA lists so the upstream drift test stays exact.
var deniedCloudMetadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("168.63.129.16/32"), // Azure wire server / metadata
}

// isDenied reports whether ip falls in an explicitly denied range: a built-in cloud metadata
// endpoint or an operator-configured denied network. Denied ranges are refused even when the
// allowlist covers them.
func isDenied(ip netip.Addr) bool {
	for _, prefix := range deniedNets {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// deniedIPv4Prefixes are the IPv4 special-purpose ranges from the IANA registry
// (https://www.iana.org/assignments/iana-ipv4-special-registry/), following the set used by
// github.com/daenney/ssrf. None of these are legitimate targets for federation traffic.
var deniedIPv4Prefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "This network" (RFC 791), includes the unspecified address
	netip.MustParsePrefix("10.0.0.0/8"),      // Private-Use (RFC 1918)
	netip.MustParsePrefix("100.64.0.0/10"),   // Shared Address Space / CGNAT (RFC 6598)
	netip.MustParsePrefix("127.0.0.0/8"),     // Loopback (RFC 1122)
	netip.MustParsePrefix("169.254.0.0/16"),  // Link Local (RFC 3927), includes cloud metadata 169.254.169.254
	netip.MustParsePrefix("172.16.0.0/12"),   // Private-Use (RFC 1918)
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF Protocol Assignments (RFC 6890)
	netip.MustParsePrefix("192.0.2.0/24"),    // Documentation TEST-NET-1 (RFC 5737)
	netip.MustParsePrefix("192.31.196.0/24"), // AS112-v4 (RFC 7535)
	netip.MustParsePrefix("192.52.193.0/24"), // AMT (RFC 7450)
	netip.MustParsePrefix("192.88.99.0/24"),  // Deprecated 6to4 Relay Anycast (RFC 7526)
	netip.MustParsePrefix("192.168.0.0/16"),  // Private-Use (RFC 1918)
	netip.MustParsePrefix("192.175.48.0/24"), // Direct Delegation AS112 Service (RFC 7534)
	netip.MustParsePrefix("198.18.0.0/15"),   // Benchmarking (RFC 2544)
	netip.MustParsePrefix("198.51.100.0/24"), // Documentation TEST-NET-2 (RFC 5737)
	netip.MustParsePrefix("203.0.113.0/24"),  // Documentation TEST-NET-3 (RFC 5737)
	netip.MustParsePrefix("224.0.0.0/4"),     // Multicast (RFC 1112)
	netip.MustParsePrefix("240.0.0.0/4"),     // Reserved (RFC 1112), includes the broadcast address
}

// globalUnicastIPv6Prefix is the range IANA allocates global unicast addresses from, i.e. "the
// internet". IPv6 is guarded allowlist-style: anything outside this range is refused, which covers
// loopback, unspecified, unique local, link-local, site-local, multicast, the discard prefix and
// the NAT64 well-known prefix without enumerating them.
var globalUnicastIPv6Prefix = netip.MustParsePrefix("2000::/3")

// deniedIPv6Prefixes are special-purpose ranges inside the global unicast range
// (https://www.iana.org/assignments/iana-ipv6-special-registry/), following the set used by
// github.com/daenney/ssrf. 2001::/23 includes Teredo and ORCHID; 2002::/16 (6to4) embeds an IPv4
// address, so it could smuggle a connection toward an internal IPv4 target through a relay.
var deniedIPv6Prefixes = []netip.Prefix{
	netip.MustParsePrefix("2001::/23"),         // IETF Protocol Assignments (RFC 2928)
	netip.MustParsePrefix("2001:db8::/32"),     // Documentation (RFC 3849)
	netip.MustParsePrefix("2002::/16"),         // 6to4 (RFC 3056)
	netip.MustParsePrefix("2620:4f:8000::/48"), // Direct Delegation AS112 Service (RFC 7534)
	netip.MustParsePrefix("3fff::/20"),         // Documentation (RFC 9637)
}

// isNonPublicAddr reports whether ip is not a public internet address. IPv4 (including IPv4-mapped
// IPv6, which the caller must Unmap first) is checked against the special-purpose denylist; IPv6
// must be global unicast and outside the special-purpose ranges within it. IPv6 addresses with a
// zone never match a prefix and are treated as non-public.
func isNonPublicAddr(ip netip.Addr) bool {
	if ip.Is4() {
		for _, prefix := range deniedIPv4Prefixes {
			if prefix.Contains(ip) {
				return true
			}
		}
		return false
	}
	if !globalUnicastIPv6Prefix.Contains(ip) {
		return true
	}
	for _, prefix := range deniedIPv6Prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// denyNonPublicAddr is a net.Dialer.Control hook. In strict mode it refuses connections whose
// resolved address is not a public internet address (see isNonPublicAddr). Because it inspects the
// actual IP the socket is about to connect to (after DNS resolution), it closes DNS-rebinding into
// those ranges, which URL-string validation such as core.ParsePublicURL cannot.
//
// Closed deployments that legitimately federate over a private network can permit specific ranges
// through SetAllowedNonPublicCIDRs (config http.client.allowedinternalcidrs).
func denyNonPublicAddr(_ string, address string, _ syscall.RawConn) error {
	if !StrictMode {
		return nil
	}
	// The Control hook runs after DNS resolution, so address holds a literal IP.
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("strictmode: cannot parse connection address %q: %w", address, err)
	}
	ip := addrPort.Addr().Unmap()
	if isDenied(ip) {
		return fmt.Errorf("strictmode: blocked connection to denied address %s", ip)
	}
	if isNonPublicAddr(ip) && !isAllowedNonPublic(ip) {
		return fmt.Errorf("strictmode: blocked connection to non-public address %s", ip)
	}
	return nil
}
