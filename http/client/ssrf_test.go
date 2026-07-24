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
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"testing"
	"time"

	"code.dny.dev/ssrf"
	"github.com/nuts-foundation/nuts-node/tracing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrefixesMatchUpstream cross-checks our prefix sets against code.dny.dev/ssrf (test-only
// dependency), which regenerates them from the IANA special-purpose registries. A failure after a
// dependency bump means the registries changed and our lists need updating.
func TestPrefixesMatchUpstream(t *testing.T) {
	asStrings := func(prefixes []netip.Prefix) []string {
		result := make([]string, 0, len(prefixes))
		for _, prefix := range prefixes {
			result = append(result, prefix.String())
		}
		slices.Sort(result)
		return result
	}
	outdated := func(list, registry string) string {
		return fmt.Sprintf("%s in ssrf.go is outdated: the IANA special-purpose registry changed "+
			"(see https://www.iana.org/assignments/%s/). Update it to match code.dny.dev/ssrf", list, registry)
	}
	assert.Equal(t, asStrings(ssrf.IPv4DeniedPrefixes), asStrings(deniedIPv4Prefixes),
		outdated("deniedIPv4Prefixes", "iana-ipv4-special-registry"))
	assert.Equal(t, asStrings(ssrf.IPv6DeniedPrefixes), asStrings(deniedIPv6Prefixes),
		outdated("deniedIPv6Prefixes", "iana-ipv6-special-registry"))
	assert.Equal(t, ssrf.IPv6GlobalUnicast, globalUnicastIPv6Prefix,
		outdated("globalUnicastIPv6Prefix", "iana-ipv6-special-registry"))
	// The NAT64 prefix lies outside global unicast, so the guard blocks it by construction.
	assert.False(t, globalUnicastIPv6Prefix.Contains(ssrf.IPv6NAT64Prefix.Addr()),
		"the NAT64 well-known prefix moved inside global unicast; block it explicitly in ssrf.go")
}

func TestDenyNonPublicAddr(t *testing.T) {
	setStrictMode := func(t *testing.T, v bool) {
		old := StrictMode
		StrictMode = v
		t.Cleanup(func() { StrictMode = old })
	}
	setAllowlist := func(t *testing.T, cidrs ...string) {
		old := allowedNonPublicNets
		require.NoError(t, SetAllowedNonPublicCIDRs(cidrs))
		t.Cleanup(func() { allowedNonPublicNets = old })
	}
	t.Run("strict mode blocks non-public addresses", func(t *testing.T) {
		setStrictMode(t, true)
		blocked := map[string]string{
			"loopback IPv4":              "127.0.0.1:443",
			"loopback IPv6":              "[::1]:443",
			"private RFC1918 10/8":       "10.0.0.5:443",
			"private RFC1918 172.16/12":  "172.16.0.1:443",
			"private RFC1918 192.168/16": "192.168.1.1:443",
			"unique local IPv6":          "[fd00::1]:443",
			"link-local IPv4":            "169.254.169.254:443",
			"link-local IPv6":            "[fe80::1]:443",
			"unspecified IPv4":           "0.0.0.0:443",
			"unspecified IPv6":           "[::]:443",
			"this-network 0/8":           "0.1.2.3:443",
			"CGNAT shared space":         "100.64.1.1:443",
			"IETF protocol assignments":  "192.0.0.8:443",
			"documentation TEST-NET-1":   "192.0.2.1:443",
			"documentation TEST-NET-2":   "198.51.100.1:443",
			"documentation TEST-NET-3":   "203.0.113.1:443",
			"benchmarking":               "198.18.0.1:443",
			"6to4 relay anycast":         "192.88.99.1:443",
			"multicast IPv4":             "224.0.1.1:443",
			"reserved 240/4":             "240.0.0.1:443",
			"broadcast":                  "255.255.255.255:443",
			"v4-mapped IPv6 loopback":    "[::ffff:127.0.0.1]:443",
			"v4-mapped IPv6 private":     "[::ffff:10.0.0.5]:443",
			"NAT64 well-known prefix":    "[64:ff9b::a00:1]:443",
			"discard-only IPv6":          "[100::1]:443",
			"site-local IPv6 deprecated": "[fec0::1]:443",
			"multicast IPv6":             "[ff05::1]:443",
			"6to4 embedding private":     "[2002:a00:1::1]:443",
			"Teredo":                     "[2001::1]:443",
			"documentation IPv6":         "[2001:db8::1]:443",
			"documentation IPv6 3fff":    "[3fff::1]:443",
			"link-local IPv6 with zone":  "[fe80::1%eth0]:443",
		}
		for name, address := range blocked {
			t.Run(name, func(t *testing.T) {
				err := denyNonPublicAddr("tcp", address, nil)
				assert.ErrorContains(t, err, "blocked connection to non-public address")
			})
		}
	})
	t.Run("strict mode allows public addresses", func(t *testing.T) {
		setStrictMode(t, true)
		for _, address := range []string{"8.8.8.8:443", "93.184.216.34:443", "[2606:2800:220:1:248:1893:25c8:1946]:443"} {
			t.Run(address, func(t *testing.T) {
				assert.NoError(t, denyNonPublicAddr("tcp", address, nil))
			})
		}
	})
	t.Run("strict mode allows non-public addresses that are in the allowlist", func(t *testing.T) {
		setStrictMode(t, true)
		setAllowlist(t, "10.0.0.0/8", "fd00::/8")

		assert.NoError(t, denyNonPublicAddr("tcp", "10.1.2.3:443", nil))
		assert.NoError(t, denyNonPublicAddr("tcp", "[fd00::1]:443", nil))
		// Non-public addresses outside the allowlisted ranges are still blocked.
		assert.ErrorContains(t, denyNonPublicAddr("tcp", "192.168.1.1:443", nil), "blocked connection to non-public address")
		assert.ErrorContains(t, denyNonPublicAddr("tcp", "127.0.0.1:443", nil), "blocked connection to non-public address")
	})
	t.Run("non-strict mode allows non-public addresses", func(t *testing.T) {
		setStrictMode(t, false)
		assert.NoError(t, denyNonPublicAddr("tcp", "127.0.0.1:443", nil))
		assert.NoError(t, denyNonPublicAddr("tcp", "10.0.0.5:443", nil))
	})
}

func TestSetAllowedNonPublicCIDRs(t *testing.T) {
	old := allowedNonPublicNets
	t.Cleanup(func() { allowedNonPublicNets = old })
	t.Run("valid", func(t *testing.T) {
		require.NoError(t, SetAllowedNonPublicCIDRs([]string{"10.0.0.0/8", "fd00::/8"}))
		assert.Len(t, allowedNonPublicNets, 2)
	})
	t.Run("invalid leaves previous value unchanged", func(t *testing.T) {
		require.NoError(t, SetAllowedNonPublicCIDRs([]string{"10.0.0.0/8"}))
		err := SetAllowedNonPublicCIDRs([]string{"not-a-cidr"})
		assert.ErrorContains(t, err, "not-a-cidr")
		assert.Len(t, allowedNonPublicNets, 1)
	})
	t.Run("empty clears the allowlist", func(t *testing.T) {
		require.NoError(t, SetAllowedNonPublicCIDRs([]string{"10.0.0.0/8"}))
		require.NoError(t, SetAllowedNonPublicCIDRs(nil))
		assert.Empty(t, allowedNonPublicNets)
	})
}

func TestSafeHttpTransport_SSRFDialGuard(t *testing.T) {
	original := tracing.Enabled()
	tracing.SetEnabled(false) // ensure New() returns SafeHttpTransport directly
	t.Cleanup(func() { tracing.SetEnabled(original) })

	// httptest TLS server listens on a loopback address.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Run("strict mode blocks connection to loopback server before TLS handshake", func(t *testing.T) {
		old := StrictMode
		StrictMode = true
		t.Cleanup(func() { StrictMode = old })

		client := New(time.Second)
		req, _ := http.NewRequest("GET", server.URL, nil)
		_, err := client.Do(req)

		require.Error(t, err)
		assert.ErrorContains(t, err, "blocked connection to non-public address")
	})
}
