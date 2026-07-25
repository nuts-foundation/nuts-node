/*
 * Copyright (C) 2024 Nuts community
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
	"net"
	"net/http"
	"time"
)

// SafeHttpTransport is a http.Transport that must be used as transport for HTTP clients
// that fetch URLs influenced by other parties, e.g. OpenID4VCI issuer/wallet endpoints and
// OAuth endpoints resolved from DID documents. It carries the strict-mode SSRF dial guard
// (see denyNonPublicAddr). It is deliberately NOT installed on http.DefaultTransport:
// PKI CRL fetching and external crypto storage clients may legitimately target
// non-public addresses.
var SafeHttpTransport *http.Transport

func init() {
	SafeHttpTransport = http.DefaultTransport.(*http.Transport).Clone()
	// guard against SSRF: in strict mode, refuse to connect to non-public addresses,
	// checked against the resolved IP so DNS-rebinding cannot bypass it.
	// Keeps the default dialer timeouts used by http.DefaultTransport.
	SafeHttpTransport.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   denyNonPublicAddr,
	}).DialContext
}

// StrictMode is a flag that can be set to true to enable strict mode for the HTTP client.
var StrictMode bool
