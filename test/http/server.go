/*
 * Copyright (C) 2023 Nuts community
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

package http

import (
	"crypto/tls"
	"github.com/nuts-foundation/nuts-node/test/pki"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	tlsServer := httptest.NewUnstartedServer(handler)
	tlsServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{pki.Certificate()},
	}
	tlsServer.StartTLS()
	t.Cleanup(tlsServer.Close)
	return tlsServer
}
