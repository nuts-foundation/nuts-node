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

package v2

import (
	"context"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

func Test_PeerDiagnosticsManager(t *testing.T) {
	t.Run("calls sender", func(t *testing.T) {
		wg := &sync.WaitGroup{}
		wg.Add(4)
		manager := newPeerDiagnosticsManager(func() transport.Diagnostics {
			return transport.Diagnostics{}
		}, func(diagnostics transport.Diagnostics) {
			wg.Done()
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go manager.start(ctx, 5*time.Millisecond)

		// Wait for the calls
		wg.Wait()
	})
}

const certBytes = `-----BEGIN CERTIFICATE-----
MIIDMTCCAhmgAwIBAgIJAPhraNcUMXs4MA0GCSqGSIb3DQEBCwUAMBIxEDAOBgNV
BAMMB1Jvb3QgQ0EwHhcNMjIxMTI4MTYwMzE5WhcNMjUwMzAyMTYwMzE5WjAUMRIw
EAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCxexjr0YvSDQUG19sSogI93UF6tsGW9gyJbpko86EPb/MAzmvU2/6Hb+Kbreil
MzEhSvtk+A8Vkgf7+NfW4tkrdyFBu6aAqW3jihvSbE7ptd+Gz75BS3j9iMAayy2p
085IJZtW85j497aO5qzJVTgFW2FwbQ9z38TJCuUkoeiJw/hElCYgDRATM7OUNA4i
Pu+3txUlYbTmPY4HDAG+Zhfm7WnaPXJsLLduxCpFZzi4oK0E2jrk1Epoku+FFxmP
EZUFRa684oEPJUEqKDS1q3QHTQdJChjZ80fmwtpPd1BCOaWAERTn1nFvrK2DL7LY
kK1Ag7d2wN00T/YVw8tThE45AgMBAAGjgYcwgYQwLAYDVR0jBCUwI6EWpBQwEjEQ
MA4GA1UEAwwHUm9vdCBDQYIJAJ2bDsozINJTMAkGA1UdEwQCMAAwCwYDVR0PBAQD
AgTwMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHREEFjAUggls
b2NhbGhvc3SCB251dHMubmwwDQYJKoZIhvcNAQELBQADggEBAKFxNP1p6S4uQXoF
l5KzF8fl6pG3eRTWUehUgQe5cP4PwiT5v/zBpZy3nIqVQXW360B3xmS+TpkIsa5h
cR8krOcC6AtVP64efIAnplEmz+pbbiZ0kJsyWVH0fl4VxKOMLF7jTvnFvAhC3ad5
kONPGln7eoxs7FFTdnAEK1LfCxsCTujVe/0xnjj9DLgPf0etehoSsZmfc2ukLlNR
p21P9o/yY3Rz1y9XhXBttE0L0Cx434rIZ6fSY4hDbOYfM8Y5sra47P9GyNMcqQIY
6V1iHNN1bqrjT/4WplTy0lMgRt0+EtevWhKKqXQi6vPKvWeQQEyphx3wIEfYAFrE
tyJ+7iY=
-----END CERTIFICATE-----
`

func MakeTestPeer(t testing.TB) transport.Peer {
	certs, err := core.ParseCertificates([]byte(certBytes))
	require.NoError(t, err)
	return transport.Peer{
		ID:          "peer",
		Certificate: certs[0],
		NodeDID:     *nodeDID,
		Address:     "example.com",
	}
}

func Test_PeerDiagnosticsManager_HandleReceived(t *testing.T) {
	testPeer := MakeTestPeer(t)

	manager := newPeerDiagnosticsManager(nil, nil)
	expected := transport.Diagnostics{
		Uptime:               10 * time.Second,
		Peers:                []transport.PeerID{"1", "2"},
		NumberOfTransactions: 1000,
		SoftwareVersion:      "abc",
		SoftwareID:           "def",
		Certificate:          certBytes,
		NodeDID:              testPeer.NodeDID.String(),
		Address:              testPeer.Address,
	}
	manager.handleReceived(testPeer, &Diagnostics{
		Uptime:               10,
		PeerID:               "1234",
		Peers:                []string{"1", "2"},
		NumberOfTransactions: 1000,
		SoftwareVersion:      "abc",
		SoftwareID:           "def",
	})

	assert.Equal(t, expected, manager.get()[testPeer.ID])
}

func Test_PeerDiagnosticsManager_Add(t *testing.T) {
	testPeer := MakeTestPeer(t)
	expected := transport.Diagnostics{
		Peers:       []transport.PeerID{},
		Certificate: certBytes,
		NodeDID:     testPeer.NodeDID.String(),
		Address:     testPeer.Address,
	}

	manager := newPeerDiagnosticsManager(nil, nil)
	manager.add(testPeer)
	assert.Equal(t, expected, manager.get()[testPeer.ID])
}

func Test_PeerDiagnosticsManager_Remove(t *testing.T) {
	manager := newPeerDiagnosticsManager(nil, nil)
	manager.add(testPeer)
	_, present := manager.get()[testPeer.ID]
	assert.True(t, present)
	assert.Len(t, manager.get(), 1)

	// Now remove
	manager.remove(testPeer)
	_, present = manager.get()[testPeer.ID]
	assert.False(t, present)
	assert.Len(t, manager.get(), 0)
}
