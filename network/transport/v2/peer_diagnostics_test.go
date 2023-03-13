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
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
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

func Test_PeerDiagnosticsManager_HandleReceived(t *testing.T) {
	manager := newPeerDiagnosticsManager(nil, nil)
	expected := transport.Diagnostics{
		Uptime:               10 * time.Second,
		Peers:                []transport.PeerID{"1", "2"},
		NumberOfTransactions: 1000,
		SoftwareVersion:      "abc",
		SoftwareID:           "def",
	}
	manager.handleReceived("1234", &Diagnostics{
		Uptime:               10,
		PeerID:               "1234",
		Peers:                []string{"1", "2"},
		NumberOfTransactions: 1000,
		SoftwareVersion:      "abc",
		SoftwareID:           "def",
	})

	assert.Equal(t, expected, manager.get()["1234"])
}

func Test_PeerDiagnosticsManager_Add(t *testing.T) {
	manager := newPeerDiagnosticsManager(nil, nil)
	manager.add("1234")
	assert.NotNil(t, manager.get()["1234"])
}

func Test_PeerDiagnosticsManager_Remove(t *testing.T) {
	manager := newPeerDiagnosticsManager(nil, nil)
	manager.add("1234")
	_, present := manager.get()["1234"]
	assert.True(t, present)

	// Now remove
	manager.remove("1234")
	_, present = manager.get()["1234"]
	assert.False(t, present)
}
