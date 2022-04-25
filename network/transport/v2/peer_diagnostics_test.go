package v2

import (
	"context"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
	"go.uber.org/atomic"
	"testing"
	"time"
)

func Test_PeerDiagnosticsManager(t *testing.T) {
	t.Run("calls sender", func(t *testing.T) {
		calls := &atomic.Int32{}
		manager := newPeerDiagnosticsManager(func() transport.Diagnostics {
			return transport.Diagnostics{}
		}, func(diagnostics transport.Diagnostics) {
			calls.Add(1)
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		manager.start(ctx, 5*time.Millisecond)

		// Wait for a bit, then check if it's at least been sent a few times
		time.Sleep(20 * time.Millisecond)
		assert.True(t, calls.Load() > 2)
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
