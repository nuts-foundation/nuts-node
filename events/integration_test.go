/*
 * Nuts node
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

package events

import (
	"bytes"
	"context"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

func Test_pub_sub(t *testing.T) {
	eventManager := createManager(t)

	stream := eventManager.GetStream(TransactionsStream)

	conn, js, err := eventManager.Pool().Acquire(context.Background())
	require.NoError(t, err)
	defer conn.Close()
	var found []byte
	foundMutex := sync.Mutex{}
	err = stream.Subscribe(conn, "TEST", "TRANSACTIONS.tx", func(msg *nats.Msg) {
		foundMutex.Lock()
		defer foundMutex.Unlock()
		found = msg.Data
		err = msg.Ack()
	})

	require.NoError(t, err)

	// the ack comes from the Nats server so we can use Publish (instead of PublishAsync)
	_, err = js.PublishAsync("TRANSACTIONS.tx", []byte{1})
	require.NoError(t, err)

	test.WaitFor(t, func() (bool, error) {
		foundMutex.Lock()
		defer foundMutex.Unlock()
		return bytes.Equal(found, []byte{1}), nil
	}, 100*time.Millisecond, "timeout waiting for message")
	require.NoError(t, err)
}

func TestManager_Configure(t *testing.T) {
	t.Run("streams are not created at startup", func(t *testing.T) {
		eventManager := createManager(t)
		_, js, _ := eventManager.Pool().Acquire(context.Background())
		// 2 streams registered in own administration
		assert.Len(t, eventManager.streams, 2)

		_, err := js.StreamInfo(eventManager.streams[TransactionsStream].Config().Name)

		assert.Equal(t, nats.ErrStreamNotFound, err)
	})

	t.Run("stream is created after added subscription", func(t *testing.T) {
		eventManager := createManager(t)
		conn, js, _ := eventManager.Pool().Acquire(context.Background())
		defer conn.Close()
		s := eventManager.GetStream(TransactionsStream)
		s.Subscribe(conn, "test", "DATA.VerifiableCredential", func(msg *nats.Msg) {})

		info, err := js.StreamInfo(eventManager.streams[TransactionsStream].Config().Name)

		require.NoError(t, err)
		assert.Equal(t, TransactionsStream, info.Config.Name)
	})
}

func createManager(t *testing.T) *manager {
	testDir := io.TestDirectory(t)
	eventManager := NewManager().(*manager)
	eventManager.config.Nats.Port = test.FreeTCPPort()
	eventManager.config.Nats.Hostname = "localhost"
	cfg := *core.NewServerConfig()
	cfg.Datadir = testDir
	err := eventManager.Configure(cfg)
	assert.NoError(t, err)
	err = eventManager.Start()
	assert.NoError(t, err)
	t.Cleanup(func() {
		eventManager.Shutdown()
	})
	return eventManager
}
