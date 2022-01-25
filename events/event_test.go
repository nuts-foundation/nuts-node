/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
	"fmt"
	"github.com/nuts-foundation/nuts-node/test"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/stretchr/testify/assert"
)

func TestNewManager(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		eventManager := NewManager()

		assert.NotNil(t, eventManager)
	})
}

func TestManager_Start(t *testing.T) {
	eventManager := NewManager().(*manager)
	eventManager.config.Port = test.FreeTCPPort()
	err := eventManager.Start()
	assert.NoError(t, err)
	err = eventManager.Configure(core.ServerConfig{})
	assert.NoError(t, err)

	defer eventManager.Shutdown()

	t.Run("Starts a Nats server", func(t *testing.T) {
		conn, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", eventManager.config.Port))

		if !assert.NoError(t, err) {
			return
		}

		if assert.NotNil(t, conn) {
			conn.Close()
		}
	})
}
