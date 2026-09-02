/*
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

package network

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	defs := DefaultConfig()
	assert.Equal(t, ":5555", defs.GrpcAddr)
	assert.Equal(t, time.Hour, defs.MaxBackoff, "a peer that comes back after a long outage should be retried within the hour")
	assert.Equal(t, 2*time.Minute, defs.IdleTimeout)
}

func TestConfig_IsProtocolEnabled(t *testing.T) {
	t.Run("not set", func(t *testing.T) {
		defs := DefaultConfig()
		assert.True(t, defs.IsProtocolEnabled(1))
		assert.True(t, defs.IsProtocolEnabled(2))
		assert.True(t, defs.IsProtocolEnabled(3))
	})
	t.Run("protocols set", func(t *testing.T) {
		defs := DefaultConfig()
		defs.Protocols = []int{2}
		assert.False(t, defs.IsProtocolEnabled(1))
		assert.True(t, defs.IsProtocolEnabled(2))
	})
}
