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

package grpc

import (
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_connectionList_closeAll(t *testing.T) {
	cn := connectionList{}
	connA := cn.getOrRegister(transport.Peer{ID: "a"}).closer()
	connB := cn.getOrRegister(transport.Peer{ID: "b"}).closer()
	cn.closeAll()

	assert.Len(t, connA, 1)
	assert.Len(t, connB, 1)
}

func Test_connectionList_getOrRegister(t *testing.T) {
	t.Run("second call with same peer ID should return same connection", func(t *testing.T) {
		cn := connectionList{}
		connA := cn.getOrRegister(transport.Peer{ID: "a"})
		connASecondCall := cn.getOrRegister(transport.Peer{ID: "a"})
		assert.Equal(t, connA, connASecondCall)
	})
	t.Run("call with other peer ID should return same connection", func(t *testing.T) {
		cn := connectionList{}
		connA := cn.getOrRegister(transport.Peer{ID: "a"})
		connB := cn.getOrRegister(transport.Peer{ID: "b"})
		assert.NotEqual(t, connA, connB)
	})
}

func Test_managedConnection_close(t *testing.T) {
	t.Run("no closers", func(t *testing.T) {
		conn := managedConnection{}
		conn.close()
		assert.Empty(t, conn.closers)
	})
	t.Run("multiple closers", func(t *testing.T) {
		conn := managedConnection{}
		c1 := conn.closer()
		c2 := conn.closer()
		conn.close()
		assert.Len(t, c1, 1)
		assert.Len(t, c2, 1)
	})
	t.Run("multiple calls does not block", func(t *testing.T) {
		conn := managedConnection{}
		c := conn.closer()
		conn.close()
		conn.close()
		conn.close()
		conn.close()
		assert.Len(t, c, 1)
	})
}
