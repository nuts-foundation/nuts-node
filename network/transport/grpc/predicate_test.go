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

package grpc

import (
	"testing"

	"github.com/nuts-foundation/go-did/did"

	"github.com/stretchr/testify/assert"
)

func TestByPeerID(t *testing.T) {
	assert.True(t, ByPeerID("123").Match(&StubConnection{PeerID: "123"}))
	assert.False(t, ByPeerID("123").Match(&StubConnection{PeerID: "anything-else"}))
}

func TestByNodeDID(t *testing.T) {
	did1, _ := did.ParseDID("did:nuts:123")
	did2, _ := did.ParseDID("did:nuts:456")

	assert.True(t, ByNodeDID(*did1).Match(&StubConnection{NodeDID: *did1}))
	assert.False(t, ByNodeDID(*did2).Match(&StubConnection{NodeDID: *did1}))
}

func TestByConnected(t *testing.T) {
	assert.True(t, ByConnected().Match(&StubConnection{Open: true}))
	assert.False(t, ByConnected().Match(&StubConnection{}))
}

func TestByNotConnected(t *testing.T) {
	assert.True(t, ByNotConnected().Match(&StubConnection{}))
	assert.False(t, ByNotConnected().Match(&StubConnection{Open: true}))
}

func TestByAuthenticated(t *testing.T) {
	assert.True(t, ByAuthenticated().Match(&StubConnection{Authenticated: true}))
	assert.False(t, ByAuthenticated().Match(&StubConnection{}))
}

func TestByAddress(t *testing.T) {
	assert.True(t, ByAddress("address").Match(&StubConnection{Address: "address"}))
	assert.False(t, ByAddress("address").Match(&StubConnection{}))
}
