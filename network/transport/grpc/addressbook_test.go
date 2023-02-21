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

package grpc

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/network/transport"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAddressBook_Get(t *testing.T) {
	address := "same-address"
	peerDID := did.MustParseDID("did:nuts:123")

	anonymous := transport.Peer{Address: address}
	named := transport.Peer{Address: address, NodeDID: peerDID}
	anonymousContact := newContact(anonymous, nil)
	namedContact := newContact(named, nil)

	ab := newAddressBook(nil, nil, nil)
	// add contacts, first element is empty to prevent accidental matching
	ab.contacts = append(ab.contacts, newContact(transport.Peer{}, nil))
	ab.contacts = append(ab.contacts, anonymousContact)
	ab.contacts = append(ab.contacts, namedContact)

	t.Run("anonymous contact", func(t *testing.T) {
		cont, exists := ab.Get(anonymous)
		require.True(t, exists)
		assert.Equal(t, cont, anonymousContact)
	})

	t.Run("named contact", func(t *testing.T) {
		cont, exists := ab.Get(named)
		require.True(t, exists)
		assert.Equal(t, cont, namedContact)
	})

	t.Run("not found", func(t *testing.T) {
		cont, exists := ab.Get(transport.Peer{Address: "who's this?"})
		assert.False(t, exists)
		assert.Nil(t, cont)
	})
}

func TestAddressBook_Update(t *testing.T) {
	store := storage.CreateTestBBoltStore(t, t.TempDir()+"/test.db")
	ab := newAddressBook(store, newTestBackoff, nil)
	assert.Len(t, ab.contacts, 0) // must be empty at start

	address1 := "this-address"
	address2 := "that-address"
	did1 := did.MustParseDID("did:nuts:123")
	did2 := did.MustParseDID("did:nuts:abc")
	peer1 := transport.Peer{Address: address1, NodeDID: did1}
	peer2 := transport.Peer{Address: address1, NodeDID: did2}
	peer1Update := transport.Peer{Address: address2, NodeDID: did1}
	peer1Remove := transport.Peer{NodeDID: did1}

	// add peers
	assert.NoError(t, ab.Update(peer1))
	assert.Len(t, ab.contacts, 1)
	assert.NoError(t, ab.Update(peer2))
	require.Len(t, ab.contacts, 2)
	assert.Equal(t, peer1, ab.contacts[0].peer)
	assert.Equal(t, peer2, ab.contacts[1].peer)

	// update contains no change
	assert.NoError(t, ab.Update(peer1))
	require.Len(t, ab.contacts, 2)
	assert.Equal(t, peer1, ab.contacts[0].peer)

	// update address
	assert.NoError(t, ab.Update(peer1Update))
	require.Len(t, ab.contacts, 2)
	assert.Equal(t, peer1Update, ab.contacts[0].peer)

	// remove contact
	assert.NoError(t, ab.Update(peer1Remove))
	require.Len(t, ab.contacts, 1)
	assert.Equal(t, peer2, ab.contacts[0].peer)

	// invalid peer
	assert.EqualError(t, ab.Update(transport.Peer{}), "invalid peer")
}

func TestAddressBook_All(t *testing.T) {
	c1 := newContact(transport.Peer{}, nil)
	c2 := newContact(transport.Peer{}, nil)
	c3 := newContact(transport.Peer{}, nil)
	ab := &addressBook{contacts: []*contact{c1, c2, c3}}

	all := ab.All()

	assert.Len(t, all, 3)
	assert.NotSame(t, all, ab.contacts) // new slice
}

func TestAddressBook_Diagnostics(t *testing.T) {
	c1 := newContact(transport.Peer{Address: "contact1"}, nil)
	c2 := newContact(transport.Peer{Address: "contact2"}, nil)
	c3 := newContact(transport.Peer{Address: "contact3"}, nil)
	ab := &addressBook{
		contacts: []*contact{c1, c2, c3},
		hasNoConnection: func(c *contact) bool { // contact c2 has an active connection
			return c.peer.Address != "contact2"
		},
	}

	diagnostics, ok := ab.Diagnostics()[0].Result().(ContactsStats)

	require.True(t, ok)
	require.Len(t, diagnostics, 2)
	assert.Contains(t, "contact1", diagnostics[0].Address)
	assert.Contains(t, "contact3", diagnostics[1].Address)
}

func TestAddressBook_limit(t *testing.T) {
	store := storage.CreateTestBBoltStore(t, t.TempDir()+"/test.db")
	ab := newAddressBook(store, newTestBackoff, nil)
	peer := transport.Peer{Address: "test"}
	ab.Update(peer)

	t.Run("no match", func(t *testing.T) {
		cs := ab.limit(1, func(c *contact) bool {
			return false
		})

		assert.Len(t, cs, 0)
	})

	t.Run("match", func(t *testing.T) {
		cs := ab.limit(1, func(c *contact) bool {
			return true
		})

		assert.Len(t, cs, 1)
	})

	t.Run("limit reached", func(t *testing.T) {
		cs := ab.limit(0, func(c *contact) bool {
			return true
		})

		assert.Len(t, cs, 0)
	})
}
