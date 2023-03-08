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

func TestAddressBook_get(t *testing.T) {
	address := "same-address"
	peerDID := did.MustParseDID("did:nuts:123")

	anonymous := transport.Peer{Address: address}
	named := transport.Peer{Address: address, NodeDID: peerDID}
	anonymousContact := newContact(anonymous, nil)
	namedContact := newContact(named, nil)

	ab := newAddressBook(nil, nil)
	// add contacts, first element is empty to prevent accidental matching
	ab.contacts = append(ab.contacts, newContact(transport.Peer{}, nil))
	ab.contacts = append(ab.contacts, anonymousContact)
	ab.contacts = append(ab.contacts, namedContact)

	t.Run("anonymous contact", func(t *testing.T) {
		cont, exists := ab.get(anonymous)
		require.True(t, exists)
		assert.Equal(t, cont, anonymousContact)
	})

	t.Run("named contact", func(t *testing.T) {
		cont, exists := ab.get(named)
		require.True(t, exists)
		assert.Equal(t, cont, namedContact)
	})

	t.Run("not found", func(t *testing.T) {
		cont, exists := ab.get(transport.Peer{Address: "who's this?"})
		assert.False(t, exists)
		assert.Nil(t, cont)
	})
}

func TestAddressBook_update(t *testing.T) {
	address := "address"
	otherAddress := "that-address"

	t.Run("bootstrap", func(t *testing.T) {
		store := storage.CreateTestBBoltStore(t, t.TempDir()+"/test.db")
		ab := newAddressBook(store, newTestBackoff)

		// add 1
		conta, update := ab.update(transport.Peer{Address: address})
		assert.True(t, update)
		assert.Len(t, ab.contacts, 1)

		// add 2
		contb, update := ab.update(transport.Peer{Address: otherAddress})
		assert.True(t, update)
		assert.NotSame(t, conta, contb)
		assert.Len(t, ab.contacts, 2)

		// duplicate of 1
		contc, update := ab.update(transport.Peer{Address: address})
		assert.False(t, update)
		assert.Same(t, conta, contc)
		assert.Len(t, ab.contacts, 2)
	})
	t.Run("named", func(t *testing.T) {
		store := storage.CreateTestBBoltStore(t, t.TempDir()+"/test.db")
		ab := newAddressBook(store, newTestBackoff)
		did1 := did.MustParseDID("did:nuts:123")
		did2 := did.MustParseDID("did:nuts:abc")

		// add 1
		conta, update := ab.update(transport.Peer{Address: address, NodeDID: did1})
		assert.True(t, update)
		assert.Len(t, ab.contacts, 1)

		// add 2
		contb, update := ab.update(transport.Peer{Address: address, NodeDID: did2})
		assert.True(t, update)
		assert.NotSame(t, conta, contb)
		assert.Len(t, ab.contacts, 2)

		// duplicate of 2
		contc, update := ab.update(transport.Peer{Address: address, NodeDID: did2})
		assert.False(t, update)
		assert.Same(t, contb, contc)
		assert.Len(t, ab.contacts, 2)

		// update 1
		contd, update := ab.update(transport.Peer{Address: otherAddress, NodeDID: did1})
		assert.True(t, update)
		assert.Same(t, conta, contd)
		assert.Len(t, ab.contacts, 2)
	})
}

func TestAddressBook_all(t *testing.T) {
	c1 := newContact(transport.Peer{}, nil)
	c2 := newContact(transport.Peer{}, nil)
	c3 := newContact(transport.Peer{}, nil)
	ab := &addressBook{contacts: []*contact{c1, c2, c3}}

	all := ab.all()

	assert.Len(t, all, 3)
	assert.NotSame(t, all, ab.contacts) // new slice
}

func TestAddressBook_remove(t *testing.T) {
	store := storage.CreateTestBBoltStore(t, t.TempDir()+"/test.db")
	ab := newAddressBook(store, newTestBackoff)
	ab.update(transport.Peer{Address: "address"})
	ab.update(transport.Peer{Address: "other-address"})
	ab.update(transport.Peer{Address: "address", NodeDID: did.MustParseDID("did:nuts:abc")})
	ab.update(transport.Peer{Address: "address", NodeDID: did.MustParseDID("did:nuts:123")})
	assert.Len(t, ab.contacts, 4)

	ab.remove(did.DID{}) // removes all bootstrap
	assert.Len(t, ab.contacts, 2)
	ab.remove(did.MustParseDID("did:nuts:abc")) // removes only this did
	assert.Len(t, ab.contacts, 1)
}

func TestAddressBook_Diagnostics(t *testing.T) {
	c1 := newContact(transport.Peer{Address: "contact1"}, nil)
	c2 := newContact(transport.Peer{Address: "contact2"}, nil)
	c3 := newContact(transport.Peer{Address: "contact3"}, nil)
	ab := &addressBook{
		contacts: []*contact{c1, c2, c3},
	}

	diagnostics, ok := ab.Diagnostics()[0].Result().(ContactsStats)

	require.True(t, ok)
	require.Len(t, diagnostics, 3)
	assert.Equal(t, "contact1", diagnostics[0].Address)
	assert.Equal(t, "contact2", diagnostics[1].Address)
	assert.Equal(t, "contact3", diagnostics[2].Address)
}

func TestAddressBook_limit(t *testing.T) {
	store := storage.CreateTestBBoltStore(t, t.TempDir()+"/test.db")
	ab := newAddressBook(store, newTestBackoff)
	peer := transport.Peer{Address: "test"}
	ab.update(peer)

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
