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
	"sync"
	"sync/atomic"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

// AddressBook provides an API for protocols to query the ConnectionManager's known addresses.
type AddressBook interface {
	// update the address for the peer's existing contact, or create an entry if it does not exist.
	// it returns the contact, and true if the AddressBook was updated (contact was created or updated).
	// bootstrap nodes contain an address with an empty DID.
	update(peer transport.Peer) (*contact, bool)
	// get the contact if it exists. Returns nil and false if it does not.
	get(peer transport.Peer) (*contact, bool)
	// all returns a copy of the slice of contacts.
	all() []transport.Contact
	// remove contact for the given DID. if peerDID.Empty() this removes all bootstrap contacts.
	remove(peerDID did.DID)
}

func newAddressBook(connectionStore stoabs.KVStore, backoffCreator func() Backoff) *addressBook {
	return &addressBook{
		contacts:       make([]*contact, 0),
		backoffStore:   connectionStore,
		backoffCreator: backoffCreator,
	}
}

type addressBook struct {
	mux            sync.RWMutex
	contacts       []*contact
	backoffStore   stoabs.KVStore
	backoffCreator func() Backoff
}

func (a *addressBook) get(peer transport.Peer) (*contact, bool) {
	a.mux.RLock()
	defer a.mux.RUnlock()
	return a.getWithoutLock(peer)
}

// getWithoutLock is get for internal calls
func (a *addressBook) getWithoutLock(peer transport.Peer) (*contact, bool) {
	if !peer.NodeDID.Empty() { // find on DID
		for _, o := range a.contacts {
			if peer.NodeDID.Equals(o.peer.NodeDID) {
				return o, true
			}
		}
	} else { // find on address -> bootstrap only
		for _, o := range a.contacts {
			if peer.Address == o.peer.Address {
				return o, true
			}
		}
	}
	return nil, false
}

func (a *addressBook) update(peer transport.Peer) (*contact, bool) {
	a.mux.Lock()
	defer a.mux.Unlock()

	// update existing address
	current, exists := a.getWithoutLock(peer)
	if exists {
		if peer.Address == current.peer.Address {
			// no change
			return current, false
		}
		current.peer.Address = peer.Address
		return current, true
	}

	// add new address
	backoff := a.backoffCreator()
	// only persist non-bootstrap contacts
	// bootstrap addresses are configured by the node owner and should always be called at startup
	if !peer.NodeDID.Empty() {
		// store the backoff under the DID since an address could be used by multiple DIDs.
		backoff = NewPersistedBackoff(a.backoffStore, peer.NodeDID.String(), backoff)
	}
	// wrap it in a lock since it's used from multiple go routines
	backoff = NewSyncedBackoff(backoff)
	newC := newContact(peer, NewSyncedBackoff(backoff))
	a.contacts = append(a.contacts, newC)
	return newC, true
}

func (a *addressBook) all() []transport.Contact {
	a.mux.RLock()
	defer a.mux.RUnlock()

	// copy contact to a new slice to prevent race conditions on a.contacts.
	// this does not prevent race conditions on the contacts
	result := make([]transport.Contact, 0, len(a.contacts))
	for _, c := range a.contacts {
		result = append(result, c.stats())
	}
	return result
}

// limit returns a number of contacts that match all predicates
func (a *addressBook) limit(number int, predicates ...predicate) []*contact {
	a.mux.RLock()
	defer a.mux.RUnlock()

	result := make([]*contact, 0)

outer:
	for _, c := range a.contacts {
		if len(result) == number {
			break
		}
		for _, p := range predicates {
			if !p(c) {
				continue outer
			}
		}
		result = append(result, c)
	}

	return result
}

func (a *addressBook) remove(peerDID did.DID) {
	a.mux.Lock()
	defer a.mux.Unlock()
	var j int
	for _, curr := range a.contacts {
		if !curr.peer.NodeDID.Equals(peerDID) {
			a.contacts[j] = curr
			j++
		}
	}
	a.contacts = a.contacts[:j]
}

// newContact connects to a remote server in a loop, taking into account a given backoff.
// When the connection succeeds it calls the given callback. The caller is responsible to reset the backoff after optional application-level checks succeed (e.g. authentication).
func newContact(peer transport.Peer, backoff Backoff) *contact {
	return &contact{
		peer:    peer,
		backoff: backoff,
	}
}

type contact struct {
	peer        transport.Peer
	calling     atomic.Bool
	backoff     Backoff
	attempts    atomic.Uint32
	lastAttempt atomic.Pointer[time.Time]
}

func (c *contact) stats() transport.Contact {
	lastAttempt := c.lastAttempt.Load()
	return transport.Contact{
		Address:     c.peer.Address,
		DID:         c.peer.NodeDID,
		Attempts:    c.attempts.Load(),
		LastAttempt: lastAttempt,
	}
}

// predicate returns true if its implementation matches a contact.
type predicate func(c *contact) bool

func isNotActivePredicate(s *grpcConnectionManager) predicate {
	return func(c *contact) bool {
		return !s.hasActiveConnection(c.peer)
	}
}

func backoffExpiredPredicate() predicate {
	return func(c *contact) bool {
		return c.backoff.Expired()
	}
}

func notDialingPredicate() predicate {
	return func(c *contact) bool {
		return !c.calling.Load()
	}
}
