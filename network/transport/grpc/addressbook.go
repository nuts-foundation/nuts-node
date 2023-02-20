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
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/network/transport"
)

// AddressBook provides an API for protocols to query the ConnectionManager's known addresses.
type AddressBook interface {
	// Update the address for the peer's existing getContact, or create one if it does not exist.
	// If the address is empty, the contact is removed.
	// bootstrap nodes contain an address with an empty DID.
	Update(peer transport.Peer) error
	// Get the getContact if it exists, or returns false if it does not.
	Get(peer transport.Peer) (*contact, bool)
	// All returns a copy of the contacts of connectors.
	All() []*contact
}

func newAddressBook(connectionStore stoabs.KVStore, backoffCreator func() Backoff) *addressBook {
	return &addressBook{
		contacts:       make([]*contact, 0),
		backoffStore:   connectionStore,
		backoffCreator: backoffCreator,
	}
}

type addressBook struct {
	mux            sync.RWMutex // TODO: check race conditions
	contacts       []*contact
	backoffStore   stoabs.KVStore
	backoffCreator func() Backoff
}

func (a *addressBook) len() int {
	return len(a.contacts)
}

func (a *addressBook) Get(peer transport.Peer) (*contact, bool) {
	a.mux.RLock()
	defer a.mux.RUnlock()
	return a.get(peer)
}

func (a *addressBook) get(peer transport.Peer) (*contact, bool) {
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

func (a *addressBook) Update(peer transport.Peer) error {
	a.mux.Lock()
	defer a.mux.Unlock()

	// TODO: add validation peer. -> ? valid address & did, no peerID?

	current, exists := a.get(peer)
	// update existing address
	if exists {
		if peer.Address == current.peer.Address {
			// nothing to update
		} else if peer.Address == "" {
			// delete NutsComm -> delete dialer
			a.remove(current)
		} else {
			// update DID's address and reset backoff
			current.peer.Address = peer.Address
			current.backoff.Reset(0)
		}
		return nil
	}

	// TODO: Should this register contact per protocol??
	// add new address
	backoff := a.backoffCreator()
	if !peer.NodeDID.Empty() {
		// only persist non-bootstrap.
		// store the backoff under the DID since an address could be used by multiple DIDs.
		backoff = NewPersistedBackoff(a.backoffStore, fmt.Sprintf("did:%s:%s", peer.NodeDID.Method, peer.NodeDID.ID), backoff)
	}
	a.contacts = append(a.contacts, newContact(peer, backoff))
	return nil
}

func (a *addressBook) All() []*contact {
	a.mux.RLock()
	defer a.mux.RUnlock()

	result := make([]*contact, len(a.contacts))
	copy(result, a.contacts)
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

func (a *addressBook) remove(target *contact) {
	var j int
	for _, curr := range a.contacts {
		if curr != target {
			a.contacts[j] = curr
			j++
		}
	}
	a.contacts = a.contacts[:j]
}

func (a *addressBook) Diagnostics() []core.DiagnosticResult {
	var connectors ConnectorsStats
	for _, curr := range a.All() {
		connectors = append(connectors, curr.stats())
	}
	return []core.DiagnosticResult{
		connectors,
	}
}

// newContact connects to a remote server in a loop, taking into account a given backoff.
// When the connection succeeds it calls the given callback. The caller is responsible to reset the backoff after optional application-level checks succeed (e.g. authentication).
func newContact(peer transport.Peer, backoff Backoff) *contact {
	return &contact{
		peer:        peer,
		backoff:     backoff,
		lastAttempt: &atomic.Value{},
	}
}

type contact struct {
	peer        transport.Peer
	dialing     atomic.Bool
	backoff     Backoff
	attempts    atomic.Uint32
	lastAttempt *atomic.Value
}

func (c *contact) stats() transport.ContactStats {
	lastAttempt, _ := c.lastAttempt.Load().(time.Time)
	return transport.ContactStats{
		Address:     c.peer.Address,
		DID:         c.peer.NodeDID.String(),
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
		return c.dialing.CompareAndSwap(false, true)
	}
}
