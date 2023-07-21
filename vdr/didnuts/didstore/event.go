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

package didstore

import (
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// event contains the transaction reference and ordering of all DID document updates
type event struct {
	// SigningTime is the transaction creation time, used for sorting
	SigningTime time.Time `json:"created"`
	// Clock contains the LC header from the transaction
	Clock uint32 `json:"lc"`
	// Previous contains the TX.Prevs of the original transaction. Used for conflict detection
	Previous []hash.SHA256Hash `json:"txprev"`
	// Ref contains the TX.Ref of the original transaction. Used for ordering
	Ref hash.SHA256Hash `json:"txref"`
	// PayloadHash contains the reference to a document on the document shelf. Equals transaction payload hash
	PayloadHash hash.SHA256Hash `json:"docref"`
	// MetaRef contains a reference to a metadata record on the documentMetadata shelf. Formatted as "DID + version"
	MetaRef string `json:"metaref"`
	// document contains the created Document. This needs to be added to a new event since we cannot write and read within the same TX.
	document *did.Document
}

func (e event) before(other event) bool {
	if e.Clock < other.Clock {
		return true
	}
	if e.Clock > other.Clock {
		return false
	}

	if e.SigningTime.Before(other.SigningTime) {
		return true
	}
	if other.SigningTime.Before(e.SigningTime) {
		return false
	}

	return e.Ref.Compare(other.Ref) < 0
}

// equal returns true when event.Ref are equal.
func (e event) equal(other event) bool {
	return e.Ref.Equals(other.Ref)
}

// eventList is an in-memory representation of an Events shelf entry
type eventList struct {
	Events []event `json:"events"`
}

// insert the event at the correct location, it returns the location at which the event was added
// only works when previous list was ordered
func (el *eventList) insert(newEvent event) int {
	// 1% case
	if len(el.Events) == 0 {
		el.Events = append(el.Events, newEvent)
		return 0
	}

	newList := make([]event, len(el.Events)+1)
	copy(newList, el.Events)
	newList[len(el.Events)] = newEvent

	index := len(el.Events)
	// start at the end since this is the most common
	for i := len(el.Events) - 1; i >= 0; i-- {
		if newEvent.before(newList[i]) {
			newList[i+1], newList[i] = newList[i], newEvent
			index = i
		} else {
			break
		}
	}
	el.Events = newList
	return index
}

func (el *eventList) contains(newEvent event) bool {
	for _, e := range el.Events {
		if e.equal(newEvent) {
			return true
		}
	}
	return false
}
