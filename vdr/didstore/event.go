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
 */

package didstore

import (
	"sort"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// event contains the transaction reference and ordering of all DID document updates
type event struct {
	// Created is the transaction creation time, used for sorting
	Created time.Time `json:"created"`
	// Clock contains the LC header from the transaction
	Clock uint32 `json:"lc"`
	// TXRef contains the TX.Ref of the original transaction. Used for ordering
	TXRef hash.SHA256Hash `json:"txref"`
	// DocRef contains the reference to a document on the document shelf. Equals transaction payload hash
	DocRef hash.SHA256Hash `json:"docref"`
	// MetaRef contains a reference to a metadata record on the documentMetadata shelf. Formatted as "DID + version"
	MetaRef string `json:"metaref"`
	// document contains the created Document. This needs to be added to a new event since we cannot write and read within the same TX.
	document *did.Document
	// metadata contains the created Metadata. This needs to be added to a new event since we cannot write and read within the same TX.
	metadata *documentMetadata
}

// Len returns the length of the Events slice. Required for sorting.
func (el *eventList) Len() int {
	return len(el.Events)
}

// Less is part of the methods required for sorting
func (el *eventList) Less(i, j int) bool {
	left := el.Events[i]
	right := el.Events[j]

	if left.Clock < right.Clock {
		return true
	}
	if left.Clock > right.Clock {
		return false
	}

	return left.Created.Before(right.Created)
}

// Swap is part of the methods required for sorting
func (el *eventList) Swap(i, j int) {
	el.Events[i], el.Events[j] = el.Events[j], el.Events[i]
}

// eventList is an in-memory representation of an Events shelf entry
type eventList struct {
	Events []event `json:"events"`
}

func (el *eventList) copy() eventList {
	cpy := eventList{Events: make([]event, len(el.Events))}
	copy(cpy.Events, el.Events)

	return cpy
}

// insert the event at the correct location
func (el *eventList) insert(e event) {
	// 1% case
	if len(el.Events) == 0 {
		el.Events = append(el.Events, e)
		return
	}

	// 98.99% case
	last := el.Events[len(el.Events)-1]
	el.Events = append(el.Events, e)
	if last.Clock < e.Clock {
		return
	}

	// 0.01% case
	sort.Stable(el)
}

// diff returns the latest matching event and a sublist of events that need to be applied to the latest.
// Given transaction orderings A: 1->2->4 and B: 1->2->3.
// A.diff(B) results in 2, [3,4] where 2 is the last common TX (base version of DID document)
// and 3,4 are updates that have to be applied to the base version as updates.
func (el *eventList) diff(updated eventList) (*event, []event) {
	if updated.Len() == 0 {
		return nil, []event{}
	}

	firstDifferenceIndex := 0
	var lastCommonEvent *event
	for i := range el.Events {
		if !el.Events[i].TXRef.Equals(updated.Events[i].TXRef) {
			break
		}
		eCopy := el.Events[i]
		lastCommonEvent = &eCopy
		firstDifferenceIndex++
	}

	diffList := eventList{Events: append(el.Events[firstDifferenceIndex:], updated.Events[firstDifferenceIndex:]...)}
	sort.Stable(&diffList)

	return lastCommonEvent, diffList.Events
}
