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

package usecase

import (
	"github.com/nuts-foundation/go-did/vc"
)

// Timestamp is value that references a point in the list.
// It is used by clients to request new entries since their last query.
// It's implemented as lamport timestamp (https://en.wikipedia.org/wiki/Lamport_timestamp);
// it is incremented when a new entry is added to the list.
// Pass 0 to start at the beginning of the list.
type Timestamp uint64

type List struct {
	State   string                      `json:"state"`
	Entries []vc.VerifiablePresentation `json:"entries"`
}

// ListWriter is responsible for handling new list entries.
type ListWriter interface {
	Add(listName string, presentation vc.VerifiablePresentation) error
}

type ListReader interface {
	Get(listName string, startAt *Timestamp) ([]vc.VerifiablePresentation, *Timestamp, error)
}

type Reader interface {
	Find(listName string, query map[string]interface{}) ([]vc.VerifiablePresentation, error)
}
