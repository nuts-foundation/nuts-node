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
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/usecase/log"
	"strings"
	"sync"
)

var _ ListWriter = &maintainer{}
var ErrListNotFound = errors.New("list not found")
var ErrPresentationAlreadyExists = errors.New("presentation already exists")

// listEntry is a singly-linked list entry, used to store the Verifiable Presentations in order they were added to the list.
type listEntry struct {
	// presentation is the Verifiable Presentation
	presentation vc.VerifiablePresentation
	// next is the next entry in the list
	next      *listEntry
	timestamp Timestamp
}

type list struct {
	definition Definition
	name       string
	// head is the first entry in the list
	head *listEntry
	// tail is the last entry in the list
	tail *listEntry
	lock sync.RWMutex
}

func (l *list) exists(presentation vc.VerifiablePresentation) bool {
	return false // TODO
}

func (l *list) add(presentation vc.VerifiablePresentation) error {
	if l.exists(presentation) {
		// Should be handled by caller, but ust to be sure since adding the same one twice corrupts the state.
		return ErrPresentationAlreadyExists
	}
	l.lock.Lock()
	defer l.lock.Unlock()
	newEntry := &listEntry{
		presentation: presentation,
		timestamp:    1,
	}
	if l.tail != nil {
		newEntry.timestamp = l.tail.timestamp + 1
		l.tail.next = newEntry
	}
	l.tail = newEntry
	if l.head == nil {
		l.head = newEntry
	}
	return nil
}

func (l *list) get(startAfter Timestamp) ([]vc.VerifiablePresentation, Timestamp) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	result := make([]vc.VerifiablePresentation, 0)
	timestamp := startAfter
	if l.head == nil {
		// empty list
		return result, timestamp
	}

	current := l.head
	for {
		if current == nil {
			// End of list
			break
		}
		if current.timestamp > startAfter {
			// Client wants presentations after the given lamport clock
			result = append(result, current.presentation)
			timestamp = current.timestamp
		}
		current = current.next
	}
	return result, timestamp
}

func createList(definition Definition) (*list, error) {
	// name is derived from endpoint: it's the last path part of the definition endpoint
	// It is used to route HTTP GET requests to the correct list.
	pathParts := strings.Split(definition.Endpoint, "/")
	name := pathParts[len(pathParts)-1]
	if name == "" {
		return nil, fmt.Errorf("can't derive list name from definition endpoint: %s", definition.Endpoint)
	}
	return &list{
		definition: definition,
		name:       name,
		lock:       sync.RWMutex{},
	}, nil
}

type maintainer struct {
	fileName string
	lists    sync.Map
}

func newMaintainer(fileName string, definitions []Definition) (*maintainer, error) {
	result := &maintainer{
		lists: sync.Map{},
	}
	for _, definition := range definitions {
		currentList, err := createList(definition)
		if err != nil {
			return nil, err
		}
		// make sure we don't end up with 2 lists with the same name, would overwrite each other
		if _, exists := result.lists.Load(currentList.name); exists {
			return nil, fmt.Errorf("duplicate list name: %s", currentList.name)
		}
		result.lists.Store(currentList.name, currentList)
		log.Logger().Infof("Node is use case maintainer for list: %s", currentList.definition.ID)
	}
	result.fileName = fileName
	return result, nil
}

func (m *maintainer) Add(listName string, presentation vc.VerifiablePresentation) error {
	if presentation.Format() != vc.JWTPresentationProofFormat {
		return errors.New("only JWT presentations are supported")
	}
	l, exists := m.lists.Load(listName)
	if !exists {
		return ErrListNotFound
	}
	targetList := l.(*list)
	// TODO: Verify VP
	if targetList.exists(presentation) {
		return ErrPresentationAlreadyExists
	}
	return targetList.add(presentation)
}

func (m *maintainer) Get(listName string, startAt Timestamp) ([]vc.VerifiablePresentation, *Timestamp, error) {
	l, exists := m.lists.Load(listName)
	if !exists {
		return nil, nil, ErrListNotFound
	}
	result, timestamp := l.(*list).get(startAt)
	return result, &timestamp, nil
}
