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
	"crypto/md5"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/usecase/log"
	"strings"
	"sync"
	"time"
)

var _ ListWriter = &maintainer{}
var ErrListNotFound = errors.New("list not found")
var ErrPresentationAlreadyExists = errors.New("presentation already exists")

// listValue is a doubly-linked list entry value, used to store the Verifiable Presentations in order they were added to the list.
type listValue struct {
	// presentation is the Verifiable Presentation
	presentation vc.VerifiablePresentation
	timestamp    Timestamp
}

type list struct {
	definition Definition
	name       string
	items      doublyLinkedList[*listValue]
	// index maps a presentation hash to the entry in the list
	index map[[16]byte]*item[*listValue]
	lock  sync.RWMutex
}

func (l *list) exists(presentation vc.VerifiablePresentation) bool {
	l.lock.RLock()
	defer l.lock.RUnlock()
	_, exists := l.index[presentationHash(presentation)]
	return exists
}

func (l *list) add(presentation vc.VerifiablePresentation) error {
	if l.exists(presentation) {
		// Should be handled by caller, but ust to be sure since adding the same one twice corrupts the state.
		return ErrPresentationAlreadyExists
	}
	l.lock.Lock()
	defer l.lock.Unlock()
	isEmpty := l.items.empty()
	newEntry := &listValue{
		presentation: presentation,
		timestamp:    1,
	}
	addedItem := l.items.append(newEntry)
	if !isEmpty {
		// list wasn't empty, so we need to increment the timestamp
		newEntry.timestamp = addedItem.prev.value.timestamp + 1
	}
	l.index[presentationHash(presentation)] = addedItem
	return nil
}

func (l *list) get(startAfter Timestamp) ([]vc.VerifiablePresentation, Timestamp) {
	l.lock.RLock()
	defer l.lock.RUnlock()

	result := make([]vc.VerifiablePresentation, 0)
	timestamp := startAfter
	if l.items.empty() {
		return result, timestamp
	}

	current := l.items.head
	for {
		if current == nil {
			// End of list
			break
		}
		if current.value.timestamp > startAfter {
			// Client wants presentations after the given lamport clock
			result = append(result, current.value.presentation)
			timestamp = current.value.timestamp
		}
		current = current.next
	}
	return result, timestamp
}

func (l *list) prune(currentTime time.Time) {
	l.lock.Lock()
	defer l.lock.Unlock()
	current := l.items.head
	for {
		if current == nil {
			// End of list
			break
		}
		token := current.value.presentation.JWT()
		// TODO: check revocation status
		if !token.Expiration().Before(currentTime) {
			// expired, remove
			l.items.remove(current)
			delete(l.index, presentationHash(current.value.presentation))
		}
		current = current.next
	}
}

func presentationHash(presentation vc.VerifiablePresentation) [16]byte {
	return md5.Sum([]byte(presentation.Raw()))
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
		index:      map[[16]byte]*item[*listValue]{},
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

func (m *maintainer) pruneLists(currentTime time.Time) {
	m.lists.Range(func(_, value any) bool {
		currentList := value.(*list)
		currentList.prune(currentTime)
		return true
	})
}
