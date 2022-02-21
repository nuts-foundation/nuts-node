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
 *
 */

package gossip

import (
	"container/list"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
)

// uniqueList represents an ordered list where each element is unique
// it is not thread safe and only works for hash.SHA256Hash structs
type uniqueList struct {
	// list that holds the list items
	list *list.List
	// set contains the items from the list but as indexed set
	set map[string]*list.Element
}

// newUniqueList returns a new uniqueList with initialized list and set
func newUniqueList() *uniqueList {
	return &uniqueList{
		list: list.New(),
		set:  map[string]*list.Element{},
	}
}

// Len returns the size of the list
func (u *uniqueList) Len() int {
	return len(u.set)
}

// Add a value, it'll only be added if all conditions return true.
// A value is only added if new.
// condition checking is done within transactional context.
func (u *uniqueList) Add(ref hash.SHA256Hash, conditions ...ConditionFunc) {
	for _, c := range conditions {
		if !c(u) {
			return
		}
	}
	if _, ok := u.set[ref.String()]; !ok {
		u.set[ref.String()] = u.list.PushBack(ref)
	}
}

// Remove a value, it'll only be removed if all conditions return true
// condition checking is done within transactional context.
func (u *uniqueList) Remove(ref hash.SHA256Hash, conditions ...ConditionFunc) {
	for _, c := range conditions {
		if !c(u) {
			return
		}
	}

	if element, ok := u.set[ref.String()]; ok {
		u.list.Remove(element)
		delete(u.set, ref.String())
	}
}

// RemoveFront the first value from the list.
// condition checking is done within transactional context.
func (u *uniqueList) RemoveFront(conditions ...ConditionFunc) {
	for _, c := range conditions {
		if !c(u) {
			return
		}
	}

	if element := u.list.Front(); element != nil {
		data := element.Value.(hash.SHA256Hash)
		delete(u.set, data.String())
		u.list.Remove(element)
	}
}

// Contains returns true if the given key exists in the set.
func (u *uniqueList) Contains(value hash.SHA256Hash) bool {
	_, ok := u.set[value.String()]
	return ok
}

// Values returns all values in the ordered list
func (u *uniqueList) Values() []hash.SHA256Hash {
	refs := make([]hash.SHA256Hash, u.list.Len())

	i := 0
	for element := u.list.Front(); element != nil; element = element.Next() {
		refs[i] = element.Value.(hash.SHA256Hash)
		i++
	}
	return refs
}

// ConditionFunc for allowing an ADd/Remove operation to be conditional
type ConditionFunc func(u *uniqueList) bool
