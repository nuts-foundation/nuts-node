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

package network

import (
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/storage"
)

// WithPersistency creates the SubscriberOption that creates the NotifierOption for persistency with the correct DAG KVStore
func (n *Network) WithPersistency() SubscriberOption {
	return func() dag.NotifierOption {
		kvStore, err := n.storeProvider.GetKVStore("data", storage.PersistentStorageClass)
		if err != nil {
			// should have errored earlier
			panic(err)
		}
		return dag.WithPersistency(kvStore)
	}
}

// WithSelectionFilter creates a SubscriberOption that creates a dag.NotifierOption with the given filter
func WithSelectionFilter(filter dag.NotificationFilter) SubscriberOption {
	return func() dag.NotifierOption {
		return dag.WithSelectionFilter(filter)
	}
}
