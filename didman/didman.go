/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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

package didman

import (
	"fmt"
	"github.com/nuts-foundation/go-did"
)

const (
	moduleName = "DID Manager"
)

// DIDManager provides high-level management operations for administrating one's DIDs.
type DIDManager struct {
	bolts map[string]Bolt
}

// NewDIDManager creates a new DID Manager.
func NewDIDManager() *DIDManager {
	return &DIDManager{
		bolts: map[string]Bolt{},
	}
}

func (dm *DIDManager) Name() string {
	return moduleName
}

// EnableBolt enables a Bolt for the given care provider with the given properties.
func (dm DIDManager) EnableBolt(careProvider did.DID, boltKey string, properties map[string]string) error {
	bolt, exists := dm.bolts[boltKey]
	if !exists {
		return fmt.Errorf("unknown Bolt: %s", boltKey)
	}
	return bolt.Enable(careProvider, properties)
}

// DisableBolt disables a Bolt for the given care provider.
func (dm DIDManager) DisableBolt(careProvider did.DID, boltKey string) error {
	bolt, exists := dm.bolts[boltKey]
	if !exists {
		return fmt.Errorf("unknown Bolt: %s", boltKey)
	}
	return bolt.Disable(careProvider)
}