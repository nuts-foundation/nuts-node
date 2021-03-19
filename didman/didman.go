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
	"github.com/nuts-foundation/nuts-node/didman/templates"
)

const (
	moduleName = "DID Manager"
)

// DIDManager provides high-level management operations for administrating one's DIDs.
type DIDManager struct {
	bolts map[string]templates.ServiceTemplateApplier
}

// NewDIDManager creates a new DID Manager.
func NewDIDManager() *DIDManager {
	return &DIDManager{
		bolts: map[string]templates.ServiceTemplateApplier{},
	}
}

func (dm *DIDManager) Name() string {
	return moduleName
}

// EnableBolt enables a ServiceTemplate for the given care provider with the given properties.
func (dm DIDManager) EnableBolt(careProvider did.DID, boltKey string, properties map[string]string) error {
	bolt, exists := dm.bolts[boltKey]
	if !exists {
		return fmt.Errorf("unknown ServiceTemplate: %s", boltKey)
	}
	return bolt.Apply(careProvider, properties)
}

// DisableBolt disables a ServiceTemplate for the given care provider.
func (dm DIDManager) DisableBolt(careProvider did.DID, boltKey string) error {
	bolt, exists := dm.bolts[boltKey]
	if !exists {
		return fmt.Errorf("unknown ServiceTemplate: %s", boltKey)
	}
	return bolt.Unapply(careProvider)
}