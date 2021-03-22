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
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/didman/templates"
	vdr "github.com/nuts-foundation/nuts-node/vdr/types"
	"strings"
)

const (
	moduleName = "DID Manager"
)

// DIDManager provides high-level management operations for administrating one's DIDs.
type DIDManager struct {
	templates map[string]templates.Definition
	vdr       vdr.VDR
}

func (dm *DIDManager) Configure(_ core.ServerConfig) error {
	tpls, err := templates.LoadEmbeddedDefinitions()
	if err != nil {
		return err
	}
	for _, template := range tpls {
		dm.templates[template.Name()] = template
	}
	return nil
}

// NewDIDManager creates a new DID Manager.
func NewDIDManager(vdr vdr.VDR) *DIDManager {
	return &DIDManager{
		vdr:       vdr,
		templates: map[string]templates.Definition{},
	}
}

func (dm *DIDManager) Name() string {
	return moduleName
}

// ApplyServiceTemplate applies a ServiceTemplate.
func (dm DIDManager) ApplyServiceTemplate(controller, subject did.DID, templateName string, properties map[string]string) error {
	template, err := dm.getTemplate(templateName)
	if err != nil {
		return err
	}
	return templates.ServiceTemplateApplier{VDR: dm.vdr}.Apply(controller, subject, template, properties)
}

// UnapplyServiceTemplate disables the services created by applying a ServiceTemplate.
func (dm DIDManager) UnapplyServiceTemplate(controller, subject did.DID, templateName string) error {
	_, err := dm.getTemplate(templateName)
	if err != nil {
		return err
	}
	panic("implement me")
}

func (dm DIDManager) getTemplateNames() []string {
	result := make([]string, 0)
	for name, _ := range dm.templates {
		result = append(result, name)
	}
	return result
}

func (dm DIDManager) getTemplate(templateName string) (templates.Definition, error) {
	template, exists := dm.templates[templateName]
	if !exists {
		return nil, fmt.Errorf("unknown service template: %s (valid are: %s)", templateName, strings.Join(dm.getTemplateNames(), ", "))
	}
	return template, nil
}
