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

package jsonld

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/signature"
	"github.com/piprate/json-gold/ld"
)

// JSONLD defines the interface of a JSON utilities engine. It allows sharing instances of utils over engines.
type JSONLD interface {
	// DocumentLoader returns the JSON-LD DocumentLoader
	DocumentLoader() ld.DocumentLoader
}

type contextManager struct {
	documentLoader ld.DocumentLoader
}

// NewManager returns a new ContextManager
func NewManager() ContextManager {
	return &contextManager{}
}

func (c contextManager) DocumentLoader() ld.DocumentLoader {
	return c.documentLoader
}

func (m *contextManager) Configure(config core.ServerConfig) (err error) {
	m.documentLoader, err = signature.NewContextLoader(!config.Strictmode)
	return
}
