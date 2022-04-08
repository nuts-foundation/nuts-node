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
	"fmt"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld/assets"
	"github.com/piprate/json-gold/ld"
)

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

func (m contextManager) Transformer() Transformer {
	return transformer{documentLoader: m.documentLoader}
}

func (m *contextManager) Configure(config core.ServerConfig) error {
	var nextLoader ld.DocumentLoader
	if !config.Strictmode {
		nextLoader = ld.NewDefaultDocumentLoader(nil)
	}
	loader := ld.NewCachingDocumentLoader(NewEmbeddedFSDocumentLoader(assets.Assets, nextLoader))
	if err := loader.PreloadWithMapping(map[string]string{
		"https://nuts.nl/credentials/v1":                                     "assets/contexts/nuts.ldjson",
		"https://www.w3.org/2018/credentials/v1":                             "assets/contexts/w3c-credentials-v1.ldjson",
		"https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json": "assets/contexts/lds-jws2020-v1.ldjson",
		"https://schema.org":                                                 "assets/contexts/schema-org-v13.ldjson",
	}); err != nil {
		return fmt.Errorf("unable to preload nuts ld-context: %w", err)
	}
	m.documentLoader = loader

	return nil
}
