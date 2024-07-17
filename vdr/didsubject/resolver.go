/*
 * Copyright (C) 2024 Nuts community
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

package didsubject

import (
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
	"time"
)

type Resolver struct {
	DB *gorm.DB
}

var _ resolver.DIDResolver = (*Resolver)(nil)

func (r Resolver) Resolve(id did.DID, metadata *resolver.ResolveMetadata) (*did.Document, *resolver.DocumentMetadata, error) {
	didDocumentMananager := NewDIDDocumentManager(r.DB)
	var notAfter *time.Time
	if metadata != nil && metadata.ResolveTime != nil {
		notAfter = metadata.ResolveTime
	}

	doc, err := didDocumentMananager.Latest(id, notAfter)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil, resolver.ErrNotFound
		}
		return nil, nil, err
	}
	updated := time.Unix(doc.UpdatedAt, 0)
	resolverMetadata := resolver.DocumentMetadata{
		Created: time.Unix(doc.CreatedAt, 0),
		Updated: &updated,
	}
	document, err := doc.ToDIDDocument()
	if resolver.IsDeactivated(document) {
		if metadata == nil || !metadata.AllowDeactivated {
			return nil, nil, resolver.ErrDeactivated
		}
		resolverMetadata.Deactivated = true
	}
	return &document, &resolverMetadata, err
}
