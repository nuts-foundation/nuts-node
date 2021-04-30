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
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/url"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
	"github.com/shengdoushi/base58"
)

const ModuleName = "Didman"

// ErrDuplicateService is returned when a DID Document already contains a service for the given type
var ErrDuplicateService = errors.New("service type already defined")
// ErrServiceInUse is returned when a service is deleted but in use by other services
var ErrServiceInUse = errors.New("service is referenced by 1 or more services")
// ErrServiceNotFound is returned when the service is not found on a DID
var ErrServiceNotFound = errors.New("service not found in DID Document")

type didman struct {
	docResolver types.DocResolver
	vdr         types.Store
}

func NewDidmanInstance(docResolver types.DocResolver, vdr types.Store) Didman {
	return &didman{
		docResolver: docResolver,
		vdr:         vdr,
	}
}

func (d *didman) Name() string {
	return ModuleName
}

func (d *didman) AddEndpoint(id did.DID, serviceType string, u url.URL) error {
	doc, meta, err := d.docResolver.Resolve(id, nil)
	if err != nil {
		return err
	}

	// check for duplicate service type
	for _, s := range doc.Service {
		if s.Type == serviceType {
			return ErrDuplicateService
		}
	}

	// construct service with correct ID
	service := constructService(id, serviceType, u)
	doc.Service = append(doc.Service, service)

	return d.vdr.Update(id, meta.Hash, *doc, nil)
}

func (d *didman) DeleteService(id ssi.URI) error {

	doc, meta, err := d.docResolver.Resolve(id, nil)
	if err != nil {
		return err
	}

	// check for existing use
	err := d.vdr.Iterate(func(doc did.Document, metadata types.DocumentMetadata) error {

		return nil
	})
	if err != nil {
		return err
	}

	// remove service
	for _, s := range doc.Service {
		if s.Type == serviceType {
			return ErrDuplicateService
		}
	}

	return d.vdr.Update(id, meta.Hash, *doc, nil)
}

func constructService(id did.DID, serviceType string, u url.URL) did.Service {
	service := did.Service{
		Type:            serviceType,
		ServiceEndpoint: u.String(),
	}

	service.ID = ssi.URI{}

	bytes, _ := json.Marshal(service)
	shaBytes := sha256.Sum256(bytes)
	d := id.URI()
	d.Fragment = base58.Encode(shaBytes[:], base58.BitcoinAlphabet)
	service.ID = d

	return service
}
