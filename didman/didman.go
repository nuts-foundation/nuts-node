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
	store       types.Store
	vdr         types.VDR
}

func NewDidmanInstance(docResolver types.DocResolver, store types.Store, vdr types.VDR) Didman {
	return &didman{
		docResolver: docResolver,
		store:       store,
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

func (d *didman) DeleteService(serviceId ssi.URI) error {
	id, err := did.ParseDID(serviceId.String())
	if err != nil {
		return err
	}
	id.Fragment = ""

	doc, meta, err := d.docResolver.Resolve(*id, nil)
	if err != nil {
		return err
	}

	// check for existing use
	if err = d.store.Iterate(func(doc did.Document, metadata types.DocumentMetadata) error {
		if referencesService(doc, serviceId) {
			return ErrServiceInUse
		}
		return nil
	}); err != nil {
		return err
	}

	// remove service
	j := 0
	for _, s := range doc.Service {
		if s.ID != serviceId {
			doc.Service[j] = s
			j++
		}
	}
	doc.Service = doc.Service[:j]

	return d.vdr.Update(*id, meta.Hash, *doc, nil)
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

type compoundService map[string]string

func referencesService(doc did.Document, serviceId ssi.URI) bool {
	id := serviceId.String()
	for _, s := range doc.Service {
		cs := compoundService{}
		// ignore structures that can not be parsed to compound endpoints
		if err := s.UnmarshalServiceEndpoint(&cs); err == nil {
			for _, v := range cs {
				if v == id {
					return true
				}
			}
		}
	}
	return false
}
