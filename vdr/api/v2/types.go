/*
 * Copyright (C) 2023 Nuts community
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
 */

package v2

import (
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
)

// DIDDocument is an alias
type DIDDocument = did.Document

// DIDDocumentMetadata is an alias
type DIDDocumentMetadata = resolver.DocumentMetadata

// VerificationMethod is an alias
type VerificationMethod = did.VerificationMethod

// Service is an alias
type Service = did.Service

// ServiceEndpoint is an alias. It exists since having an OpenAPI schema of {} causes the code generator to use interface{} as the type,
// on which you can't define functions, which the strict server interface does with the VisitXYZ response functions.
// By wrapping an interface{} type we can still respond with any type.
// But, the MarshalJSON function is needed on the actual response types, since they are type definitions (and otherwise the JSON encoder won't use them).
type ServiceEndpoint struct {
	Value interface{}
}

func (s ResolveServiceEndpointByType200JSONResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Value)
}
func (s ResolveServiceEndpointByID200JSONResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Value)
}
