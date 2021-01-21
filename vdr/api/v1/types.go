/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package v1

import (
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// DIDResolutionResult is a convenience type for marshalling/unmarshalling
type DIDResolutionResult struct {
	Document         *did.Document           `json: "document,omitempty"`
	DocumentMetadata *types.DocumentMetadata `json: "documentMetadata,omitempty"`
}

// DIDUpdateRequest is a convenience type for updating a DID
type DIDUpdateRequest struct {
	Document         did.Document           `json: "document"`
	CurrentHash      string                 `json: "currentHash"`
}
