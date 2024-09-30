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
 *
 */

package v1

import (
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/discovery"
)

// VerifiablePresentation is a type alias for the VerifiablePresentation from the go-did library.
type VerifiablePresentation = vc.VerifiablePresentation

// ServiceDefinition is a type alias
type ServiceDefinition = discovery.ServiceDefinition

// VerifiableCredential is a type alias for the VerifiableCredential from the go-did library.
type VerifiableCredential = vc.VerifiableCredential

// GetServiceActivation200JSONResponseStatus is a type alias for string, generated from an enum.
type GetServiceActivation200JSONResponseStatus string

const (
	// ServiceStatusActive is the status for an active service.
	ServiceStatusActive = "active"
	// ServiceStatusError is the status for an inactive service.
	ServiceStatusError = "error"
)
