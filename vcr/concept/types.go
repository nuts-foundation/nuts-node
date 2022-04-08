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

package concept

import (
	"errors"
)

// ErrUnknownConcept is returned when an unknown concept is requested
var ErrUnknownConcept = errors.New("unknown concept")

// ErrNoType is returned when a template is loaded which doesn't have a type
var ErrNoType = errors.New("no template type found")

// ErrNoValue is returned when a requested path doesn't have a value.
var ErrNoValue = errors.New("no value for given path")

// IDField defines the concept/VC JSON joinPath to a VC ID
const IDField = "id"

// IssuerField defines the concept/VC JSON joinPath to a VC issuer
const IssuerField = "issuer"
