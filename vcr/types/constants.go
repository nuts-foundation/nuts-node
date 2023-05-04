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

package types

import (
	"errors"
)

// ErrNotFound is returned when a credential can not be found based on its ID.
var ErrNotFound = errors.New("credential not found")

// ErrMultipleFound is returned when multiple credentials or revocations are found for the same ID.
var ErrMultipleFound = errors.New("multiple found")

// ErrRevoked is returned when a credential has been revoked and the required action requires it to not be revoked.
var ErrRevoked = errors.New("credential is revoked")

// ErrUntrusted is returned when a credential is resolved or searched but its issuer is not trusted.
var ErrUntrusted = errors.New("credential issuer is untrusted")

// ErrInvalidCredential is returned when validation failed
var ErrInvalidCredential = errors.New("invalid credential")

// ErrCredentialNotValidAtTime is returned when the credential is not valid at the given time.
var ErrCredentialNotValidAtTime = errors.New("credential not valid at given time")

// ErrPresentationNotValidAtTime is returned when the presentation is not valid at the given time.
var ErrPresentationNotValidAtTime = errors.New("presentation not valid at given time")

// VcDocumentType holds the content type used in network documents which contain Verifiable Credentials
const VcDocumentType = "application/vc+json"

// RevocationLDDocumentType holds the content type used in network documents which contain Revocation messages of credentials in JSON-LD form
const RevocationLDDocumentType = "application/ld+json;type=revocation"
