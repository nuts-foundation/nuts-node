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
	"net/url"

	"github.com/nuts-foundation/go-did/did"
)

// Didman groups all high-level methods for manipulating DID Documents
type Didman interface {
	// AddEndpoint adds a service to a DID Document. The serviceEndpoint is set to the given URL.
	AddEndpoint(id did.DID, serviceType string, u url.URL) error
}
