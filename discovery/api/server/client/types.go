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

package client

import "github.com/nuts-foundation/go-did/vc"

// PresentationsResponse is the response for the GetPresentations endpoint.
type PresentationsResponse struct {
	// Entries contains mappings from timestamp (as string) to a VerifiablePresentation.
	Entries map[string]vc.VerifiablePresentation `json:"entries"`
	// Timestamp is the timestamp of the latest entry. It's not a unix timestamp but a Lamport Clock.
	Timestamp int `json:"timestamp"`
}
