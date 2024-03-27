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

package client

import (
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
)

// PresentationDefinition is a type alias for the PresentationDefinition from the nuts-node/vcr/pe package.
type PresentationDefinition = pe.PresentationDefinition

// PresentationSubmission is a type alias for the PresentationSubmission from the nuts-node/vcr/pe package.
type PresentationSubmission = pe.PresentationSubmission

// MultiPEX is a type alias for the MultiPEX from the nuts-node/policy package.
type MultiPEX = pe.MultiPEX

// AuthorizedRequest contains the information about the request
type AuthorizedRequest struct {
	// Audience contains the audience of the access token. This is the identifier (DID) of the authorizer and issuer of the access token.
	Audience string `json:"audience"`

	// ClientId contains the client ID of the client that requested the resource (DID).
	ClientId string `json:"client_id"`

	// PresentationSubmission contains a JSON object that maps requirements from the Presentation Definition to the verifiable presentations that were used to request an access token.
	// Specified at https://identity.foundation/presentation-exchange/spec/v2.0.0/
	// A JSON schema is available at https://identity.foundation/presentation-exchange/#json-schema
	PresentationSubmission pe.PresentationSubmission `json:"presentation_submission"`

	// RequestMethod contains the HTTP method of the resource request.
	RequestMethod string `json:"request_method"`

	// RequestUrl contains URL of the resource request.
	RequestUrl string `json:"request_url"`

	// Scope contains the scope used in the authorization request.
	Scope string `json:"scope"`

	// Vps contains the verifiable presentations that were used to request the access token.
	// The verifiable presentations could be in JWT format or in JSON format.
	Vps []vc.VerifiablePresentation `json:"vps"`
}
