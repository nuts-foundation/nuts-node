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

package vcr

import (
	"errors"
	"fmt"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/types"
)

// conclave, noun, a private meeting.
// conclave will handle the reliable delivery of non-public credentials to the holder.
type conclave struct{
	docResolver types.DocResolver
}

const nutsCommEndpointType = "NutsComm"

var errNotAddressable = errors.New("DID Document of holder does not have a NutsComm serviceEndpoint")

// Send will send the credential to the DID in the credential.credentialSubject.id field.
// Returns errNotAddressable if the corresponding DID document does not have a NutsComm serviceEndpoint.
func (c conclave) Send(verifiableCredential vc.VerifiableCredential) error {
	credentialSubject := credential.BaseCredentialSubject{}
	if err := verifiableCredential.UnmarshalCredentialSubject(&credentialSubject); err != nil {
		return fmt.Errorf("failed to extract credentialSubject from verifiable credential: %w", err)
	}

	subject, err := did.ParseDID(credentialSubject.ID)
	if err != nil {
		return fmt.Errorf("credentialSubject.id is not a valid DID: %w", err)
	}

	document, _, err := c.docResolver.Resolve(*subject, nil)
	if err != nil {
		return fmt.Errorf("failed to resolve DID document: %w", err)
	}

	var service *did.Service
	for _, curr := range document.Service {
		if curr.Type == nutsCommEndpointType {
			service = &curr
			break
		}
	}
	if service == nil {
		return errNotAddressable
	}

	// TODO publish correct event

	return nil
}

// TODO add start, shutdown functionality to start stop the retry queues
