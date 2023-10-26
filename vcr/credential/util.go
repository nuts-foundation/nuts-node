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

package credential

import (
	"errors"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
)

// ResolveSubjectDID resolves the subject DID from the given credentials.
// It returns an error if:
// - the credentials do not have the same subject DID.
// - the credentials do not have a subject DID.
func ResolveSubjectDID(credentials ...vc.VerifiableCredential) (*did.DID, error) {
	var subjectID did.DID
	for _, credential := range credentials {
		sid, err := credential.SubjectDID()
		if err != nil {
			return nil, err
		}
		if !subjectID.Empty() && !subjectID.Equals(*sid) {
			return nil, errors.New("not all VCs have the same credentialSubject.id")
		}
		subjectID = *sid
	}
	return &subjectID, nil
}

// VerifyPresenterIsHolder checks if the holder of the VP is the same as the subject of the VCs being presented.
// It returns an error when:
// - the VP does not have a holder.
// - the VP holder is not the same as the subject of the VCs.
// If the check succeeds, it returns nil.
func VerifyPresenterIsHolder(vp vc.VerifiablePresentation) error {
	// Check VP signer == VC subject (presenter is holder of VCs)
	if vp.Holder == nil {
		// Is this even possible?
		return errors.New("no holder")
	}
	credentialSubjectID, err := ResolveSubjectDID(vp.VerifiableCredential...)
	if err != nil {
		return err
	}
	if *vp.Holder != credentialSubjectID.URI() {
		return errors.New("not all VC credentialSubject.id match VP holder")
	}
	return nil
}
