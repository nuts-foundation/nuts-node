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
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"time"
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

// VerifyPresenterIsCredentialSubject checks if the presenter of the VP is the same as the subject of the VCs being presented.
// It returns an error when:
// - the VP proof is unsupported.
// - the VP signer is not the same as the subject of the VCs.
// If the check succeeds, it returns nil.
func VerifyPresenterIsCredentialSubject(vp vc.VerifiablePresentation) error {
	signerDID, err := PresentationSigner(vp)
	if err != nil {
		return err
	}
	credentialSubjectID, err := ResolveSubjectDID(vp.VerifiableCredential...)
	if err != nil {
		return err
	}
	if !credentialSubjectID.Equals(*signerDID) {
		return errors.New("not all VC credentialSubject.id match VP signer")
	}
	return nil
}

// PresentationIssuanceDate returns the date at which the presentation was issued.
// For JSON-LD, it looks at the first LinkedData proof's 'created' property.
// For JWT, it looks at the 'iat' claim, or if that is not present, the 'nbf' claim.
// If it can't resolve the date, it returns nil.
func PresentationIssuanceDate(presentation vc.VerifiablePresentation) *time.Time {
	var result time.Time
	switch presentation.Format() {
	case vc.JWTPresentationProofFormat:
		jwt := presentation.JWT()
		if result = jwt.IssuedAt(); result.IsZero() {
			result = jwt.NotBefore()
		}
	case vc.JSONLDPresentationProofFormat:
		var proofs []proof.LDProof
		if err := presentation.UnmarshalProofValue(&proofs); err != nil {
			return nil
		}
		if len(proofs) == 0 {
			return nil
		}
		result = proofs[0].Created
	}
	if result.IsZero() {
		return nil
	}
	return &result
}

// PresentationExpirationDate returns the date at which the presentation was issued.
// For JSON-LD, it looks at the first LinkedData proof's 'expires' property.
// For JWT, it looks at the 'exp' claim.
// If it can't resolve the date, it returns nil.
func PresentationExpirationDate(presentation vc.VerifiablePresentation) *time.Time {
	var result time.Time
	switch presentation.Format() {
	case vc.JWTPresentationProofFormat:
		result = presentation.JWT().Expiration()
	case vc.JSONLDPresentationProofFormat:
		var proofs []proof.LDProof
		if err := presentation.UnmarshalProofValue(&proofs); err != nil {
			return nil
		}
		if len(proofs) == 0 {
			return nil
		}
		if proofs[0].Expires != nil {
			result = *proofs[0].Expires
		}
	}
	if result.IsZero() {
		return nil
	}
	return &result
}
