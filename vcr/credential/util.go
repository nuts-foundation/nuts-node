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
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
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

// PresenterIsCredentialSubject checks if the presenter of the VP is the same as the subject of the VCs being presented.
// If the presentation signer or credential subject can't be resolved, it returns an error.
// If parsing succeeds and the signer DID is the same as the credential subject DID, it returns the DID.
func PresenterIsCredentialSubject(vp vc.VerifiablePresentation) (*did.DID, error) {
	signerDID, err := PresentationSigner(vp)
	if err != nil {
		return nil, err
	}
	credentialSubjectID, err := ResolveSubjectDID(vp.VerifiableCredential...)
	if err != nil {
		return nil, err
	}
	if !credentialSubjectID.Equals(*signerDID) {
		return nil, nil
	}
	return signerDID, nil
}

// PresentationIssuanceDate returns the date at which the presentation was issued.
// For JSON-LD, it looks at the first LinkedData proof's 'created' property.
// For JWT, it looks at the 'nbf' claim, or if that is not present, the 'iat' claim.
// If it can't resolve the date, it returns nil.
func PresentationIssuanceDate(presentation vc.VerifiablePresentation) *time.Time {
	var result time.Time
	switch presentation.Format() {
	case vc.JWTPresentationProofFormat:
		jwt := presentation.JWT()
		if result = jwt.NotBefore(); result.IsZero() {
			result = jwt.IssuedAt()
		}
	case vc.JSONLDPresentationProofFormat:
		ldProof, err := ParseLDProof(presentation)
		if err != nil {
			return nil
		}
		result = ldProof.Created
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
		ldProof, err := ParseLDProof(presentation)
		if err != nil || ldProof.Expires == nil {
			return nil
		}
		result = *ldProof.Expires
	}
	if result.IsZero() {
		return nil
	}
	return &result
}

// AutoCorrectSelfAttestedCredential sets the required fields for a self-attested credential.
// These are provided through the API, and for convenience we set the required fields, if not already set.
// It only does this for unsigned credentials.
func AutoCorrectSelfAttestedCredential(credential vc.VerifiableCredential, requester did.DID) vc.VerifiableCredential {
	if len(credential.Proof) > 0 {
		return credential
	}
	if credential.ID == nil {
		credential.ID, _ = ssi.ParseURI(uuid.NewString())
	}
	if credential.Issuer.String() == "" {
		credential.Issuer = requester.URI()
	}
	if credential.IssuanceDate.IsZero() {
		credential.IssuanceDate = time.Now().Truncate(time.Second)
	}
	var credentialSubject []map[string]interface{}
	_ = credential.UnmarshalCredentialSubject(&credentialSubject)
	if len(credentialSubject) == 1 {
		if _, ok := credentialSubject[0]["id"]; !ok {
			credentialSubject[0]["id"] = requester.String()
			credential.CredentialSubject[0] = credentialSubject[0]
		}
	}
	return credential
}
