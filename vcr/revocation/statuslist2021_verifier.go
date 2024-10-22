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

package revocation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"gorm.io/gorm/clause"
)

// maxAgeExternal is the maximum age of external StatusList2021Credentials. If older than this we try to refresh.
const maxAgeExternal = 15 * time.Minute

// Verify StatusList2021 returns a types.ErrRevoked when the credentialStatus contains a 'StatusList2021Entry' that can be resolved and lists the credential as 'revoked'
// Other credentialStatus type/statusPurpose are ignored. Verification may fail with other non-standardized errors.
func (cs *StatusList2021) Verify(credentialToVerify vc.VerifiableCredential) error {
	if credentialToVerify.CredentialStatus == nil {
		return nil
	}
	statuses, err := credentialToVerify.CredentialStatuses()
	if err != nil {
		// cannot happen. already validated in defaultCredentialValidator{}
		return err
	}

	// only check credentialStatus of type StatusList2021Entry with statusPurpose == revocation other types/purposes are ignored
	// returns errors if processing fails -> TODO: hard/soft fail option?
	// returns types.ErrRevoked if correct type, purpose, and listed.
	for _, status := range statuses {
		if status.Type != StatusList2021EntryType {
			// ignore other credentialStatus.type
			log.Logger().
				WithField("credentialStatus.type", status.Type).
				WithField(core.LogFieldCredentialID, credentialToVerify.ID).
				WithField(core.LogFieldCredentialType, credentialToVerify.Type).
				Info("Ignoring credentialStatus with unknown type")
			continue
		}
		var slEntry StatusList2021Entry // CredentialStatus of the credentialToVerify
		if err = json.Unmarshal(status.Raw(), &slEntry); err != nil {
			// cannot happen. already validated in credential.defaultCredentialValidator{}
			return err
		}
		if slEntry.StatusPurpose != "revocation" {
			// ignore non-revocation purposes
			log.Logger().
				WithField("credentialStatus.statusPurpose", slEntry.StatusPurpose).
				WithField(core.LogFieldCredentialID, credentialToVerify.ID).
				WithField(core.LogFieldCredentialType, credentialToVerify.Type).
				Info("Ignoring credentialStatus with purpose other than 'revocation'")
			continue
		}

		// get StatusList2021Credential with same purpose
		sList, err := cs.statusList(slEntry.StatusListCredential)
		if err != nil {
			return fmt.Errorf("status list: %w", err)
		}
		if sList.StatusPurpose != slEntry.StatusPurpose {
			return fmt.Errorf("StatusList2021Credential.credentialSubject.statusPuspose='%s' does not match vc.credentialStatus.statusPurpose='%s'", sList.StatusPurpose, slEntry.StatusPurpose)
		}

		// check if listed
		index, err := strconv.Atoi(slEntry.StatusListIndex)
		if err != nil {
			// can't happen, checked during validation of credentialToVerify
			return err
		}
		revoked, err := sList.Bitstring.bit(index)
		if err != nil {
			return err
		}
		if revoked {
			return errRevoked
		}
	}
	return nil
}

func (cs *StatusList2021) statusList(statusListCredential string) (*credentialRecord, error) {
	cr, err := cs.loadCredential(statusListCredential)
	if err != nil {
		// assume any error means we don't have the credential, so try fetching remote
		return cs.update(statusListCredential)
	}

	// managed StatusList2021Credentials are always up-to-date, does not matter if it is expired
	if cs.isManaged(statusListCredential) {
		return cr, nil
	}

	// TODO: renewal criteria need to be reconsidered if we add other purposes. A 'suspension' may have been canceled
	// renew expired certificates
	if (cr.Expires != nil && time.Unix(*cr.Expires, 0).Before(time.Now())) || // expired
		time.Unix(cr.CreatedAt, 0).Add(maxAgeExternal).Before(time.Now()) { // older than 15 min
		crUpdated, err := cs.update(statusListCredential)
		if err == nil {
			return crUpdated, nil
		}
		// use known StatusList2021Credential if we can't fetch a new one, even if it is older/expired
		if cr.Expires != nil && time.Unix(*cr.Expires, 0).Before(time.Now()) {
			// log warning if using expired StatusList2021Credential
			log.Logger().WithError(err).WithField(core.LogFieldCredentialSubject, statusListCredential).
				Info("Validating credentialStatus using expired StatusList2021Credential")
		}
	}

	// return credentialRecord, which could be outdated but is the best information available.
	return cr, nil
}

// update StatusList2021Credential in db by downloading remote StatusList2021Credential. Storage failures are logged, but do not return an error.
func (cs *StatusList2021) update(statusListCredential string) (*credentialRecord, error) {
	// TODO: use caching headers for unchanged status list StatusList2021Credentials
	// download and verify
	cred, err := cs.download(statusListCredential)
	if err != nil {
		return nil, err
	}
	credSubject, err := cs.verify(*cred)
	if err != nil {
		return nil, err
	}
	if statusListCredential != credSubject.ID {
		return nil, fmt.Errorf("status list: wrong credential: expected '%s', got '%s'", statusListCredential, credSubject.ID)
	}

	// make bit string
	expanded, err := expand(credSubject.EncodedList)
	if err != nil {
		// cant happen, already checked in verify
		return nil, err
	}

	var expiresPtr *int64
	if cred.ExpirationDate != nil && !cred.ExpirationDate.IsZero() {
		expires := cred.ExpirationDate.Unix()
		expiresPtr = &expires
	}

	sl := credentialRecord{
		SubjectID:     statusListCredential,
		StatusPurpose: credSubject.StatusPurpose,
		Bitstring:     expanded,
		//Created:              time.Now(), // set by gorm when stored
		Expires: expiresPtr,
		Raw:     cred.Raw(),
	}

	// store StatusList2021Credential
	err = cs.db.Clauses(clause.OnConflict{UpdateAll: true}).Create(&sl).Error
	if err != nil {
		// log if storage fails, but still return the credential
		log.Logger().WithError(err).Info("Failed to store StatusList2021Credential")
	}
	return &sl, nil
}

// download the StatusList2021Credential found at statusList2021Entry.statusListCredential
func (cs *StatusList2021) download(statusListCredential string) (*vc.VerifiableCredential, error) {
	var cred vc.VerifiableCredential // VC containing CredentialStatus of the credentialToVerify
	req, err := http.NewRequest(http.MethodGet, statusListCredential, nil)
	if err != nil {
		return nil, err
	}
	res, err := cs.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = res.Body.Close(); err != nil {
			// log, don't fail
			log.Logger().WithError(err).WithField("StatusList2021Credential url", statusListCredential).
				Debug("Failed to close response body")
		}
	}()
	body, err := io.ReadAll(res.Body)
	if res.StatusCode > 299 || err != nil {
		return nil, errors.Join(fmt.Errorf("fetching StatusList2021Credential from '%s' failed", statusListCredential), err)
	}
	if err = json.Unmarshal(body, &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

// verify returns the StatusList2021Credential's StatusList2021CredentialSubject,
// or an error if the signature is invalid or the StatusList2021Credential does not meet the spec.
func (cs *StatusList2021) verify(cred vc.VerifiableCredential) (*StatusList2021CredentialSubject, error) {
	// confirm contents match spec
	credSubj, err := cs.validate(cred)
	if err != nil {
		return nil, err
	}

	if _, err = expand(credSubj.EncodedList); err != nil {
		return nil, fmt.Errorf("credentialSubject.encodedList is invalid: %w", err)
	}

	// Verify signature
	if err = cs.VerifySignature(cred, nil); err != nil {
		return nil, err
	}

	return credSubj, nil
}

// validate returns an error when the StatusList2021Credential doesn't meet the spec.
func (cs *StatusList2021) validate(cred vc.VerifiableCredential) (*StatusList2021CredentialSubject, error) {
	// TODO: replace with json schema validator?
	{ // Credential checks
		// context
		// all fields in the StatusList2021Credential must be defined by the contexts
		// TODO: this makes testing a lot harder, and the errors aren't useful. Maybe check for presence of contexts again.
		//credJSON, err := json.Marshal(cred)
		//if err != nil {
		//	return nil, err
		//}
		//if err = jsonld.AllFieldsDefined(cs.jsonldManager.DocumentLoader(), credJSON); err != nil {
		//	return nil, err
		//}
		if !cred.ContainsContext(vc.VCContextV1URI()) {
			return nil, errors.New("default context is required")
		}
		if !cred.ContainsContext(StatusList2021ContextURI) {
			return nil, errors.New("context 'https://w3id.org/vc/status-list/2021/v1' is required")
		}

		// type
		if !cred.IsType(vc.VerifiableCredentialTypeV1URI()) { // same type for vc v2 spec
			return nil, errors.New("type 'VerifiableCredential' is required")
		}
		if !cred.IsType(statusList2021CredentialTypeURI) {
			return nil, fmt.Errorf("type '%s' is required", statusList2021CredentialTypeURI)
		}
		if len(cred.Type) > 2 {
			return nil, errors.New("StatusList2021Credential contains other types")
		}

		// id
		if cred.ID == nil {
			return nil, errors.New("'ID' is required")
		}

		if cred.IssuanceDate.IsZero() {
			return nil, errors.New("issuanceDate is required")
		}

		if cred.Format() == vc.JSONLDCredentialProofFormat && cred.Proof == nil {
			return nil, errors.New("'proof' is required for JSON-LD credentials")
		}

		// prevent an infinite loops in credentialStatus resolution; note that this is not prohibited by the spec
		if cred.CredentialStatus != nil {
			return nil, errors.New("StatusList2021Credential with a CredentialStatus is not supported")
		}
	}

	var credentialSubject StatusList2021CredentialSubject
	{ // credentialSubject checks
		var target []StatusList2021CredentialSubject
		err := cred.UnmarshalCredentialSubject(&target)
		if err != nil {
			return nil, err
		}
		// The spec is not clear if there could be multiple CredentialSubjects. This could allow 'revocation' and 'suspension' to be defined in a single credential.
		// However, it is not defined how to select the correct list (StatusPurpose) when validating credentials that are using this StatusList2021Credential.
		if len(target) != 1 {
			return nil, errors.New("single credentialSubject expected")
		}
		credentialSubject = target[0]

		if credentialSubject.Type != StatusList2021CredentialSubjectType {
			return nil, fmt.Errorf("credentialSubject.type '%s' is required", StatusList2021CredentialSubjectType)
		}
		if credentialSubject.StatusPurpose == "" {
			return nil, errors.New("credentialSubject.statusPurpose is required")
		}
		if credentialSubject.EncodedList == "" {
			return nil, errors.New("credentialSubject.encodedList is required")
		}
	}

	return &credentialSubject, nil
}
