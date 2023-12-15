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

package verifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/credential/statuslist2021"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/types"
)

type credentialStatus struct {
	client          core.HTTPRequestDoer
	verifySignature func(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error // TODO: replace with new SignatureVerifier interface?
}

// statusList is an immutable struct containing all information needed to verify a credentialStatus
type statusList struct {
	// credential is the complete StatusList2021Credential this statusList is about
	credential *vc.VerifiableCredential
	// statusListCredential is the URL (from StatusList2021Entry.statusListCredential) that credential was downloaded from
	// it should match with credential.ID
	statusListCredential string
	// statusPurpose is the purpose listed in the StatusList2021Credential.credentialSubject
	statusPurpose string
	// expanded StatusList2021 Bitstring
	expanded statuslist2021.Bitstring
	// lastUpdated is the timestamp this statusList was generated
	lastUpdated time.Time
}

// VerifyCredentialStatus returns a types.ErrRevoked when the credentialStatus contains a 'StatusList2021Entry' that can be resolved and lists the credential as 'revoked'
// Other credentialStatus type/statusPurpose are ignored. Verification may fail with other non-standardized errors.
func (cs *credentialStatus) verify(credentialToVerify vc.VerifiableCredential) error {
	if credentialToVerify.CredentialStatus == nil {
		return nil
	}
	statuses, err := credentialToVerify.CredentialStatuses()
	if err != nil {
		// cannot happen. already validated in credential.defaultCredentialValidator{}
		return err
	}

	// only check credentialStatus of type StatusList2021Entry with statusPurpose == revocation other types/purposes are ignored
	// returns errors if processing fails -> TODO: hard/soft fail option?
	// returns types.ErrRevoked if correct type, purpose, and listed.
	for _, status := range statuses {
		if status.Type != credential.StatusList2021EntryType {
			// ignore other credentialStatus.type
			// TODO: what log level?
			log.Logger().
				WithField("credentialStatus.type", status.Type).
				Info("ignoring credentialStatus with unknown type")
			continue
		}
		var slEntry credential.StatusList2021Entry // CredentialStatus of the credentialToVerify
		if err = json.Unmarshal(status.Raw(), &slEntry); err != nil {
			// cannot happen. already validated in credential.defaultCredentialValidator{}
			return err
		}
		if slEntry.StatusPurpose != "revocation" {
			// ignore purposes that are not revocation
			// TODO: what log level?
			log.Logger().
				WithField("credentialStatus.statusPurpose", slEntry.StatusPurpose).
				Info("ignoring credentialStatus with purpose other than 'revocation'")
			continue
		}

		// get StatusList2021Credential with same purpose
		sList, err := cs.statusList(slEntry.StatusListCredential)
		if err != nil {
			return err
		}
		if sList.statusPurpose != slEntry.StatusPurpose {
			return fmt.Errorf("StatusList2021Credential.credentialSubject.statusPuspose='%s' does not match vc.credentialStatus.statusPurpose='%s'", sList.statusPurpose, slEntry.StatusPurpose)
		}

		// check if listed
		index, err := strconv.Atoi(slEntry.StatusListIndex)
		if err != nil {
			// cannot happen. already validated in credential.defaultCredentialValidator{}
			return err
		}
		revoked, err := sList.expanded.Bit(index)
		if err != nil {
			return err
		}
		if revoked {
			return types.ErrRevoked
		}
	}
	return nil
}

func (cs *credentialStatus) statusList(statusListCredential string) (*statusList, error) {
	// TODO: check if there is a cached version to return
	return cs.update(statusListCredential)
}

// update
func (cs *credentialStatus) update(statusListCredential string) (*statusList, error) {
	// download and verify
	cred, err := cs.download(statusListCredential)
	if err != nil {
		return nil, err
	}
	credSubject, err := cs.verifyStatusList2021Credential(*cred)
	if err != nil {
		return nil, err
	}

	// make statusList
	expanded, err := statuslist2021.Expand(credSubject.EncodedList)
	if err != nil {
		// cant happen, already checked in verifyStatusList2021Credential
		return nil, err
	}
	sl := statusList{
		credential:           cred,
		statusListCredential: statusListCredential,
		statusPurpose:        credSubject.StatusPurpose,
		expanded:             expanded,
		lastUpdated:          time.Now(),
	}
	// TODO: cache updated credential so it does not have to be downloaded everytime
	//  	 also cache if statusPurposes != 'revocation' to prevent unnecessary downloads
	return &sl, nil
}

// download the StatusList2021Credential found at statusList2021Entry.statusListCredential
func (cs *credentialStatus) download(statusListCredential string) (*vc.VerifiableCredential, error) {
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
			log.Logger().
				WithError(err).
				WithField("method", "credentialStatus.download").
				Debug("failed to close response body")
		}
	}()
	body, err := io.ReadAll(res.Body)
	if res.StatusCode > 299 || err != nil {
		return nil, fmt.Errorf("fetching StatusList2021Credential from '%s' failed", statusListCredential)
	}
	if err = json.Unmarshal(body, &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

// verifyStatusList2021Credential checks that the StatusList2021Credential is currently valid
func (cs *credentialStatus) verifyStatusList2021Credential(cred vc.VerifiableCredential) (*credential.StatusList2021CredentialSubject, error) {
	// make sure we have the correct credential.
	if len(cred.Type) > 2 || !cred.IsType(ssi.MustParseURI(credential.StatusList2021CredentialType)) {
		return nil, errors.New("incorrect credential types")
	}

	// returns statusList2021CredentialValidator, or Validate() fails because base type is missing
	if err := credential.FindValidator(cred).Validate(cred); err != nil {
		return nil, err
	}

	// prevent an infinite loops in credentialStatus resolution; not that this is not prohibited by the spec
	if cred.CredentialStatus != nil {
		return nil, errors.New("StatusList2021Credential with a CredentialStatus is not supported")
	}

	// check credentialSubject
	var credSubjects []credential.StatusList2021CredentialSubject
	if err := cred.UnmarshalCredentialSubject(&credSubjects); err != nil {
		// cannot happen. already validated in credential.statusList2021CredentialValidator{}
		return nil, err
	}
	credSubject := credSubjects[0] // validators already ensured there is exactly 1 credentialSubject
	_, err := statuslist2021.Expand(credSubject.EncodedList)
	if err != nil {
		return nil, fmt.Errorf("credentialSubject.encodedList is invalid: %w", err)
	}

	// verify signature
	if err = cs.verifySignature(cred, nil); err != nil {
		return nil, err
	}
	return &credSubject, nil
}
