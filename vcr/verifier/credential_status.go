package verifier

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/credential/statuslist2021"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"io"
	"net/http"
	"strconv"
	"time"
)

type credentialStatus struct {
	client          core.HTTPRequestDoer
	verifySignature func(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error //
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
	// expanded StatusList2021 bitstring
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
		// this cannot happen, already checked in credential.validateCredentialStatus()
		return err
	}

	// only check credentialStatus of type StatusList2021Entry with statusPurpose == revocation other types/purposes are ignored
	// returns errors if processing fails -> TODO: hard/soft fail option?
	// returns types.ErrRevoked if correct type, purpose, and listed.
	for _, status := range statuses {
		if status.Type != credential.StatusList2021EntryType {
			// ignore other credentialStatus.type
			// TODO: should this be logged?
			continue
		}
		var slEntry credential.StatusList2021Entry // CredentialStatus of the credentialToVerify
		if err = json.Unmarshal(status.Raw(), &slEntry); err != nil {
			return err
		}
		if slEntry.StatusPurpose != "revocation" {
			// ignore purposes that aren't check for revocations
			// TODO: should other purposes be logged?
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
	cred, err := cs.download(statusListCredential)
	if err != nil {
		return nil, err
	}
	if err = cs.verifyStatusList2021Credential(cred); err != nil {
		return nil, err
	}
	var credSubjects []credential.StatusList2021CredentialSubject
	if err := cred.UnmarshalCredentialSubject(&credSubjects); err != nil {
		return nil, err
	}
	credSubject := credSubjects[0] // validators already ensured there is exactly 1 credentialSubject
	expanded, err := statuslist2021.Expand(credSubject.EncodedList)
	if err != nil {
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
	return &sl, nil
}

// download the StatusList2021Credential found at statusList2021Entry.statusListCredential
func (cs *credentialStatus) download(statusListCredential string) (*vc.VerifiableCredential, error) {
	var cred vc.VerifiableCredential // VC containing CredentialStatus of the credentialToVerify
	req, err := http.NewRequest(http.MethodGet, statusListCredential, new(bytes.Buffer))
	if err != nil {
		return nil, err
	}
	res, err := cs.client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(res.Body)
	if err = res.Body.Close(); err != nil {
		//TODO: log, don't fail
	}
	if res.StatusCode > 299 || err != nil {
		return nil, fmt.Errorf("fetching StatusList2021Credential from '%s' failed: %w", statusListCredential, err)
	}
	if err = json.Unmarshal(body, &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

// verifyStatusList2021Credential checks that the StatusList2021Credential is currently valid
func (cs *credentialStatus) verifyStatusList2021Credential(cred *vc.VerifiableCredential) error {
	// make sure we have the correct credential.
	if len(cred.Type) > 2 || !cred.IsType(ssi.MustParseURI(credential.StatusList2021CredentialType)) {
		return errors.New("incorrect credential type recieved")
	}

	// returns statusList2021CredentialValidator, or Validate() fails because base type is missing
	if err := credential.FindValidator(*cred).Validate(*cred); err != nil {
		return err
	}

	// prevent an infinite loops in credentialStatus resolution; not that this is not prohibited by the spec
	if cred.CredentialStatus != nil {
		return errors.New("StatusListCredential with a CredentialStatus is not supported")
	}
	if err := cs.verifySignature(*cred, nil); err != nil {
		return err
	}
	return nil
}
