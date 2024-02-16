package statuslist

import (
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/vc"
)

// TODO: copy from credential package, merge with other
type defaultCredentialValidator struct {
}

func (d defaultCredentialValidator) Validate(credential vc.VerifiableCredential) error {
	if !credential.IsType(vc.VerifiableCredentialTypeV1URI()) {
		return errors.New("type 'VerifiableCredential' is required")
	}

	if !credential.ContainsContext(vc.VCContextV1URI()) {
		return errors.New("default context is required")
	}

	if credential.ID == nil {
		return errors.New("'ID' is required")
	}

	// 'issuanceDate' must be present, but can be zero if replaced by alias 'validFrom'
	if (credential.IssuanceDate == nil || credential.IssuanceDate.IsZero()) &&
		(credential.ValidFrom == nil || credential.ValidFrom.IsZero()) {
		return errors.New("'issuanceDate' is required")
	}

	if credential.Format() == vc.JSONLDCredentialProofFormat && credential.Proof == nil {
		return errors.New("'proof' is required for JSON-LD credentials")
	}

	//// CredentialStatus is not specific to the credential type and the syntax (not status) should be checked here.
	//if err := credential.validateCredentialStatus(credential); err != nil {
	//	return fmt.Errorf("invalid credentialStatus: %s", err)
	//}

	return nil
}

// statusList2021CredentialValidator validates that all required fields of a StatusList2021CredentialType are present
type statusList2021CredentialValidator struct{}

func (d statusList2021CredentialValidator) Validate(credential vc.VerifiableCredential) error {
	if err := (defaultCredentialValidator{}).Validate(credential); err != nil {
		return err
	}

	{ // Credential checks
		if !credential.ContainsContext(StatusList2021ContextURI) {
			return fmt.Errorf("context '%s' is required", StatusList2021ContextURI)
		}
		if !credential.IsType(statusList2021CredentialTypeURI) {
			return fmt.Errorf("type '%s' is required", statusList2021CredentialTypeURI)
		}
	}

	{ // CredentialSubject checks
		var target []StatusList2021CredentialSubject
		err := credential.UnmarshalCredentialSubject(&target)
		if err != nil {
			return err
		}
		// The spec is not clear if there could be multiple CredentialSubjects. This could allow 'revocation' and 'suspension' to be defined in a single credential.
		// However, it is not defined how to select the correct list (StatusPurpose) when validating credentials that are using this StatusList2021Credential.
		if len(target) != 1 {
			return errors.New("single CredentialSubject expected")
		}
		cs := target[0]

		if cs.Type != StatusList2021CredentialSubjectType {
			return fmt.Errorf("credentialSubject.type '%s' is required", StatusList2021CredentialSubjectType)
		}
		if cs.StatusPurpose == "" {
			return errors.New("credentialSubject.statusPurpose is required")
		}
		if cs.EncodedList == "" {
			return errors.New("credentialSubject.encodedList is required")
		}
	}

	return nil
}
