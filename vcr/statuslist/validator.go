package statuslist

import (
	"github.com/nuts-foundation/go-did/vc"
	credential2 "github.com/nuts-foundation/nuts-node/vcr/credential"
)

// statusList2021CredentialValidator validates that all required fields of a StatusList2021CredentialType are present
type statusList2021CredentialValidator struct{}

func (d statusList2021CredentialValidator) Validate(credential vc.VerifiableCredential) error {
	if err := (credential2.defaultCredentialValidator{}).Validate(credential); err != nil {
		return err
	}

	{ // Credential checks
		if !credential.ContainsContext(statusList2021ContextURI) {
			return credential2.failure("context '%s' is required", statusList2021ContextURI)
		}
		if !credential.IsType(statusList2021CredentialTypeURI) {
			return credential2.failure("type '%s' is required", statusList2021CredentialTypeURI)
		}
	}

	{ // CredentialSubject checks
		var target []StatusList2021CredentialSubject
		err := credential.UnmarshalCredentialSubject(&target)
		if err != nil {
			return credential2.failure(err.Error())
		}
		// The spec is not clear if there could be multiple CredentialSubjects. This could allow 'revocation' and 'suspension' to be defined in a single credential.
		// However, it is not defined how to select the correct list (StatusPurpose) when validating credentials that are using this StatusList2021Credential.
		if len(target) != 1 {
			return credential2.failure("single CredentialSubject expected")
		}
		cs := target[0]

		if cs.Type != StatusList2021CredentialSubjectType {
			return credential2.failure("credentialSubject.type '%s' is required", StatusList2021CredentialSubjectType)
		}
		if cs.StatusPurpose == "" {
			return credential2.failure("credentialSubject.statusPurpose is required")
		}
		if cs.EncodedList == "" {
			return credential2.failure("credentialSubject.encodedList is required")
		}
	}

	return nil
}
