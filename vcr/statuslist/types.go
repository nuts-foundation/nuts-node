package statuslist

import (
	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/jsonld"
)

const (
	// StatusList2021CredentialType is the type of StatusList2021Credential
	StatusList2021CredentialType = "StatusList2021Credential"
	// StatusList2021CredentialSubjectType is the credentialSubject.type in a StatusList2021Credential
	StatusList2021CredentialSubjectType = "StatusList2021"
	// StatusList2021EntryType is the credentialStatus.type that lists the entry of that credential on a list
	StatusList2021EntryType = "StatusList2021Entry"
)

var StatusList2021ContextURI = ssi.MustParseURI(jsonld.W3cStatusList2021Context)
var statusList2021CredentialTypeURI = ssi.MustParseURI(StatusList2021CredentialType)

// StatusList2021Entry is the "credentialStatus" property used by issuers to enable VerifiableCredential status information.
type StatusList2021Entry struct {
	// ID is expected to be a URL that identifies the status information associated with the verifiable credential.
	// It MUST NOT be the URL for the status list, which is in StatusListCredential.
	ID string `json:"id,omitempty"`
	// Type MUST be "StatusList2021Entry"
	Type string `json:"type,omitempty"`
	// StatusPurpose indicates what it means if the VerifiableCredential is on the list.
	// The value is arbitrary, with predefined values `revocation` and `suspension`.
	// This value must match credentialSubject.statusPurpose value in the VerifiableCredential.
	StatusPurpose string `json:"statusPurpose,omitempty"`
	// StatusListIndex is an arbitrary size integer greater than or equal to 0, expressed as a string.
	// The value identifies the bit position of the status of the verifiable credential.
	StatusListIndex string `json:"statusListIndex,omitempty"`
	// The statusListCredential property MUST be a URL to a verifiable credential.
	// When the URL is dereferenced, the resulting verifiable credential MUST have type property that includes the "StatusList2021Credential" value.
	StatusListCredential string `json:"statusListCredential,omitempty"`
}

type StatusList2021CredentialSubject struct {
	// ID for the credential subject
	Id string `json:"id"`
	// Type MUST be "StatusList2021Credential"
	Type string `json:"type"`
	// StatusPurpose defines the reason credentials are listed. ('revocation', 'suspension')
	StatusPurpose string `json:"statusPurpose"`
	// EncodedList is the GZIP-compressed [RFC1952], base-64 encoded [RFC4648] bitstring values for the associated range
	// of verifiable credential status values. The uncompressed bitstring MUST be at least 16KB in size.
	EncodedList string `json:"encodedList"`
}
