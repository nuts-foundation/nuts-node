/*
 * Copyright (C) 2024 Nuts community
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

package statuslist2021

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"gorm.io/gorm"
)

const (
	// CredentialType is the type of StatusList2021Credential
	CredentialType = "StatusList2021Credential"
	// CredentialSubjectType is the credentialSubject.type in a StatusList2021Credential
	CredentialSubjectType = "StatusList2021"
	// EntryType is the credentialStatus.type that lists the entry of that credential on a list
	EntryType = "StatusList2021Entry"
)

var ContextURI = ssi.MustParseURI(jsonld.W3cStatusList2021Context)
var credentialTypeURI = ssi.MustParseURI(CredentialType)

// errNotFound wraps types.ErrNotFound to clarify which credential is not found
var errNotFound = fmt.Errorf("status list: %w", types.ErrNotFound)

// errRevoked wraps types.ErrRevoked to clarify the source of the error
var errRevoked = fmt.Errorf("status list: %w", types.ErrRevoked)

// errUnsupportedPurpose limits current usage to 'revocation'
var errUnsupportedPurpose = errors.New("status list: purpose not supported")

type StatusPurpose string

const (
	StatusPurposeRevocation = "revocation"
	statusPurposeSuspension = "suspension" // currently not supported
)

// Issuer side of StatusList2021
type Issuer interface {
	// Credential provides a valid StatusList2021Credential with subject ID derived from the issuer and page.
	// It returns the last issued credential if it is still valid or issues a new credential.
	Credential(ctx context.Context, issuer did.DID, page int) (*vc.VerifiableCredential, error)
	// Create a StatusList2021Entry that can be added to the credentialStatus of a VC.
	// The corresponding credential will have a gap in the bitstring if the returned entry does not make it into a credential.
	// If the entry belongs to a new StatusList2021Credential, an empty credential is issued and stored.
	Create(ctx context.Context, issuer did.DID, purpose StatusPurpose) (*Entry, error)
	// Revoke by adding the StatusList2021Entry to the list of revocations, and updates the relevant StatusList2021Credential.
	// The credentialID allows reverse search of revocations, its issuer is NOT verified against the entry issuer or VC.
	// Returns types.ErrRevoked if already revoked, or types.ErrNotFound when the entry.StatusListCredential is unknown.
	Revoke(ctx context.Context, credentialID ssi.URI, entry Entry) error
}

// Verifier side of StatusList2021
type Verifier interface {
	// Verify returns a types.ErrRevoked when the credentialStatus contains a 'StatusList2021Entry' that can be resolved and lists the credential as 'revoked'
	// Other credentialStatus type/statusPurpose are ignored. Verification may fail with other non-standardized errors.
	Verify(credentialToVerify vc.VerifiableCredential) error
}

// VerifySignFn verifies the signature on VC. The vcr.verifier injects its VerifySignature method here.
type VerifySignFn func(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error

// SignFn signs a VC according to the specified format. The vcr.issuer injects its signVC method here.
type SignFn func(ctx context.Context, unsignedCredential vc.VerifiableCredential, credentialFormat string) (*vc.VerifiableCredential, error)

var _ Issuer = (*CredentialStatus)(nil)
var _ Verifier = (*CredentialStatus)(nil)

type CredentialStatus struct {
	client          core.HTTPRequestDoer
	db              *gorm.DB
	VerifySignature VerifySignFn // injected by verifier
	Sign            SignFn       // injected by issuer, context must contain an audit log
}

// NewCredentialStatus returns a CredentialStatus without a Sign or VerifySignature method.
func NewCredentialStatus(db *gorm.DB, client core.HTTPRequestDoer) *CredentialStatus {
	return &CredentialStatus{client: client, db: db}
}

// Entry is the "credentialStatus" property used by issuers to enable VerifiableCredential status information.
type Entry struct {
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
	// StatusListCredential property MUST be a URL to a verifiable credential.
	// When the URL is dereferenced, the resulting verifiable credential MUST have type property that includes the "StatusList2021Credential" value.
	StatusListCredential string `json:"statusListCredential,omitempty"`
}

// Validate returns an error if the contents of the Entry violate the spec.
func (e Entry) Validate() error {
	// 'id' MUST NOT be the URL for the status list
	if e.ID == e.StatusListCredential {
		return errors.New("StatusList2021Entry.id is the same as the StatusList2021Entry.statusListCredential")
	}

	if e.Type != EntryType {
		return errors.New("StatusList2021Entry.type must be StatusList2021Entry")
	}

	// StatusPurpose must contain a purpose
	if e.StatusPurpose == "" {
		return errors.New("StatusList2021Entry.statusPurpose is required")
	}

	// statusListIndex must be a non-negative number
	if n, err := strconv.Atoi(e.StatusListIndex); err != nil || n < 0 {
		return errors.New("invalid StatusList2021Entry.statusListIndex")
	}

	// 'statusListCredential' must be a URL
	if _, err := url.ParseRequestURI(e.StatusListCredential); err != nil {
		return fmt.Errorf("parse StatusList2021Entry.statusListCredential URL: %w", err)
	}

	return nil
}

type CredentialSubject struct {
	// ID for the credential subject
	ID string `json:"id"`
	// Type MUST be "StatusList2021Credential"
	Type string `json:"type"`
	// StatusPurpose defines the reason credentials are listed. ('revocation', 'suspension')
	StatusPurpose string `json:"statusPurpose"`
	// EncodedList is the GZIP-compressed [RFC1952], base-64 encoded [RFC4648] bitstring values for the associated range
	// of verifiable credential status values. The uncompressed bitstring MUST be at least 16KB in size.
	EncodedList string `json:"encodedList"`
}
