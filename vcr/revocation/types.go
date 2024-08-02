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

package revocation

import (
	"context"
	"crypto"
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
	"github.com/nuts-foundation/nuts-node/vdr/resolver"
	"gorm.io/gorm"
)

const (
	// StatusList2021CredentialType is the type of StatusList2021Credential
	StatusList2021CredentialType = "StatusList2021Credential"
	// StatusList2021CredentialSubjectType is the credentialSubject.type in a StatusList2021Credential
	StatusList2021CredentialSubjectType = "StatusList2021"
	// StatusList2021EntryType is the credentialStatus.type
	StatusList2021EntryType = "StatusList2021Entry"
)

var StatusList2021ContextURI = ssi.MustParseURI(jsonld.W3cStatusList2021Context)
var statusList2021CredentialTypeURI = ssi.MustParseURI(StatusList2021CredentialType)

// errNotFound wraps types.ErrNotFound to clarify which StatusList2021Credential is not found
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

// StatusList2021Issuer is the issuer side of StatusList2021
type StatusList2021Issuer interface {
	// Credential provides a valid StatusList2021Credential with subject ID derived from the issuer and page.
	// It returns the last issued StatusList2021Credential if it is still valid or issues a new StatusList2021Credential.
	Credential(ctx context.Context, issuer did.DID, page int) (*vc.VerifiableCredential, error)
	// Entry creates a StatusList2021Entry that can be added to the credentialStatus of a VC.
	// The corresponding StatusList2021Credential will have a gap in the bitstring if the returned entry does not make it into a VC.
	// If the entry belongs to a new StatusList2021Credential, an empty StatusList2021Credential is issued and stored.
	Entry(ctx context.Context, issuer did.DID, purpose StatusPurpose) (*StatusList2021Entry, error)
	// Revoke by adding the StatusList2021Entry to the list of revocations, and updates the relevant StatusList2021Credential.
	// The credentialID allows reverse search of revocations, its issuer is NOT verified against the entry issuer or VC.
	// Returns types.ErrRevoked if already revoked, or types.ErrNotFound when the entry.StatusListCredential is unknown.
	Revoke(ctx context.Context, credentialID ssi.URI, entry StatusList2021Entry) error
}

// StatusList2021Verifier is the verifier side of StatusList2021
type StatusList2021Verifier interface {
	// Verify returns a types.ErrRevoked when the credentialStatus contains a 'StatusList2021Entry' that can be resolved and lists the credential as 'revoked'
	// Other credentialStatus type/statusPurpose are ignored. Verification may fail with other non-standardized errors.
	Verify(credentialToVerify vc.VerifiableCredential) error
}

// VerifySignFn verifies the signature on VC. The vcr.verifier injects its VerifySignature method here.
type VerifySignFn func(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error

// SignFn signs a VC according to the specified format. The vcr.issuer injects its signVC method here.
type SignFn func(ctx context.Context, unsignedCredential vc.VerifiableCredential, kid string) (*vc.VerifiableCredential, error)

// ResolveKeyFn resolves the key used SignFn to sign the StatusList2021Credential.
// The vcr.issuer injects its keyResolver.ResolveAssertionKey here.
type ResolveKeyFn func(issuerDID did.DID, at *time.Time, relationType resolver.RelationType) (string, crypto.PublicKey, error)

var _ StatusList2021Issuer = (*StatusList2021)(nil)
var _ StatusList2021Verifier = (*StatusList2021)(nil)

// StatusList2021 implements the W3C Verifiable Credentials Status List v2021 draft specification.
// https://www.w3.org/TR/2023/WD-vc-status-list-20230427/
// VerifySignature and Sign methods are used to verify and sign StatusList2021Credentials
type StatusList2021 struct {
	client          core.HTTPRequestDoer
	db              *gorm.DB
	baseURL         string
	VerifySignature VerifySignFn // injected by verifier
	Sign            SignFn       // injected by issuer, context must contain an audit log
	ResolveKey      ResolveKeyFn // injected by issuer
}

// NewStatusList2021 returns a StatusList2021 without a Sign or VerifySignature method.
// The URL in the credential will be constructed as follows using the given base URL: <baseURL>/statuslist/<did>/<page>
func NewStatusList2021(db *gorm.DB, client core.HTTPRequestDoer, baseURL string) *StatusList2021 {
	return &StatusList2021{client: client, db: db, baseURL: baseURL}
}

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
	// The value identifies the position in the bitstring of the corresponding StatusListCredential.
	StatusListIndex string `json:"statusListIndex,omitempty"`
	// StatusListCredential property MUST be a URL to the StatusList2021Credential.
	// When the URL is dereferenced, the resulting verifiable credential's type MUST include the "StatusList2021Credential".
	StatusListCredential string `json:"statusListCredential,omitempty"`
}

// Validate returns an error if the contents of the StatusList2021Entry violate the spec.
func (e StatusList2021Entry) Validate() error {
	// 'id' MUST NOT be the URL for the status list
	if e.ID == e.StatusListCredential {
		return errors.New("StatusList2021Entry.id is the same as the StatusList2021Entry.statusListCredential")
	}

	if e.Type != StatusList2021EntryType {
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

// StatusList2021CredentialSubject of a StatusList2021Credential
type StatusList2021CredentialSubject struct {
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
