package issuer

import (
	"context"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"strconv"
	"sync"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/credential/statuslist2021"
	"github.com/nuts-foundation/nuts-node/vdr/didweb"
)

// errNotFound wraps types.ErrNotFound to clarify which credential is not found
var errNotFound = fmt.Errorf("status list: %w", types.ErrNotFound)

// errUnsupportedPurpose limits current usage to 'revocation'
var errUnsupportedPurpose = errors.New("status list: purpose not supported")

// errNotFound wraps types.ErrRevoked to clarify the source of the error
var errRevoked = fmt.Errorf("status list: %w", types.ErrRevoked)

type StatusPurpose string

const (
	StatusPurposeRevocation = "revocation"
	statusPurposeSuspension = "suspension" // currently not supported
)

// StatusList2021Store keeps track of the number of credentials with a credential status per issuer, and allows revoking
// them by setting the relevant bit on the StatusList.
// Individual statuses should be derived from the StatusList2021Credential(s), not inspected here.
type StatusList2021Store interface {
	// CredentialSubject creates a StatusList2021CredentialSubject to incorporate in a StatusList2021Credential issued by issuer.
	CredentialSubject(ctx context.Context, issuer did.DID, page int) (*credential.StatusList2021CredentialSubject, error)
	// Create a credential.StatusList2021Entry that can be added to the credentialStatus of a VC.
	// The corresponding credential will have a gap in the bitstring if the returned entry does not make it into a credential.
	Create(ctx context.Context, issuer did.DID, purpose StatusPurpose) (*credential.StatusList2021Entry, error)
	// Revoke by adding StatusList2021Entry to the list of revocations.
	// The credentialID is only used to allow reverse search of revocations, its issuer is NOT compared to the entry issuer.
	// Returns types.ErrRevoked if already revoked, or types.ErrNotFound when the entry.StatusListCredential is unknown.
	Revoke(ctx context.Context, credentialID ssi.URI, entry credential.StatusList2021Entry) error
}

// lastIndex tracks the last Page + StatusListIndex combo issued for an Issuer
type lastIndex struct {
	Issuer          string // did:web:example.com:iam:id
	Page            int    // >= 1
	StatusListIndex int    // 0 <= statusListIndex < statuslist2021.MaxBitstringIndex
}

// revocation exists if the index on the statusListCredential is set
type revocation struct {
	StatusListCredential string // https://example.com/iam/id/status/page
	CredentialID         string // did:web:example.com:iam:id#unique-identifier
	Page                 int    // >= 1
	StatusListIndex      int    // 0 <= statusListIndex <= statuslist2021.MaxBitstringIndex
}

var _ StatusList2021Store = (*statusListMemoryStore)(nil)

func newStatusListMemoryStore() *statusListMemoryStore {
	return &statusListMemoryStore{
		revocations: make(map[string][]revocation),
		issuers:     make(map[string]lastIndex),
		mux:         sync.RWMutex{},
	}
}

// statusListMemoryStore is an in-memory store for testing. It does not store anything and only works for did:web
type statusListMemoryStore struct {
	// revocations maps all revoked credentials to the relevant statusListCredential (so incl. page)
	revocations map[string][]revocation
	// issuers keeps track of known issuers and their last statusListIndex+Page combo
	issuers map[string]lastIndex
	mux     sync.RWMutex
}

func (s *statusListMemoryStore) CredentialSubject(_ context.Context, issuer did.DID, page int) (*credential.StatusList2021CredentialSubject, error) {
	s.mux.RLock()
	defer s.mux.RUnlock()

	statusListCredential, err := toStatusListCredential(issuer, page)
	if err != nil {
		return nil, err
	}

	// get revocations
	pageRevocations, ok := s.revocations[statusListCredential]
	if !ok {
		return nil, errNotFound
	}

	// make encodedList
	bitstring := statuslist2021.NewBitstring()
	for _, rev := range pageRevocations {
		if err = bitstring.SetBit(rev.StatusListIndex, true); err != nil {
			// can't happen
			return nil, err
		}
	}
	encodedList, err := statuslist2021.Compress(*bitstring)
	if err != nil {
		// can't happen
		return nil, err
	}

	return &credential.StatusList2021CredentialSubject{
		Id:            statusListCredential,
		Type:          credential.StatusList2021CredentialSubjectType,
		StatusPurpose: StatusPurposeRevocation,
		EncodedList:   encodedList,
	}, nil
}

func (s *statusListMemoryStore) Create(_ context.Context, issuer did.DID, purpose StatusPurpose) (*credential.StatusList2021Entry, error) {
	if purpose != StatusPurposeRevocation {
		return nil, errUnsupportedPurpose
	}

	// lock db after validating input
	s.mux.Lock()
	defer s.mux.Unlock()

	// last index
	issuerIndex, ok := s.issuers[issuer.String()]

	// new StatusList2021Credential issuer
	if !ok {
		issuerIndex = lastIndex{
			Issuer:          issuer.String(),
			Page:            1,
			StatusListIndex: -1, // will be incremented before usage
		}
	}

	// next index
	issuerIndex.StatusListIndex++
	if issuerIndex.StatusListIndex > statuslist2021.MaxBitstringIndex {
		issuerIndex.StatusListIndex = 0
		issuerIndex.Page++
	}

	// statusListCredential with correct page
	statusListCredential, err := toStatusListCredential(issuer, issuerIndex.Page)
	if err != nil {
		return nil, err
	}

	// store new page
	if issuerIndex.StatusListIndex == 0 {
		s.revocations[statusListCredential] = []revocation{}
	}

	// store index
	s.issuers[issuer.String()] = issuerIndex

	return &credential.StatusList2021Entry{
		ID:                   fmt.Sprintf("%s#%d", statusListCredential, issuerIndex.StatusListIndex),
		Type:                 credential.StatusList2021EntryType,
		StatusPurpose:        StatusPurposeRevocation,
		StatusListIndex:      strconv.Itoa(issuerIndex.StatusListIndex),
		StatusListCredential: statusListCredential,
	}, nil
}

func (s *statusListMemoryStore) Revoke(_ context.Context, credentialID ssi.URI, entry credential.StatusList2021Entry) error {
	// validate statusListIndex
	indexToRevoke, err := strconv.Atoi(entry.StatusListIndex)
	if err != nil {
		return err
	}
	if indexToRevoke < 0 || indexToRevoke > statuslist2021.MaxBitstringIndex {
		return statuslist2021.ErrIndexNotInBitstring
	}

	// lock db after validating input
	s.mux.Lock()
	defer s.mux.Unlock()

	// get revocations for this page. exists when a StatusList2021Entry with purpose 'revocation' was issued for the page
	revokedIndices, ok := s.revocations[entry.StatusListCredential]
	if !ok {
		return errNotFound
	}

	// check if revoked
	for _, rev := range revokedIndices {
		if rev.StatusListIndex == indexToRevoke {
			// already revoked
			return errRevoked
		}
	}

	// store revocation
	newRevocation := revocation{
		StatusListCredential: entry.StatusListCredential,
		CredentialID:         credentialID.String(),
		StatusListIndex:      indexToRevoke,
	}
	s.revocations[entry.StatusListCredential] = append(s.revocations[entry.StatusListCredential], newRevocation)

	return nil
}

func toStatusListCredential(issuer did.DID, page int) (string, error) {
	switch issuer.Method {
	case "web":
		issuerAsURL, err := didweb.DIDToURL(issuer) // https://example.com/iam/id
		if err != nil {
			return "", err
		}
		return issuerAsURL.JoinPath("statuslist", strconv.Itoa(page)).String(), nil // https://example.com/iam/id/status/page
	}
	return "", fmt.Errorf("status list: unsupported DID method: %s", issuer.Method)
}
