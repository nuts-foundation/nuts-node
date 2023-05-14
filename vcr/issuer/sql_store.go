package issuer

import (
	"database/sql"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/storage"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/piprate/json-gold/ld"
)

var _ Store = (*sqlStore)(nil)

func NewSQLStore(db *sql.DB, documentLoader ld.DocumentLoader) (Store, error) {
	revocationStore, err := storage.NewSQLRevocationStore(db, storage.RoleIssuer)
	if err != nil {
		return nil, err
	}
	credentialStore, err := storage.NewSQLCredentialStore(db, storage.RoleIssuer, documentLoader)
	if err != nil {
		return nil, err
	}
	return sqlStore{
		revocationStore: revocationStore,
		credentialStore: credentialStore,
	}, nil
}

type sqlStore struct {
	revocationStore *storage.SQLRevocationStore
	credentialStore *storage.SQLCredentialStore
}

func (s sqlStore) StoreCredential(credential vc.VerifiableCredential) error {
	return s.credentialStore.StoreCredential(credential)
}

func (s sqlStore) GetCredential(id ssi.URI) (*vc.VerifiableCredential, error) {
	return s.credentialStore.GetCredential(id)
}

func (s sqlStore) SearchCredential(credentialType ssi.URI, issuer did.DID, subject *ssi.URI) ([]vc.VerifiableCredential, error) {
	query := vc.VerifiableCredential{
		Context: []ssi.URI{ssi.MustParseURI("https://www.w3.org/2018/credentials/v1")},
		Type:    []ssi.URI{credentialType},
		Issuer:  issuer.URI(),
	}
	if subject != nil {
		query.CredentialSubject = []interface{}{
			credential.BaseCredentialSubject{
				ID: subject.String(),
			},
		}
	}
	return s.credentialStore.SearchCredentials(query, true)
}

func (s sqlStore) GetRevocation(id ssi.URI) (*credential.Revocation, error) {
	revocations, err := s.revocationStore.GetRevocations(id)
	if err != nil {
		return nil, err
	}
	if len(revocations) == 0 {
		return nil, types.ErrNotFound
	}
	return revocations[0], err
}

func (s sqlStore) StoreRevocation(r credential.Revocation) error {
	return s.revocationStore.StoreRevocation(r)
}

func (s sqlStore) Diagnostics() []core.DiagnosticResult {
	var err error
	var issuedCredentialCount int
	issuedCredentialCount, err = s.credentialStore.Count()
	if err != nil {
		issuedCredentialCount = -1
		log.Logger().
			WithError(err).
			Warn("Unable to retrieve issuedCredentials document count")
	}
	var revokedCredentialsCount int
	revokedCredentialsCount, err = s.revocationStore.Count()
	if err != nil {
		revokedCredentialsCount = -1
		log.Logger().
			WithError(err).
			Warn("Unable to retrieve revokedCredentials document count")
	}
	return []core.DiagnosticResult{
		core.GenericDiagnosticResult{
			Title:   "issued_credentials_count",
			Outcome: issuedCredentialCount,
		},
		core.GenericDiagnosticResult{
			Title:   "revoked_credentials_count",
			Outcome: revokedCredentialsCount,
		},
	}
}

func (s sqlStore) Close() error {
	return nil
}
