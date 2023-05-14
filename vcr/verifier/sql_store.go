package verifier

import (
	"database/sql"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"github.com/nuts-foundation/nuts-node/vcr/storage"
)

var _ Store = (*sqlStore)(nil)

func NewSQLStore(db *sql.DB) (Store, error) {
	store, err := storage.NewSQLRevocationStore(db, storage.RoleHolderVerifier)
	if err != nil {
		return nil, err
	}
	return sqlStore{
		underlyingStore: store,
	}, nil
}

type sqlStore struct {
	underlyingStore *storage.SQLRevocationStore
}

func (s sqlStore) Diagnostics() []core.DiagnosticResult {
	var count int
	var err error
	count, err = s.underlyingStore.Count()
	if err != nil {
		count = -1
		log.Logger().
			WithError(err).
			Warn("Unable to retrieve revocations document count")
	}
	return []core.DiagnosticResult{
		core.GenericDiagnosticResult{
			Title:   "revocations_count",
			Outcome: count,
		},
	}
}

func (s sqlStore) GetRevocations(id ssi.URI) ([]*credential.Revocation, error) {
	return s.underlyingStore.GetRevocations(id)
}

func (s sqlStore) StoreRevocation(r credential.Revocation) error {
	return s.underlyingStore.StoreRevocation(r)
}

func (s sqlStore) Close() error {
	return nil
}
