package storage

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSQLRevocationStore(t *testing.T) {
	container, db, err := startDatabase()
	require.NoError(t, err)
	defer container.Terminate(context.Background())

	jsonldInstance := jsonld.NewJSONLDInstance()
	err = jsonldInstance.(core.Configurable).Configure(*core.NewServerConfig())
	require.NoError(t, err)

	for _, role := range []Role{RoleIssuer, RoleHolderVerifier} {
		store, err := NewSQLRevocationStore(db, role)
		require.NoError(t, err)
		t.Run(string(role), func(t *testing.T) {
			t.Run("1 revocation", func(t *testing.T) {
				credentialID := ssi.MustParseURI(localDID.String() + "#" + uuid.NewString())
				revocation := credential.BuildRevocation(localDID.URI(), credentialID)
				err = store.StoreRevocation(revocation)
				require.NoError(t, err)

				revocations, err := store.GetRevocations(credentialID)

				require.NoError(t, err)
				require.Len(t, revocations, 1)
				actualJSON, _ := json.Marshal(revocations[0])
				expectedJSON, _ := json.Marshal(revocation)
				assert.JSONEq(t, string(expectedJSON), string(actualJSON))
			})
			t.Run("multiple revocations", func(t *testing.T) {
				credentialID := ssi.MustParseURI(localDID.String() + "#" + uuid.NewString())
				revocation1 := credential.BuildRevocation(localDID.URI(), credentialID)
				err = store.StoreRevocation(revocation1)
				require.NoError(t, err)
				revocation2 := credential.BuildRevocation(localDID.URI(), credentialID)
				revocation2.Date = revocation1.Date.Add(time.Hour)
				err = store.StoreRevocation(revocation2)
				require.NoError(t, err)

				revocations, err := store.GetRevocations(credentialID)

				require.NoError(t, err)
				require.Len(t, revocations, 2)
			})
			t.Run("no revocations", func(t *testing.T) {
				credentialID := ssi.MustParseURI(localDID.String() + "#" + uuid.NewString())

				revocations, err := store.GetRevocations(credentialID)

				require.NoError(t, err)
				require.Empty(t, revocations)
			})
			t.Run("count", func(t *testing.T) {
				credentialID1 := ssi.MustParseURI(localDID.String() + "#" + uuid.NewString())
				credentialID2 := ssi.MustParseURI(localDID.String() + "#" + uuid.NewString())
				store, err := NewSQLRevocationStore(db, role)
				require.NoError(t, err)
				_, err = db.Exec("TRUNCATE TABLE " + store.tableName())
				require.NoError(t, err)

				// Empty
				count, err := store.Count()
				require.NoError(t, err)
				assert.Equal(t, 0, count)

				// 1 result
				revocation1 := credential.BuildRevocation(localDID.URI(), credentialID1)
				err = store.StoreRevocation(revocation1)
				require.NoError(t, err)
				count, err = store.Count()
				require.NoError(t, err)
				assert.Equal(t, 1, count)

				// 3 results (1 VC with 2 revocations, 1 VC with 1 revocation)
				revocation2 := credential.BuildRevocation(localDID.URI(), credentialID1)
				revocation2.Date = revocation1.Date.Add(time.Hour)
				err = store.StoreRevocation(revocation2)
				require.NoError(t, err)
				revocation3 := credential.BuildRevocation(localDID.URI(), credentialID2)
				err = store.StoreRevocation(revocation3)
				require.NoError(t, err)

				count, err = store.Count()
				require.NoError(t, err)
				assert.Equal(t, 3, count)
			})
		})
	}
}
