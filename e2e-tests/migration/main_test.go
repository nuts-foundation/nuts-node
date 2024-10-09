//go:build e2e_tests

/*
 * Copyright (C) 2023 Nuts community
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

package migration

import (
	"encoding/json"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"strings"
	"testing"
)

type manager struct {
	DID *didsubject.SqlDIDManager
	DOC *didsubject.SqlDIDDocumentManager
}

func Test_Migrations(t *testing.T) {
	db := storage.NewTestStorageEngineInDir(t, "./nodeA/data").GetSQLDatabase()
	man := &manager{
		DID: didsubject.NewDIDManager(db),
		DOC: didsubject.NewDIDDocumentManager(db),
	}

	DIDs, err := man.DID.All()
	require.NoError(t, err)
	require.Len(t, DIDs, 7) // 4 did:nuts, 3 did:web

	t.Run("vendor", func(t *testing.T) {
		// versions for did:nuts:
		// - LC0: init -> no controller because vendor
		// - LC4: add service1
		// - LC4: add service2, conflicts with above
		// - LC8: add verification method, solves conflict
		// no updates during migration
		//
		// total 4 versions in SQL; latest has 2 services and 2 VMs
		id := did.MustParseDID(os.Getenv("VENDOR_DID"))
		doc, err := man.DOC.Latest(id, nil)
		require.NoError(t, err)

		assert.Equal(t, 3, doc.Version)
		assert.Len(t, doc.Services, 2)
		assert.Len(t, doc.VerificationMethods, 2)

		// migration: add did:web
		hasDIDWeb(t, man, doc)
	})
	t.Run("org1", func(t *testing.T) {
		// versions for did:nuts:
		// - LC1: init -> has controller
		// - LC5: add service2
		// - LC6: add service1, conflicts with above
		// migration removes controller (solves document conflict)
		//
		// total 4 versions in SQL; latest one has no controller, 2 services, and 1 VM
		id := did.MustParseDID(os.Getenv("ORG1_DID"))
		doc, err := man.DOC.Latest(id, nil)
		require.NoError(t, err)

		assert.Equal(t, 3, doc.Version)
		assert.Len(t, doc.Services, 2)
		assert.Len(t, doc.VerificationMethods, 1)
		didDoc := new(did.Document)
		require.NoError(t, json.Unmarshal([]byte(doc.Raw), didDoc))
		assert.Empty(t, didDoc.Controller)

		// migration: add did:web
		hasDIDWeb(t, man, doc)
	})
	t.Run("org2", func(t *testing.T) {
		// versions for did:nuts:
		// - LC2: init -> has controller
		// - LC5: deactivate
		// - LC6: service2, conflicts with above
		// deactivated, so no updates during migration;
		//
		// total 2 versions in SQL, migration stopped at LC5; no controller, 0 service, 0 VM
		id := did.MustParseDID(os.Getenv("ORG2_DID"))
		doc, err := man.DOC.Latest(id, nil)
		require.NoError(t, err)

		assert.Equal(t, 1, doc.Version)
		assert.Len(t, doc.Services, 0)
		assert.Len(t, doc.VerificationMethods, 0)

		// deactivated; has no did:web
		dids, err := man.DID.FindBySubject(doc.DID.Subject) // migrated documents have subject == did:nuts:...
		require.NoError(t, err)
		assert.Len(t, dids, 1)
	})
	t.Run("org3", func(t *testing.T) {
		// versions for did:nuts:
		// - LC3: init -> has controller
		// - LC7: add service1
		// - LC7: add verification method, conflicts with above
		// - LC9: add service2, solves conflict
		// migration removes controller
		//
		// total 5 versions in SQL; no controller, 2 services, 2 VMs
		id := did.MustParseDID(os.Getenv("ORG3_DID"))
		doc, err := man.DOC.Latest(id, nil)
		require.NoError(t, err)

		assert.Equal(t, 4, doc.Version)
		assert.Len(t, doc.Services, 2)
		assert.Len(t, doc.VerificationMethods, 2)
		didDoc := new(did.Document)
		require.NoError(t, json.Unmarshal([]byte(doc.Raw), didDoc))
		assert.Empty(t, didDoc.Controller)

		// migration: add did:web
		hasDIDWeb(t, man, doc)
	})
}

func hasDIDWeb(t *testing.T, man *manager, nutsDoc *orm.DidDocument) {
	dids, err := man.DID.FindBySubject(nutsDoc.DID.Subject) // migrated documents have subject == did:nuts:...
	require.NoError(t, err)
	assert.Len(t, dids, 2)
	var webDoc *orm.DidDocument
	for _, id := range dids {
		if strings.HasPrefix(id.ID, "did:web:") {
			webDoc, err = man.DOC.Latest(did.MustParseDID(id.ID), nil)
			require.NoError(t, err)
		}
	}
	assert.Equal(t, 0, webDoc.Version)
}
