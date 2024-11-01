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

package didsubject

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/crypto/storage/spi"
	"github.com/nuts-foundation/nuts-node/storage/orm"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core/to"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestManager_List(t *testing.T) {
	t.Run("2 subjects with each 2 DIDs", func(t *testing.T) {
		db := testDB(t)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{
			"example1": testMethod{method: "example1"},
			"example2": testMethod{method: "example2"},
		}, PreferredOrder: []string{"example2", "example1"}}
		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(SubjectCreationOption{Subject: "subject1"}))
		require.NoError(t, err)
		_, _, err = m.Create(audit.TestContext(), DefaultCreationOptions().With(SubjectCreationOption{Subject: "subject2"}))
		require.NoError(t, err)

		result, err := m.List(audit.TestContext())

		require.NoError(t, err)
		require.Len(t, result, 2)
		assert.Contains(t, result, "subject1")
		assert.Len(t, result["subject1"], 2)
		assert.Contains(t, result, "subject2")
		assert.Len(t, result["subject2"], 2)

		t.Run("preferred order", func(t *testing.T) {
			assert.Equal(t, "example2", result["subject1"][0].Method)
			assert.Equal(t, "example1", result["subject1"][1].Method)
			assert.Equal(t, "example2", result["subject2"][0].Method)
			assert.Equal(t, "example1", result["subject2"][1].Method)
		})
	})
}

func TestManager_ListDIDs(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		db := testDB(t)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{
			"example1": testMethod{method: "example1"},
			"example2": testMethod{method: "example2"},
		}, PreferredOrder: []string{"example2", "example1"}}
		opts := DefaultCreationOptions().With(SubjectCreationOption{Subject: "subject"})
		_, subject, err := m.Create(audit.TestContext(), opts)
		require.NoError(t, err)

		dids, err := m.ListDIDs(audit.TestContext(), subject)

		require.NoError(t, err)
		assert.Len(t, dids, 2)
		t.Run("preferred order", func(t *testing.T) {
			assert.True(t, strings.HasPrefix(dids[0].String(), "did:example2:"))
			assert.True(t, strings.HasPrefix(dids[1].String(), "did:example1:"))
		})
	})
	t.Run("unknown subject", func(t *testing.T) {
		db := testDB(t)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{
			"example": testMethod{},
		}}

		_, err := m.ListDIDs(audit.TestContext(), "subject")

		require.ErrorIs(t, err, ErrSubjectNotFound)
	})
}

func TestManager_Create(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		db := testDB(t)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{"example": testMethod{}}}

		documents, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())

		require.NoError(t, err)
		require.Len(t, documents, 1)

		t.Run("check for empty did_change_log", func(t *testing.T) {
			didChangeLog := make([]orm.DIDChangeLog, 0)

			require.NoError(t, db.Find(&didChangeLog).Error)

			assert.Len(t, didChangeLog, 0)
		})
	})
	t.Run("multiple methods", func(t *testing.T) {
		db := testDB(t)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{
			"example": testMethod{},
			"test":    testMethod{method: "test"},
		}, PreferredOrder: []string{"test", "example"}}

		documents, _, err := m.Create(audit.TestContext(), DefaultCreationOptions())
		require.NoError(t, err)
		require.Len(t, documents, 2)
		IDs := make([]string, 2)
		for i, document := range documents {
			IDs[i] = document.ID.String()
		}
		assert.True(t, strings.HasPrefix(IDs[0], "did:test:"))
		assert.True(t, strings.HasPrefix(IDs[1], "did:example:"))
	})
	t.Run("with unknown option", func(t *testing.T) {
		db := testDB(t)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{"example": testMethod{}}}

		_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(""))

		require.Error(t, err)
		assert.ErrorIs(t, err, ErrSubjectValidation)
		assert.ErrorContains(t, err, "unknown option: string")
	})
	t.Run("already exists", func(t *testing.T) {
		db := testDB(t)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{"example": testMethod{}}}
		opts := DefaultCreationOptions().With(SubjectCreationOption{Subject: "subject"})
		_, _, err := m.Create(audit.TestContext(), opts)
		require.NoError(t, err)

		_, _, err = m.Create(audit.TestContext(), opts)

		require.ErrorIs(t, err, ErrSubjectAlreadyExists)
	})
	t.Run("subject validation", func(t *testing.T) {
		t.Run("empty", func(t *testing.T) {
			db := testDB(t)
			m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{
				"example": testMethod{},
			}}

			_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(SubjectCreationOption{Subject: ""}))

			require.Error(t, err)
			assert.ErrorIs(t, err, ErrSubjectValidation)
			assert.ErrorContains(t, err, "invalid subject (must follow pattern: ^[a-zA-Z0-9._-]+$)")
		})
		t.Run("contains allowed characters", func(t *testing.T) {
			db := testDB(t)
			m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{
				"example": testMethod{},
			}}

			_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(SubjectCreationOption{Subject: "subject_with-special.characters"}))

			assert.NoError(t, err)
		})
		t.Run("contains illegal character (space)", func(t *testing.T) {
			db := testDB(t)
			m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{
				"example": testMethod{},
			}}

			_, _, err := m.Create(audit.TestContext(), DefaultCreationOptions().With(SubjectCreationOption{Subject: "subject with space"}))

			require.Error(t, err)
			assert.ErrorIs(t, err, ErrSubjectValidation)
			assert.ErrorContains(t, err, "invalid subject (must follow pattern: ^[a-zA-Z0-9._-]+$)")
		})
	})
}

func TestManager_Services(t *testing.T) {
	db := testDB(t)
	m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{
		"example": testMethod{},
	}}
	subject := "subject"
	opts := DefaultCreationOptions().With(SubjectCreationOption{Subject: subject})
	documents, _, err := m.Create(audit.TestContext(), opts)

	require.NoError(t, err)
	require.Len(t, documents, 1)
	document := documents[0]

	t.Run("create", func(t *testing.T) {
		service := did.Service{Type: "test", ServiceEndpoint: "https://example.com"}

		services, err := m.CreateService(audit.TestContext(), subject, service)

		require.NoError(t, err)
		require.Len(t, services, 1)
		serviceID := services[0].ID
		assert.True(t, strings.HasPrefix(serviceID.String(), document.ID.String()))
		assert.Equal(t, "4zQgDc15kLf9pXbAUSeus7ERTC8UBeqDrBSys1S89why", serviceID.Fragment)
		t.Run("duplicate", func(t *testing.T) {
			services, err := m.FindServices(audit.TestContext(), subject, to.Ptr("test"))
			require.Len(t, services, 1)
			doc, err := NewDIDDocumentManager(db).Latest(document.ID, nil)
			require.NoError(t, err)
			version := doc.Version

			services, err = m.CreateService(audit.TestContext(), subject, service)

			require.NoError(t, err)
			// check for no change
			doc, err = NewDIDDocumentManager(db).Latest(document.ID, nil)
			require.NoError(t, err)
			assert.Equal(t, version, doc.Version)
		})
		t.Run("update", func(t *testing.T) {
			services, err := m.FindServices(audit.TestContext(), subject, to.Ptr("test"))
			require.Len(t, services, 1)
			newService := did.Service{Type: "test", ServiceEndpoint: "https://sub.example.com"}

			services, err = m.UpdateService(audit.TestContext(), subject, serviceID, newService)

			require.NoError(t, err)
			require.Len(t, services, 1)
			assert.NotEqual(t, "", services[0].ID.String())
			services, err = m.FindServices(audit.TestContext(), subject, to.Ptr("test"))
			require.Len(t, services, 1)
		})
		t.Run("delete", func(t *testing.T) {
			services, err := m.FindServices(audit.TestContext(), subject, to.Ptr("test"))
			require.Len(t, services, 1)

			err = m.DeleteService(audit.TestContext(), subject, services[0].ID)

			require.NoError(t, err)
			services, err = m.FindServices(audit.TestContext(), subject, to.Ptr("test"))
			require.Len(t, services, 0)
		})
	})
}

func TestManager_AddVerificationMethod(t *testing.T) {
	db := testDB(t)
	m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{"example": testMethod{}, "test": testMethod{}}}
	subject := "subject"
	opts := DefaultCreationOptions().With(SubjectCreationOption{Subject: subject})
	documents, _, err := m.Create(audit.TestContext(), opts)

	require.NoError(t, err)
	require.Len(t, documents, 2)

	t.Run("ok", func(t *testing.T) {
		vms, err := m.AddVerificationMethod(audit.TestContext(), subject, orm.AssertionKeyUsage())

		require.NoError(t, err)
		require.Len(t, vms, 2)
	})
}

func TestManager_Deactivate(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	ctx := audit.TestContext()

	t.Run("not found", func(t *testing.T) {
		db := testDB(t)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{"example": testMethod{}}}

		err := m.Deactivate(ctx, "subject")
		require.ErrorIs(t, err, ErrSubjectNotFound)
	})
	t.Run("ok", func(t *testing.T) {
		db := testDB(t)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{"example": testMethod{}}}
		documents, subject, err := m.Create(ctx, DefaultCreationOptions())
		require.NoError(t, err)
		require.Len(t, documents, 1)

		err = m.Deactivate(ctx, subject)
		require.NoError(t, err)
	})
	t.Run("error", func(t *testing.T) {
		db := testDB(t)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{"example": testMethod{}}}
		documents, subject, err := m.Create(ctx, DefaultCreationOptions())
		require.NoError(t, err)
		require.Len(t, documents, 1)

		m.MethodManagers["example"] = testMethod{error: assert.AnError}
		err = m.Deactivate(ctx, subject)
		assert.Error(t, err)
	})
}

func TestManager_rollback(t *testing.T) {
	didId := orm.DID{
		ID:      "did:example:123",
		Subject: "subject",
	}
	didDocument := orm.DidDocument{
		ID:        "1",
		DidID:     "did:example:123",
		UpdatedAt: time.Now().Add(-time.Hour).Unix(),
	}
	didChangeLog := orm.DIDChangeLog{
		DIDDocumentVersionID: "1",
		Type:                 "created",
		TransactionID:        "2",
	}
	saveExamples := func(t *testing.T, db *gorm.DB) {
		require.NoError(t, db.Save(&didId).Error)
		require.NoError(t, db.Save(&didDocument).Error)
		require.NoError(t, db.Save(&didChangeLog).Error)
	}

	t.Run("uncommited results in rollback", func(t *testing.T) {
		db := testDB(t)
		manager := SqlManager{DB: db, MethodManagers: map[string]MethodManager{"example": testMethod{}}}

		saveExamples(t, db)

		manager.Rollback(context.Background())

		// check removal of DIDChangeLog
		didChangeLog := make([]orm.DIDChangeLog, 0)
		require.NoError(t, db.Find(&didChangeLog).Error)
		assert.Len(t, didChangeLog, 0)

		// check removal of  DIDDocument
		didDocuments := make([]orm.DidDocument, 0)
		require.NoError(t, db.Find(&didDocuments).Error)
		assert.Len(t, didDocuments, 0)
	})
	t.Run("IsCommitted returns error", func(t *testing.T) {
		db := testDB(t)
		manager := SqlManager{DB: db,
			MethodManagers: map[string]MethodManager{
				"example": testMethod{error: assert.AnError},
			},
		}
		saveExamples(t, db)

		manager.Rollback(context.Background())

		// check existence of DIDChangeLog
		didChangeLog := make([]orm.DIDChangeLog, 0)
		require.NoError(t, db.Find(&didChangeLog).Error)
		assert.Len(t, didChangeLog, 1)

		// check existence of DIDDocument
		didDocuments := make([]orm.DidDocument, 0)
		require.NoError(t, db.Find(&didDocuments).Error)
		assert.Len(t, didDocuments, 1)
	})
	t.Run("commited by method removes changelog", func(t *testing.T) {
		db := testDB(t)
		manager := SqlManager{DB: db,
			MethodManagers: map[string]MethodManager{
				"example": testMethod{committed: true},
			},
		}
		saveExamples(t, db)

		manager.Rollback(context.Background())

		// check removal of DIDChangeLog
		didChangeLog := make([]orm.DIDChangeLog, 0)
		require.NoError(t, db.Find(&didChangeLog).Error)
		assert.Len(t, didChangeLog, 0)

		// check existence of DIDDocument
		didDocuments := make([]orm.DidDocument, 0)
		require.NoError(t, db.Find(&didDocuments).Error)
		assert.Len(t, didDocuments, 1)
	})
	t.Run("rollback removes all from transaction", func(t *testing.T) {
		db := testDB(t)
		manager := SqlManager{DB: db, MethodManagers: map[string]MethodManager{"example": testMethod{}}}
		saveExamples(t, db)
		didId2 := orm.DID{
			ID:      "did:example:321",
			Subject: "subject",
		}
		didDocument2 := orm.DidDocument{
			ID:        "2",
			DidID:     "did:example:321",
			UpdatedAt: time.Now().Add(-time.Hour).Unix(),
		}
		didChangeLog2 := orm.DIDChangeLog{
			DIDDocumentVersionID: "2",
			Type:                 "created",
			TransactionID:        "2",
		}
		require.NoError(t, db.Save(&didId2).Error)
		require.NoError(t, db.Save(&didDocument2).Error)
		require.NoError(t, db.Save(&didChangeLog2).Error)

		manager.Rollback(context.Background())

		// check removal of DIDChangeLog
		didChangeLog := make([]orm.DIDChangeLog, 0)
		require.NoError(t, db.Find(&didChangeLog).Error)
		assert.Len(t, didChangeLog, 0)

		// check removal of  DIDDocument
		didDocuments := make([]orm.DidDocument, 0)
		require.NoError(t, db.Find(&didDocuments).Error)
		assert.Len(t, didDocuments, 0)
	})
}

func TestNewIDForService(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/v1")
	expectedID := "D4eNCVjdtGaeHYMdjsdYHpTQmiwXtQKJmE9QSwwsKKzy"

	t.Run("ok", func(t *testing.T) {
		id := NewIDForService(did.Service{
			Type:            "type",
			ServiceEndpoint: u.String(),
		})
		assert.Equal(t, expectedID, id)
	})
	t.Run("id is ignored", func(t *testing.T) {
		service := did.Service{
			ID:              ssi.MustParseURI("ID-is-ignored"),
			Type:            "type",
			ServiceEndpoint: u.String(),
		}
		id := NewIDForService(service)
		assert.Equal(t, expectedID, id)
		assert.Equal(t, "ID-is-ignored", service.ID.String(), "input service should not change")
	})
}

type testMethod struct {
	committed bool
	error     error
	method    string
	document  *orm.DidDocument
}

func (t testMethod) NewDocument(_ context.Context, _ orm.DIDKeyFlags) (*orm.DidDocument, error) {
	if t.document != nil {
		return t.document, nil
	}
	method := t.method
	if method == "" {
		method = "example"
	}
	id := fmt.Sprintf("did:%s:%s", method, uuid.New().String())
	return &orm.DidDocument{DID: orm.DID{ID: id}}, t.error
}

func (t testMethod) NewVerificationMethod(_ context.Context, controller did.DID, _ orm.DIDKeyFlags) (*did.VerificationMethod, error) {
	return &did.VerificationMethod{
		ID: did.MustParseDIDURL(fmt.Sprintf("%s#%s", controller.String(), uuid.New().String())),
	}, t.error
}

func (t testMethod) Commit(_ context.Context, _ orm.DIDChangeLog) error {
	return t.error
}

func (t testMethod) IsCommitted(_ context.Context, _ orm.DIDChangeLog) (bool, error) {
	return t.committed, t.error
}

func Test_sortDIDDocumentsByMethod(t *testing.T) {
	documents := []did.Document{
		{ID: did.MustParseDID("did:example:1")},
		{ID: did.MustParseDID("did:test:1")},
	}

	sortDIDDocumentsByMethod(documents, []string{"test", "example"})

	require.Len(t, documents, 2)
	assert.Equal(t, "did:test:1", documents[0].ID.String())
	assert.Equal(t, "did:example:1", documents[1].ID.String())
}

func TestSqlManager_MigrateDIDHistoryToSQL(t *testing.T) {
	testDID := did.MustParseDID("did:nuts:test")
	vmID := did.MustParseDIDURL("did:nuts:test#key-1")
	key, _ := spi.GenerateKeyPair()
	vm, err := did.NewVerificationMethod(vmID, ssi.JsonWebKey2020, testDID, key.Public())
	require.NoError(t, err)
	service := did.Service{
		ID:              ssi.MustParseURI(testDID.String() + "#service-1"),
		Type:            "test",
		ServiceEndpoint: "https://example.com",
	}
	created := time.Now().Add(-5 * time.Second)
	subject := "test-subject"

	rawDocNew, err := json.Marshal(did.Document{ID: testDID, CapabilityInvocation: []did.VerificationRelationship{{VerificationMethod: vm}}, VerificationMethod: did.VerificationMethods{vm}})
	require.NoError(t, err)
	rawDocUpdate, _ := json.Marshal(did.Document{ID: testDID, Service: []did.Service{service}, CapabilityInvocation: []did.VerificationRelationship{{VerificationMethod: vm}}})
	rawDocDeactivate, _ := json.Marshal(did.Document{ID: testDID})
	ormMigrateNew := orm.MigrationDocument{Raw: rawDocNew, Created: created, Updated: created, Version: 0}
	ormMigrateUpdate := orm.MigrationDocument{Raw: rawDocUpdate, Created: created, Updated: created.Add(2 * time.Second), Version: 1}
	ormMigrateDeactivate := orm.MigrationDocument{Raw: rawDocDeactivate, Created: created, Updated: created.Add(2 * time.Second), Version: 1}
	ormDocNew, err := ormMigrateNew.ToORMDocument(subject)
	require.NoError(t, err)
	ormDocUpdate, _ := ormMigrateUpdate.ToORMDocument(subject)
	ormDocDeactivate, _ := ormMigrateDeactivate.ToORMDocument(subject)
	equal := func(t *testing.T, o1, o2 orm.DidDocument) {
		//assert.NotEqual(t, o1.ID, o2.ID) // ToORMDocument generates a random ID everytime. Should probably be ignored.
		assert.Equal(t, o1.DidID, o2.DidID)
		assert.Equal(t, o1.DID, o2.DID)
		assert.Equal(t, o1.CreatedAt, o2.CreatedAt)
		assert.Equal(t, o1.UpdatedAt, o2.UpdatedAt)
		assert.Equal(t, o1.Version, o2.Version)
		assert.Equal(t, o1.VerificationMethods, o2.VerificationMethods)
		assert.Equal(t, o1.Services, o2.Services)
		assert.Equal(t, o1.Raw, o2.Raw)
	}
	t.Run("create", func(t *testing.T) {
		db := storage.NewTestStorageEngine(t).GetSQLDatabase()
		manager := SqlManager{DB: db}

		err = manager.MigrateDIDHistoryToSQL(testDID, subject, func(id did.DID, sinceVersion int) ([]orm.MigrationDocument, error) {
			assert.Equal(t, testDID, id)
			assert.Equal(t, 0, sinceVersion)
			return []orm.MigrationDocument{ormMigrateNew, ormMigrateUpdate}, nil
		})
		require.NoError(t, err)

		// version 0
		ormDoc, err := NewDIDDocumentManager(db).Latest(testDID, &created)
		require.NoError(t, err)
		equal(t, *ormDoc, ormDocNew)
		// version 1
		ormDoc, err = NewDIDDocumentManager(db).Latest(testDID, nil)
		require.NoError(t, err)
		equal(t, *ormDoc, ormDocUpdate)
	})
	t.Run("update", func(t *testing.T) {
		db := storage.NewTestStorageEngine(t).GetSQLDatabase()
		manager := SqlManager{DB: db}

		// init version 0
		err = manager.MigrateDIDHistoryToSQL(testDID, subject, func(id did.DID, sinceVersion int) ([]orm.MigrationDocument, error) {
			assert.Equal(t, 0, sinceVersion)
			return []orm.MigrationDocument{ormMigrateNew}, nil
		})
		require.NoError(t, err)
		ormDoc, err := NewDIDDocumentManager(db).Latest(testDID, nil)
		require.NoError(t, err)
		equal(t, *ormDoc, ormDocNew)

		// update to version 1
		err = manager.MigrateDIDHistoryToSQL(testDID, subject, func(id did.DID, sinceVersion int) ([]orm.MigrationDocument, error) {
			assert.Equal(t, 1, sinceVersion)
			return []orm.MigrationDocument{ormMigrateUpdate}, nil
		})
		require.NoError(t, err)
		ormDoc, err = NewDIDDocumentManager(db).Latest(testDID, nil)
		require.NoError(t, err)
		equal(t, *ormDoc, ormDocUpdate)
	})
	t.Run("deactivate", func(t *testing.T) {
		db := storage.NewTestStorageEngine(t).GetSQLDatabase()
		manager := SqlManager{DB: db}

		// create in version 0, deactivate in version 1
		err = manager.MigrateDIDHistoryToSQL(testDID, subject, func(id did.DID, sinceVersion int) ([]orm.MigrationDocument, error) {
			return []orm.MigrationDocument{ormMigrateNew, ormMigrateDeactivate}, nil
		})
		require.NoError(t, err)
		ormDoc, err := NewDIDDocumentManager(db).Latest(testDID, nil)
		require.NoError(t, err)
		equal(t, *ormDoc, ormDocDeactivate)

		// don't update deactivated document
		assert.NotPanics(t, func() {
			_ = manager.MigrateDIDHistoryToSQL(testDID, subject, func(id did.DID, sinceVersion int) ([]orm.MigrationDocument, error) {
				panic("function should not be called")
			})
		})
	})
	t.Run("error - getHistory", func(t *testing.T) {
		db := storage.NewTestStorageEngine(t).GetSQLDatabase()
		manager := SqlManager{DB: db}
		err = manager.MigrateDIDHistoryToSQL(testDID, subject, func(id did.DID, sinceVersion int) ([]orm.MigrationDocument, error) {
			return nil, errors.New("test")
		})
		assert.EqualError(t, err, "test")
	})
}

func TestSqlManager_MigrateAddWebToNuts(t *testing.T) {
	didNuts := did.MustParseDID("did:nuts:test")
	didWeb := did.MustParseDID("did:web:example.com")
	nutsDoc := generateTestORMDoc(t, didNuts, didNuts.String(), true)
	webDoc := generateTestORMDoc(t, didWeb, didNuts.String(), false) // don't add service to check it gets migrated properly

	var err error
	auditContext := audit.Context(context.Background(), "system", "VDR", "migrate_add_did:web_to_did:nuts")

	t.Run("ok", func(t *testing.T) {
		db := testDB(t)
		_, err = NewDIDDocumentManager(db).CreateOrUpdate(nutsDoc.DID, nutsDoc.VerificationMethods, nutsDoc.Services)
		require.NoError(t, err)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{
			"web": testMethod{document: &webDoc},
		}, PreferredOrder: []string{"web"}}

		// create did:web
		err = m.MigrateAddWebToNuts(auditContext, didNuts)
		assert.NoError(t, err)

		dids, err := NewDIDManager(db).FindBySubject(didNuts.String())
		assert.NoError(t, err)
		require.Len(t, dids, 2)
		assert.Equal(t, didNuts.String(), dids[0].ID)
		assert.Equal(t, didWeb.String(), dids[1].ID)

		require.NoError(t, err)
		docWeb, err := NewDIDDocumentManager(db).Latest(didWeb, nil)
		require.NoError(t, err)
		assert.Len(t, docWeb.Services, 0)
	})
	t.Run("ok - already has did:web", func(t *testing.T) {
		db := testDB(t)
		_, err = NewDIDDocumentManager(db).CreateOrUpdate(nutsDoc.DID, nutsDoc.VerificationMethods, nutsDoc.Services)
		require.NoError(t, err)
		m := SqlManager{DB: db, MethodManagers: map[string]MethodManager{
			"web": testMethod{document: &webDoc},
		}, PreferredOrder: []string{"web"}}

		// migration 1; create did:web
		err = m.MigrateAddWebToNuts(auditContext, didNuts)
		assert.NoError(t, err)

		dids, err := NewDIDManager(db).FindBySubject(didNuts.String())
		assert.NoError(t, err)
		require.Len(t, dids, 2)

		// migration 2; already has a did:web
		err = m.MigrateAddWebToNuts(auditContext, didNuts)
		assert.NoError(t, err)

		dids2, err := NewDIDManager(db).FindBySubject(didNuts.String())
		assert.NoError(t, err)
		require.Len(t, dids2, 2)
		assert.Equal(t, dids, dids2)
	})
	t.Run("ok - deactivated", func(t *testing.T) {
		db := testDB(t)
		_, err = NewDIDDocumentManager(db).CreateOrUpdate(nutsDoc.DID, nil, nil)
		require.NoError(t, err)
		m := SqlManager{DB: db}

		// migrate is a noop
		err = m.MigrateAddWebToNuts(auditContext, didNuts)
		assert.NoError(t, err)

		dids, err := NewDIDManager(db).FindBySubject(didNuts.String())
		assert.NoError(t, err)
		require.Len(t, dids, 1)
		assert.Equal(t, didNuts.String(), dids[0].ID)
	})
	t.Run("error - did not found", func(t *testing.T) {
		db := testDB(t)
		m := SqlManager{DB: db}

		// empty db
		err = m.MigrateAddWebToNuts(auditContext, didNuts)

		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})
	t.Run("error - doc not found", func(t *testing.T) {
		db := testDB(t)
		storage.AddDIDtoSQLDB(t, db, didNuts) // only add did, not the doc
		m := SqlManager{DB: db}

		// migrate is a noop
		err = m.MigrateAddWebToNuts(auditContext, didNuts)

		assert.ErrorIs(t, err, gorm.ErrRecordNotFound)
	})
}

func generateTestORMDoc(t *testing.T, id did.DID, subject string, addService bool) orm.DidDocument {
	// verification method
	vmID := did.MustParseDIDURL(id.String() + "#key-1")
	key, _ := spi.GenerateKeyPair()
	vm, err := did.NewVerificationMethod(vmID, ssi.JsonWebKey2020, id, key.Public())
	require.NoError(t, err)
	// service
	var service did.Service
	if addService {
		service = did.Service{
			ID:              ssi.MustParseURI(id.String() + "#service-1"),
			Type:            "test",
			ServiceEndpoint: "https://example.com",
		}
	}
	// generate and parse document
	didDoc := did.Document{ID: id, VerificationMethod: did.VerificationMethods{vm}, CapabilityInvocation: []did.VerificationRelationship{{VerificationMethod: vm}}, Service: []did.Service{service}}
	rawDoc, err := json.Marshal(didDoc)
	require.NoError(t, err)
	now := time.Now()
	ormDoc, err := orm.MigrationDocument{Raw: rawDoc, Created: now, Updated: now, Version: 0}.ToORMDocument(subject)
	require.NoError(t, err)
	return ormDoc
}
