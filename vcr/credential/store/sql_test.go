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

package store

import (
	"encoding/json"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
	"testing"
)

var vcAlice vc.VerifiableCredential
var vcBob vc.VerifiableCredential
var vcOrganization vc.VerifiableCredential
var personIssuer = ssi.MustParseURI("https://example.com/mayor")
var organizationIssuer = ssi.MustParseURI("https://example.com/chamber-of-commerce")

func init() {
	vcAlice = createPersonCredential("1", "did:example:alice", map[string]interface{}{
		"givenName":  "Alice",
		"familyName": "Jones",
	})
	vcBob = createPersonCredential("2", "did:example:bob", map[string]interface{}{
		"givenName":  "Bob",
		"familyName": "Jomper",
	})
	vcOrganization = vc.VerifiableCredential{
		Issuer: organizationIssuer,
		CredentialSubject: []interface{}{
			credential.NutsOrganizationCredentialSubject{
				ID:           "did:example:org",
				Organization: map[string]string{"name": "Example Corp"},
			},
		},
	}
	vcOrganization.ID, _ = ssi.ParseURI("3")
}

func TestCredentialStore_Store(t *testing.T) {
	logrus.SetLevel(logrus.DebugLevel)
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})
	db := storageEngine.GetSQLDatabase()

	t.Run("ok - CredentialSubject struct", func(t *testing.T) {
		setupStore(t, storageEngine.GetSQLDatabase())
		_, err := CredentialStore{}.Store(storageEngine.GetSQLDatabase(), vcOrganization)
		assert.NoError(t, err)
	})
	t.Run("duplicate credential.ID", func(t *testing.T) {
		setupStore(t, storageEngine.GetSQLDatabase())
		vcEve := createPersonCredential("66", "did:example:eve", map[string]interface{}{
			"givenName":  "Evil",
			"familyName": "Mastermind",
		})
		vcEve2 := createPersonCredential("66", "did:example:eve", map[string]interface{}{
			"givenName":  "Eviler",
			"familyName": "Mastermind",
		})
		_, err := CredentialStore{}.Store(storageEngine.GetSQLDatabase(), vcEve)
		require.NoError(t, err)
		_, err = CredentialStore{}.Store(storageEngine.GetSQLDatabase(), vcEve2)
		require.EqualError(t, err, "credential with this ID already exists with different contents: 66")
	})
	t.Run("with indexable properties in credential", func(t *testing.T) {
		setupStore(t, storageEngine.GetSQLDatabase())
		_, err := CredentialStore{}.Store(storageEngine.GetSQLDatabase(), vcAlice)
		require.NoError(t, err)
		var actual []CredentialPropertyRecord

		assert.NoError(t, db.Find(&actual).Error)

		require.Len(t, actual, 2)
		assert.Equal(t, "Alice", sliceToMap(actual)["credentialSubject.person.givenName"])
		assert.Equal(t, "Jones", sliceToMap(actual)["credentialSubject.person.familyName"])
	})
	t.Run("with non-indexable properties in credential", func(t *testing.T) {
		setupStore(t, storageEngine.GetSQLDatabase())
		_, err := CredentialStore{}.Store(storageEngine.GetSQLDatabase(), createPersonCredential("1", "did:example:alice", map[string]interface{}{
			"givenName": "Alice",
			"age":       35,
		}))
		assert.NoError(t, err)

		var actual []CredentialPropertyRecord
		assert.NoError(t, db.Find(&actual).Error)
		require.Len(t, actual, 1)
		assert.Equal(t, "Alice", sliceToMap(actual)["credentialSubject.person.givenName"])
	})
	t.Run("without indexable properties in credential", func(t *testing.T) {
		setupStore(t, storageEngine.GetSQLDatabase())
		_, err := CredentialStore{}.Store(storageEngine.GetSQLDatabase(), createPersonCredential("1", "did:example:alice", nil))
		assert.NoError(t, err)

		var actual []CredentialPropertyRecord
		assert.NoError(t, db.Find(&actual).Error)
		assert.Empty(t, actual)
	})
}

func sliceToMap(slice []CredentialPropertyRecord) map[string]string {
	var result = make(map[string]string)
	for _, curr := range slice {
		result[curr.Path] = curr.Value
	}
	return result
}

func TestCredentialStore_BuildSearchStatement(t *testing.T) {
	storageEngine := storage.NewTestStorageEngine(t)
	require.NoError(t, storageEngine.Start())
	t.Cleanup(func() {
		_ = storageEngine.Shutdown()
	})
	db := storageEngine.GetSQLDatabase()

	type testCase struct {
		name        string
		inputVCs    []vc.VerifiableCredential
		query       map[string]string
		expectedVCs []string
	}
	testCases := []testCase{
		{
			name:     "issuer",
			inputVCs: []vc.VerifiableCredential{vcAlice},
			query: map[string]string{
				"issuer": personIssuer.String(),
			},
			expectedVCs: []string{vcAlice.ID.String()},
		},
		{
			name:     "id",
			inputVCs: []vc.VerifiableCredential{vcAlice},
			query: map[string]string{
				"id": vcAlice.ID.String(),
			},
			expectedVCs: []string{vcAlice.ID.String()},
		},
		{
			name:     "type",
			inputVCs: []vc.VerifiableCredential{vcAlice},
			query: map[string]string{
				"type": "PersonCredential",
			},
			expectedVCs: []string{vcAlice.ID.String()},
		},
		{
			name:     "credentialSubject.id",
			inputVCs: []vc.VerifiableCredential{vcAlice, vcBob},
			query: map[string]string{
				"credentialSubject.id": "did:example:alice",
			},
			expectedVCs: []string{vcAlice.ID.String()},
		},
		{
			name:     "1 property",
			inputVCs: []vc.VerifiableCredential{vcAlice, vcBob},
			query: map[string]string{
				"credentialSubject.person.givenName": "Alice",
			},
			expectedVCs: []string{vcAlice.ID.String()},
		},
		{
			name:     "2 properties",
			inputVCs: []vc.VerifiableCredential{vcAlice},
			query: map[string]string{
				"credentialSubject.person.givenName":  "Alice",
				"credentialSubject.person.familyName": "Jones",
			},
			expectedVCs: []string{vcAlice.ID.String()},
		},
		{
			name:     "properties and base properties",
			inputVCs: []vc.VerifiableCredential{vcAlice},
			query: map[string]string{
				"issuer":                             personIssuer.String(),
				"credentialSubject.person.givenName": "Alice",
			},
			expectedVCs: []string{vcAlice.ID.String()},
		},
		{
			name:     "wildcard postfix",
			inputVCs: []vc.VerifiableCredential{vcAlice, vcBob},
			query: map[string]string{
				"credentialSubject.person.familyName": "Jo*",
			},
			expectedVCs: []string{vcAlice.ID.String(), vcBob.ID.String()},
		},
		{
			name:     "wildcard prefix",
			inputVCs: []vc.VerifiableCredential{vcAlice, vcBob},
			query: map[string]string{
				"credentialSubject.person.givenName": "*ce",
			},
			expectedVCs: []string{vcAlice.ID.String()},
		},
		{
			name:     "wildcard midway (no interpreted as wildcard)",
			inputVCs: []vc.VerifiableCredential{vcAlice, vcBob},
			query: map[string]string{
				"credentialSubject.person.givenName": "A*ce",
			},
			expectedVCs: []string{},
		},
		{
			name:     "just wildcard",
			inputVCs: []vc.VerifiableCredential{vcAlice, vcBob},
			query: map[string]string{
				"id": "*",
			},
			expectedVCs: []string{vcAlice.ID.String(), vcBob.ID.String()},
		},
		{
			name:     "2 VPs, 1 match",
			inputVCs: []vc.VerifiableCredential{vcAlice, vcBob},
			query: map[string]string{
				"credentialSubject.person.givenName": "Alice",
			},
			expectedVCs: []string{vcAlice.ID.String()},
		},
		{
			name:     "multiple matches",
			inputVCs: []vc.VerifiableCredential{vcAlice, vcBob},
			query: map[string]string{
				"issuer": personIssuer.String(),
			},
			expectedVCs: []string{vcAlice.ID.String(), vcBob.ID.String()},
		},
		{
			name:     "no match",
			inputVCs: []vc.VerifiableCredential{vcAlice},
			query: map[string]string{
				"credentialSubject.person.givenName": "Bob",
			},
			expectedVCs: []string{},
		},
		{
			name: "empty database",
			query: map[string]string{
				"credentialSubject.person.givenName": "Bob",
			},
			expectedVCs: []string{},
		},
	}

	store := CredentialStore{}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setupStore(t, storageEngine.GetSQLDatabase())
			for _, credential := range tc.inputVCs {
				err := db.Transaction(func(tx *gorm.DB) error {
					credentialRecord, err := store.Store(tx, credential)
					if err != nil {
						return err
					}
					return tx.Create(&testCredential{
						ID: credentialRecord.ID,
					}).Error
				})
				require.NoError(t, err)
			}
			var actualVCs []testCredential
			stmt := db.Model(&testCredential{})
			err := store.BuildSearchStatement(stmt, "test_credential.id", tc.query).
				Preload("Credential").
				Find(&actualVCs).Error
			require.NoError(t, err)
			require.Len(t, actualVCs, len(tc.expectedVCs))
			for _, expectedVC := range tc.expectedVCs {
				found := false
				for _, actualVC := range actualVCs {
					if actualVC.Credential.ID == expectedVC {
						found = true
						break
					}
				}
				require.True(t, found, "expected to find VC with ID %s", expectedVC)
			}
		})
	}
}

var _ schema.Tabler = testCredential{}

// testCredential is a Gorm DTO for the test_credential table.
// There's no point a sole 'credential' existing in the database without being referred to by a feature/role,
// e.g. credential issuer (issued credential), wallet (stored credential), discovery service (registered credentials), etc.
// testCredential fills that role in the context of the tests.
type testCredential struct {
	ID         string           `gorm:"primaryKey"`
	Credential CredentialRecord `gorm:"foreignKey:ID;references:ID"`
}

func (t testCredential) TableName() string {
	return "test_credential"
}

func setupStore(t *testing.T, db *gorm.DB) {
	// related tables are emptied due to on-delete-cascade clause
	require.NoError(t, db.Exec("DELETE FROM credential").Error)
	require.NoError(t, db.Exec("DROP TABLE IF EXISTS test_credential").Error)
	require.NoError(t, db.Exec("CREATE TABLE test_credential (id VARCHAR(500) NOT NULL PRIMARY KEY)").Error)
}

func createPersonCredential(id string, subjectID string, properties map[string]interface{}) vc.VerifiableCredential {
	parsedID := ssi.MustParseURI(id)
	cred := vc.VerifiableCredential{
		ID:     &parsedID,
		Issuer: personIssuer,
		Type:   []ssi.URI{ssi.MustParseURI("PersonCredential")},
		CredentialSubject: []interface{}{
			map[string]interface{}{
				"id":     subjectID,
				"person": properties,
			},
		},
	}
	data, _ := cred.MarshalJSON()
	_ = json.Unmarshal(data, &cred)
	return cred
}
