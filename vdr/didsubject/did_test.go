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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSqlDIDManager_Add(t *testing.T) {
	manager := NewDIDManager(transaction(t, testDB(t)))

	added, err := manager.Add("alice", alice)
	assert.NoError(t, err)
	assert.NotNil(t, added)
	assert.Equal(t, "alice", added.Subject)
	assertLen(t, manager.tx, 1)
}

func TestSqlDIDManager_All(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		manager := NewDIDManager(transaction(t, testDB(t)))

		_, err := manager.Add("alice", alice)
		require.NoError(t, err)
		dids, err := manager.All()
		require.NoError(t, err)

		require.Len(t, dids, 1)
		assert.Equal(t, alice.String(), dids[0].ID)
	})
	t.Run("not found", func(t *testing.T) {
		manager := NewDIDManager(transaction(t, testDB(t)))

		dids, err := manager.All()
		require.NoError(t, err)

		require.Len(t, dids, 0)
	})
}

func TestSqlDIDManager_Delete(t *testing.T) {
	manager := NewDIDManager(transaction(t, testDB(t)))

	_, err := manager.Add("alice", alice)
	require.NoError(t, err)
	err = manager.Delete(alice)
	assert.NoError(t, err)
	assertLen(t, manager.tx, 0)
}

func TestSqlDIDManager_DeleteAll(t *testing.T) {
	manager := NewDIDManager(transaction(t, testDB(t)))

	_, err := manager.Add("alice", alice)
	require.NoError(t, err)
	err = manager.DeleteAll("alice")
	assert.NoError(t, err)
	assertLen(t, manager.tx, 0)
}

func TestSqlDIDManager_Find(t *testing.T) {
	manager := NewDIDManager(transaction(t, testDB(t)))
	_, err := manager.Add("alice", alice)
	require.NoError(t, err)

	t.Run("found", func(t *testing.T) {
		did, err := manager.Find(alice)
		require.NoError(t, err)

		assert.Equal(t, alice.String(), did.ID)
	})
	t.Run("not found", func(t *testing.T) {
		did, err := manager.Find(bob)
		require.NoError(t, err)
		assert.Nil(t, did)
	})
	t.Run("loads aliases", func(t *testing.T) {
		_, err := manager.Add("alice", bob)
		require.NoError(t, err)

		did, err := manager.Find(alice)
		require.NoError(t, err)

		require.Len(t, did.Aka, 2)

	})
}

func TestSqlDIDManager_FindBySubject(t *testing.T) {
	manager := NewDIDManager(transaction(t, testDB(t)))
	_, err := manager.Add("alice", alice)
	require.NoError(t, err)

	t.Run("ok", func(t *testing.T) {
		dids, err := manager.FindBySubject("alice")
		require.NoError(t, err)

		require.Len(t, dids, 1)
		assert.Equal(t, alice.String(), dids[0].ID)
	})
	t.Run("loads aliases", func(t *testing.T) {
		_, err := manager.Add("alice", bob)
		require.NoError(t, err)

		dids, err := manager.FindBySubject("alice")
		require.NoError(t, err)

		require.Len(t, dids, 2)
		a := dids[0]
		require.Len(t, a.Aka, 2)
	})
}
