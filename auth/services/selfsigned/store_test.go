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

package selfsigned

import (
	"github.com/nuts-foundation/nuts-node/auth/services/selfsigned/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewMemorySessionStore(t *testing.T) {
	store := NewMemorySessionStore()
	memStore := store.(*memorySessionStore)
	assert.NotNil(t, memStore.sessions)
}

func Test_memorySessionStore_CheckAndSetStatus(t *testing.T) {
	t.Run("ok - session has expected status", func(t *testing.T) {
		store := NewMemorySessionStore()
		memStore := store.(*memorySessionStore)
		memStore.sessions["sessionID"] = types.Session{Status: "expectedStatus"}
		ok := store.CheckAndSetStatus("sessionID", "expectedStatus", "newStatus")
		assert.True(t, ok)
		assert.Equal(t, "newStatus", memStore.sessions["sessionID"].Status)
	})

	t.Run("fail - session has not expected status", func(t *testing.T) {
		store := NewMemorySessionStore()
		memStore := store.(*memorySessionStore)
		memStore.sessions["sessionID"] = types.Session{Status: "unexpectedStatus"}
		ok := store.CheckAndSetStatus("sessionID", "expectedStatus", "newStatus")
		assert.False(t, ok)
		assert.Equal(t, "unexpectedStatus", memStore.sessions["sessionID"].Status)
	})

	t.Run("fail - session does not exist", func(t *testing.T) {
		store := NewMemorySessionStore()
		ok := store.CheckAndSetStatus("sessionID", "expectedStatus", "newStatus")
		assert.False(t, ok)
	})
}

func Test_memorySessionStore_Delete(t *testing.T) {
	t.Run("ok - session exists", func(t *testing.T) {
		store := NewMemorySessionStore()
		memStore := store.(*memorySessionStore)
		memStore.sessions["sessionID"] = types.Session{}
		store.Delete("sessionID")
		_, ok := memStore.sessions["sessionID"]
		assert.False(t, ok)
	})

	t.Run("ok - session does not exist", func(t *testing.T) {
		store := NewMemorySessionStore()
		store.Delete("sessionID")

		memStore := store.(*memorySessionStore)
		_, ok := memStore.sessions["sessionID"]
		assert.False(t, ok)
	})
}

func Test_memorySessionStore_Load(t *testing.T) {
	t.Run("ok - session exists", func(t *testing.T) {
		store := NewMemorySessionStore()
		memStore := store.(*memorySessionStore)
		expectedSession := types.Session{Status: "expectedStatus"}
		memStore.sessions["sessionID"] = expectedSession
		session, ok := store.Load("sessionID")
		assert.True(t, ok)
		assert.Equal(t, expectedSession, session)
		assert.False(t, &expectedSession == &session, "should be a copy")
	})

	t.Run("fail - session does not exist", func(t *testing.T) {
		store := NewMemorySessionStore()
		session, ok := store.Load("sessionID")
		assert.False(t, ok)
		assert.Equal(t, types.Session{}, session)
	})
}

func Test_memorySessionStore_Store(t *testing.T) {
	t.Run("ok - session does not exist", func(t *testing.T) {
		store := NewMemorySessionStore()
		memStore := store.(*memorySessionStore)
		session := types.Session{Status: "expectedStatus"}
		store.Store("sessionID", session)
		assert.Equal(t, session, memStore.sessions["sessionID"])
	})

	t.Run("ok - session overwrites existing", func(t *testing.T) {
		store := NewMemorySessionStore()
		memStore := store.(*memorySessionStore)
		memStore.sessions["sessionID"] = types.Session{Status: "expectedStatus"}
		newSession := types.Session{Status: "newStatus"}
		store.Store("sessionID", newSession)
		assert.Equal(t, newSession, memStore.sessions["sessionID"])
	})
}
