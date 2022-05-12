/*
 * Copyright (C) 2021 Nuts community
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

package grpc

import (
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/test/io"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBoundedRandomBackoff_Backoff(t *testing.T) {
	b := defaultBackoff().(*boundedRandomBackoff)
	// Initially the backoff should be min-backoff
	assert.Equal(t, b.min, b.Backoff())

	var current time.Duration = 0
	for current < b.max {
		current = b.Backoff()
	}
}

func TestBoundedRandomBackoff_Reset(t *testing.T) {
	b := defaultBackoff().(*boundedRandomBackoff)
	b.Backoff()
	assert.True(t, b.Backoff() > b.min)
	b.Reset(0)
	assert.Equal(t, b.min, b.Backoff())
}

func TestBoundedRandomBackoff_DefaultValues(t *testing.T) {
	b := defaultBackoff().(*boundedRandomBackoff)
	assert.Equal(t, time.Second, b.min)
	assert.Equal(t, time.Hour, b.max)
}

func TestPersistedBackoff_Backoff(t *testing.T) {
	t.Run("read persisted backoff", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		nowFunc = func() time.Time {
			return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		}

		// Create back-off
		db, _ := storage.CreateBBoltStore(path.Join(testDirectory, "backoff.db"))
		defer db.Close()
		b := NewPersistedBackoff(db, "test", defaultBackoff())

		// Do some back-off
		var prev time.Duration
		for i := 0; i < 5; i++ {
			b := b.Backoff()
			assert.True(t, b > prev)
			prev = b
		}

		// Re-open back-off, check if started from the same point
		_ = db.Close()
		db, _ = storage.CreateBBoltStore(path.Join(testDirectory, "backoff.db"))
		defer db.Close()
		b = NewPersistedBackoff(db, "test", defaultBackoff())
		assert.Equal(t, int(prev.Seconds()), int(b.Value().Seconds()))
		backoffAfterPersist := b.Backoff()
		assert.Truef(t, backoffAfterPersist > prev, "%s should be greater than %s", backoffAfterPersist, prev)
	})
	t.Run("persisted max backoff", func(t *testing.T) {
		testDirectory := io.TestDirectory(t)
		initialDate := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		maxBackoff := defaultBackoff().(*boundedRandomBackoff).max
		nowFunc = func() time.Time {
			return initialDate
		}

		// Create back-off
		db, _ := storage.CreateBBoltStore(path.Join(testDirectory, "backoff.db"))
		defer db.Close()
		b := NewPersistedBackoff(db, "test", defaultBackoff())

		// Set backoff to
		b.Reset(maxBackoff)

		// Re-open back-off, simulate half of the max back-off time has passed
		// So the initial back-off should be half of the max back-off, but the subsequent back-off should be the max back-off again
		nowFunc = func() time.Time {
			return initialDate.Add(maxBackoff / 2)
		}
		_ = db.Close()
		db, _ = storage.CreateBBoltStore(path.Join(testDirectory, "backoff.db"))
		defer db.Close()
		b = NewPersistedBackoff(db, "test", defaultBackoff())
		assert.Equal(t, maxBackoff / 2, b.Value())
		assert.Equal(t, maxBackoff, b.Backoff())
	})
}

func TestPersistedBackoff_Reset(t *testing.T) {
	testDirectory := io.TestDirectory(t)

	// Create back-off
	db, _ := storage.CreateBBoltStore(path.Join(testDirectory, "backoff.db"))
	defer db.Close()
	b := NewPersistedBackoff(db, "test", defaultBackoff())

	// Do some back-off
	for i := 0; i < 5; i++ {
		_ = b.Backoff()
	}
	assert.True(t, b.Value() > 0)
	b.Reset(0)

	// Re-open back-off, check if 0 due to reset
	_ = db.Close()
	db, _ = storage.CreateBBoltStore(path.Join(testDirectory, "backoff.db"))
	defer db.Close()
	b = NewPersistedBackoff(db, "test", defaultBackoff())
	backoffAfterPersist := b.Value()
	assert.Equal(t, time.Duration(0), backoffAfterPersist)
}

func TestRandomBackoff(t *testing.T) {
	for i := 0; i < 100; i++ {
		const min = time.Second
		const max = 10 * time.Second
		val := RandomBackoff(min, max)
		assert.True(t, val >= min && val <= max)
	}
}
