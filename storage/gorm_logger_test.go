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

package storage

import (
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"testing"
	"time"
)

func Test_gormLogrusLogger_Trace(t *testing.T) {
	hook := &test.Hook{}
	underlying := logrus.New()
	underlying.SetLevel(logrus.TraceLevel)
	underlying.AddHook(hook)
	logger := gormLogrusLogger{
		underlying:    underlying.WithFields(nil),
		slowThreshold: 10 * time.Second,
	}
	now := time.Now()
	nowFunc = func() time.Time {
		return now
	}
	t.Run("execution error", func(t *testing.T) {
		defer hook.Reset()
		logger.Trace(nil, now.Add(-time.Second), func() (sql string, rowsAffected int64) {
			return "SELECT 1", 0
		}, assert.AnError)
		require.Len(t, hook.Entries, 1)
		assert.Equal(t, hook.LastEntry().Message, "Query failed (took 1s): SELECT 1")
	})
	t.Run("normal query", func(t *testing.T) {
		defer hook.Reset()
		logger.Trace(nil, now.Add(-time.Second), func() (sql string, rowsAffected int64) {
			return "SELECT 1", 0
		}, nil)
		require.Len(t, hook.Entries, 1)
		assert.Equal(t, hook.LastEntry().Message, "Query (took 1s): SELECT 1")
	})
	t.Run("record not found (error is ignored)", func(t *testing.T) {
		defer hook.Reset()
		logger.Trace(nil, now.Add(-time.Second), func() (sql string, rowsAffected int64) {
			return "SELECT 1", 0
		}, gorm.ErrRecordNotFound)
		require.Len(t, hook.Entries, 1)
		assert.Equal(t, hook.LastEntry().Message, "Query (took 1s): SELECT 1")
	})
	t.Run("slow query", func(t *testing.T) {
		defer hook.Reset()
		logger.Trace(nil, now.Add(-20*time.Second), func() (sql string, rowsAffected int64) {
			return "SELECT 1", 0
		}, nil)
		require.Len(t, hook.Entries, 1)
		assert.Equal(t, hook.LastEntry().Message, "Slow query (took 20s): SELECT 1")
	})
}
