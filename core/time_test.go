/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package core

import (
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRFC3339Time_MarshalText(t *testing.T) {
	t1 := RFC3339Time{time.Date(2020, 1, 1, 12, 30, 0, 0, time.UTC)}
	s, err := json.Marshal(t1)
	require.NoError(t, err)
	assert.Equal(t, "\"2020-01-01T12:30:00Z\"", string(s))
}

func TestRFC3339Time_UnmarshalJSON(t *testing.T) {
	t1 := RFC3339Time{time.Date(2020, 1, 1, 12, 30, 0, 0, time.UTC)}
	j := "2020-01-01T12:30:00Z"
	rfc := &RFC3339Time{}
	err := rfc.UnmarshalJSON([]byte(j))
	require.NoError(t, err)
	assert.Equal(t, t1, *rfc)
}

func TestPeriod_Contains(t *testing.T) {
	t5 := time.Unix(5, 0)
	t10 := time.Unix(10, 0)
	t15 := time.Unix(15, 0)
	t20 := time.Unix(20, 0)

	open := Period{
		Begin: t10,
	}
	closed := Period{
		Begin: t5,
		End:   &t15,
	}

	t.Run("false for before", func(t *testing.T) {
		assert.False(t, open.Contains(t5))
	})

	t.Run("false for after", func(t *testing.T) {
		assert.False(t, closed.Contains(t20))
	})

	t.Run("true for after", func(t *testing.T) {
		assert.True(t, open.Contains(t20))
	})

	t.Run("true for within", func(t *testing.T) {
		assert.True(t, closed.Contains(t10))
	})
}
