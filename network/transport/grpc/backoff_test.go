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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestBackoff(t *testing.T) {
	b := defaultBackoff().(*backoff)
	// Initially the backoff should be min-backoff
	assert.Equal(t, b.min, b.Backoff())
	var i = 0
	for i = 0; i < 10; i++ {
		b.Backoff().Milliseconds()
	}
	// In a few passes we should have reached max-backoff
	assert.Equal(t, b.max, b.Backoff())
}

func TestBackoffReset(t *testing.T) {
	b := defaultBackoff().(*backoff)
	b.Backoff()
	assert.True(t, b.Backoff() > b.min)
	b.Reset()
	assert.Equal(t, b.min, b.Backoff())
}

func TestBackoffDefaultValues(t *testing.T) {
	b := defaultBackoff().(*backoff)
	assert.Equal(t, time.Second, b.min)
	assert.Equal(t, 30*time.Second, b.max)
}

func TestRandomBackoff(t *testing.T) {
	for i := 0; i < 100; i++ {
		const min = time.Second
		const max = 10 * time.Second
		val := RandomBackoff(min, max)
		assert.True(t, val >= min && val <= max)
	}
}
