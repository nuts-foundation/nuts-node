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

package p2p

import (
	"math/rand"
	"time"
)

// Backoff defines an API for delaying calls (or connections) to a remote system when its unresponsive,
// to avoid flooding both local and remote system. When a call fails Backoff() must be called,
// which returns the waiting time before the action should be retried.
// When the call succeeds Reset() and the Backoff is stored for re-use, Reset() should be called to make sure to reset
// the internal counters.
type Backoff interface {
	// Reset resets the internal counters of the Backoff and should be called after a successful call.
	Reset()
	// Backoff returns the waiting time before the call should be retried, and should be called after a failed call.
	Backoff() time.Duration
}

// RandomBackoff returns a random time.Duration which lies between the given (inclusive) min/max bounds.
// It can be used to get a random, one-off backoff.
func RandomBackoff(min, max time.Duration) time.Duration {
	return time.Duration(rand.Int63n(int64(max-min)) + int64(min))
}

type backoff struct {
	multiplier float64
	value      time.Duration
	max        time.Duration
	min        time.Duration
}

func (b *backoff) Reset() {
	b.value = 0
}

func (b *backoff) Backoff() time.Duration {
	// Jitter could be added to add a bit of randomness to the backoff value (e.g. https://github.com/grpc/grpc/blob/master/doc/connection-backoff.md)
	if b.value < b.min {
		b.value = b.min
	} else {
		b.value = time.Duration(float64(b.value) * b.multiplier)
		if b.value > b.max {
			b.value = b.max
		}
	}
	return b.value
}

func defaultBackoff() Backoff {
	// TODO: Make this configurable
	return &backoff{
		multiplier: 1.5,
		value:      0,
		max:        30 * time.Second,
		min:        time.Second,
	}
}
