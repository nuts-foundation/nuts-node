/*
 * Copyright (C) 2020. Nuts community
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
	"time"
)

type Backoff interface {
	Reset()
	Backoff() time.Duration
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
	// TODO: Might want to add jitter (e.g. https://github.com/grpc/grpc/blob/master/doc/connection-backoff.md)
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
