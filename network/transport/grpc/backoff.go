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
	"encoding/binary"
	"errors"
	"github.com/nuts-foundation/nuts-node/network/log"
	"go.etcd.io/bbolt"
	"math/rand"
	"time"
)

const backoffValueByteSize = 8

var nowFunc = time.Now

// Backoff defines an API for delaying calls (or connections) to a remote system when its unresponsive,
// to avoid flooding both local and remote system. When a call fails Backoff() must be called,
// which returns the waiting time before the action should be retried.
// When the call succeeds Reset() and the Backoff is stored for re-use, Reset() should be called to make sure to reset
// the internal counters.
type Backoff interface {
	// Reset resets the internal counters of the Backoff to the given value. Should be called after a successful call (set to 0).
	Reset(value time.Duration)
	// Backoff returns the waiting time before the call should be retried, and should be called after a failed call.
	Backoff() time.Duration
	// Value returns the last backoff value returned by Backoff().
	Value() time.Duration
}

// RandomBackoff returns a random time.Duration which lies between the given (inclusive) min/max bounds.
// It can be used to get a random, one-off boundedRandomBackoff.
func RandomBackoff(min, max time.Duration) time.Duration {
	return time.Duration(rand.Int63n(int64(max-min)) + int64(min))
}

type boundedRandomBackoff struct {
	multiplier float64
	value      time.Duration
	max        time.Duration
	min        time.Duration
}

func (b *boundedRandomBackoff) Value() time.Duration {
	return b.value
}

func (b *boundedRandomBackoff) Reset(value time.Duration) {
	b.value = value
}

func (b *boundedRandomBackoff) Backoff() time.Duration {
	// Jitter could be added to add a bit of randomness to the boundedRandomBackoff value (e.g. https://github.com/grpc/grpc/blob/master/doc/connection-boundedRandomBackoff.md)
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
	return &boundedRandomBackoff{
		multiplier: 1.5,
		value:      0,
		max:        time.Hour,
		min:        time.Second,
	}
}

// persistedBackoff wraps a Backoff and remembers the last value returned by Backoff()
type persistedBackoff struct {
	underlying  Backoff
	peerAddress string
	db          *bbolt.DB
}

func (p persistedBackoff) Value() time.Duration {
	return p.underlying.Value()
}

// NewPersistedBackoff wraps another backoff and stores the last value returned by Backoff() in BBolt.
// It reads the last backoff value from the DB and returns it as the first value of the Backoff.
func NewPersistedBackoff(db *bbolt.DB, peerAddress string, underlying Backoff) Backoff {
	b := &persistedBackoff{
		peerAddress: peerAddress,
		db:          db,
		underlying:  underlying,
	}
	valueAsTimestamp := b.read()
	if valueAsTimestamp.Before(nowFunc()) {
		// Backoff timestamp in the past, reset it to 0 (no initial backoff)
		b.underlying.Reset(0)
	} else {
		// Remaining time until the backoff is initial backoff
		b.underlying.Reset(valueAsTimestamp.Sub(nowFunc()))
	}
	return b
}

func (p persistedBackoff) Reset(value time.Duration) {
	p.underlying.Reset(value)
	p.write(value)
}

func (p persistedBackoff) Backoff() time.Duration {
	b := p.underlying.Backoff()
	p.write(b)
	return b
}

func (p persistedBackoff) write(backoff time.Duration) {
	timestampAfterBackoff := nowFunc().Add(backoff).Unix()
	err := p.db.Update(func(tx *bbolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists([]byte("backoff"))
		if err != nil {
			return err
		}
		data := make([]byte, backoffValueByteSize)
		binary.LittleEndian.PutUint64(data, uint64(timestampAfterBackoff))
		return bucket.Put([]byte(p.peerAddress), data)
	})
	if err != nil {
		log.Logger().Errorf("Failed to persist backoff: %v", err)
	}
}

func (p persistedBackoff) read() time.Time {
	var result time.Time
	err := p.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("backoff"))
		if bucket == nil {
			return nil
		}
		data := bucket.Get([]byte(p.peerAddress))
		if data == nil {
			return nil
		}
		if len(data) < backoffValueByteSize {
			return errors.New("invalid persisted backoff")
		}
		result = time.Unix(int64(binary.LittleEndian.Uint64(data)), 0)
		return nil
	})
	if err != nil {
		log.Logger().Errorf("Failed to read persisted backoff: %v", err)
	}
	return result
}
