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
	"bytes"
	"encoding/gob"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/nuts-foundation/nuts-node/storage"
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

// persistingBackoff wraps a Backoff and remembers the last value returned by Backoff()
type persistingBackoff struct {
	underlying       Backoff
	peerAddress      string
	store            storage.KVStore
	persistedBackoff time.Time
}

type persistedBackoff struct {
	// Moment holds the time at which the current backoff expires.
	Moment time.Time
	// Value holds the actual backoff value.
	Value time.Duration
}

func (p *persistingBackoff) Value() time.Duration {
	if !p.persistedBackoff.IsZero() {
		// Remaining time until the previously persisted backoff is the initial backoff
		result := p.persistedBackoff.Sub(nowFunc()) // negative is no problem: time.Sleep() returns immediately in that case
		p.persistedBackoff = time.Time{}
		return result
	}
	return p.underlying.Value()
}

// NewPersistedBackoff wraps another backoff and stores the last value returned by Backoff() in BBolt.
// It reads the last backoff value from the DB and returns it as the first value of the Backoff.
func NewPersistedBackoff(connectionStore storage.KVStore, peerAddress string, underlying Backoff) Backoff {
	b := &persistingBackoff{
		peerAddress: peerAddress,
		store:       connectionStore,
		underlying:  underlying,
	}
	persisted := b.read()
	if !persisted.Moment.IsZero() {
		b.persistedBackoff = persisted.Moment
		b.underlying.Reset(persisted.Value)
	}
	return b
}

func (p *persistingBackoff) Reset(value time.Duration) {
	p.underlying.Reset(value)
	p.persistedBackoff = time.Time{}
	p.write(value)
}

func (p *persistingBackoff) Backoff() time.Duration {
	b := p.underlying.Backoff()
	p.persistedBackoff = time.Time{}
	p.write(b)
	return b
}

func (p persistingBackoff) write(backoff time.Duration) {
	err := p.store.WriteBucket("backoff", func(writer storage.BucketWriter) error {
		var buf bytes.Buffer
		err := gob.NewEncoder(&buf).Encode(persistedBackoff{
			Moment: nowFunc().Add(backoff),
			Value:  backoff,
		})
		if err != nil {
			return err
		}
		return writer.Put([]byte(p.peerAddress), buf.Bytes())
	})
	if err != nil {
		log.Logger().Errorf("Failed to persist backoff: %v", err)
	}
}

func (p persistingBackoff) read() persistedBackoff {
	var result persistedBackoff
	err := p.store.ReadBucket("backoff", func(reader storage.BucketReader) error {
		data, err := reader.Get([]byte(p.peerAddress))
		if err != nil {
			return err
		}
		if data == nil {
			return nil
		}
		return gob.NewDecoder(bytes.NewReader(data)).Decode(&result)
	})
	if err != nil {
		log.Logger().Errorf("Failed to read persisted backoff: %v", err)
	}
	return result
}
