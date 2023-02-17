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
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/network/log"
	"math/rand"
	"time"
)

var nowFunc = time.Now

// Backoff defines an API for delaying calls (or connections) to a remote system when its unresponsive,
// to avoid flooding both local and remote system. When a call fails Backoff() must be called,
// which returns the waiting time before the action should be retried.
// When the call succeeds Reset() and the Backoff is stored for re-use, Reset() should be called to make sure to reset
// the internal counters.
type Backoff interface {
	// Set the internal counters of the Backoff to the given value.
	Set(value time.Duration)
	// Backoff returns the waiting time before the call should be retried, and should be called after a failed call.
	Backoff() time.Duration
	// Value returns the last backoff value returned by Backoff().
	Value() time.Duration
	// Expired returns true if the backoff period has passed.
	Expired() bool
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
	deadline   time.Time
}

func (b *boundedRandomBackoff) Expired() bool {
	return b.deadline.Sub(nowFunc()) <= 0
}

func (b *boundedRandomBackoff) Value() time.Duration {
	return b.value
}

func (b *boundedRandomBackoff) Set(value time.Duration) {
	b.value = value
	b.deadline = nowFunc().Add(b.value)
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
	b.deadline = nowFunc().Add(b.value)
	return b.value
}

func BoundedBackoff(min time.Duration, max time.Duration) Backoff {
	return &boundedRandomBackoff{
		multiplier: 1.5,
		value:      0,
		max:        max,
		min:        min,
	}
}

// persistingBackoff wraps a Backoff and remembers the last value returned by Backoff()
type persistingBackoff struct {
	underlying       Backoff
	peerDID          string
	store            stoabs.KVStore
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
		return result
	}
	return p.underlying.Value()
}

// NewPersistedBackoff wraps another backoff and stores the last value returned by Backoff() in BBolt.
// It reads the last backoff value from the DB and returns it as the first value of the Backoff.
func NewPersistedBackoff(connectionStore stoabs.KVStore, peerDID did.DID, underlying Backoff) Backoff {
	b := &persistingBackoff{
		peerDID:    fmt.Sprintf("did:%s:%s", peerDID.Method, peerDID.ID), // remove all that is not part of the DID.
		store:      connectionStore,
		underlying: underlying,
	}
	persisted := b.read()
	if !persisted.Moment.IsZero() {
		b.persistedBackoff = persisted.Moment
		b.underlying.Set(persisted.Value)
	}
	return b
}

func (p *persistingBackoff) Expired() bool {
	if !p.persistedBackoff.IsZero() {
		return p.persistedBackoff.Sub(nowFunc()) < 0
	}
	return p.underlying.Expired()
}

func (p *persistingBackoff) Set(value time.Duration) {
	p.underlying.Set(value)
	p.persistedBackoff = time.Time{}
	p.write(value)
}

func (p *persistingBackoff) Backoff() time.Duration {
	b := p.underlying.Backoff()
	p.persistedBackoff = time.Time{}
	p.write(b)
	return b
}

func (p *persistingBackoff) write(backoff time.Duration) {
	err := p.store.WriteShelf(context.Background(), "backoff", func(writer stoabs.Writer) error {
		var buf bytes.Buffer
		err := gob.NewEncoder(&buf).Encode(persistedBackoff{
			Moment: nowFunc().Add(backoff),
			Value:  backoff,
		})
		if err != nil {
			return err
		}
		return writer.Put(stoabs.BytesKey(p.peerDID), buf.Bytes())
	})
	if err != nil {
		log.Logger().
			WithError(err).
			Error("Failed to persist backoff")
	}
}

func (p *persistingBackoff) read() persistedBackoff {
	var result persistedBackoff
	err := p.store.ReadShelf(context.Background(), "backoff", func(reader stoabs.Reader) error {
		data, err := reader.Get(stoabs.BytesKey(p.peerDID))
		if errors.Is(err, stoabs.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return gob.NewDecoder(bytes.NewReader(data)).Decode(&result)
	})
	if err != nil {
		log.Logger().
			WithError(err).
			Error("Failed to read persisted backoff")
	}
	return result
}
