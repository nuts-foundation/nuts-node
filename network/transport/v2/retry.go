/*
 * Nuts node
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

package v2

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
	"go.etcd.io/bbolt"
)

// Retriable defines methods for a persistent retry mechanism
type Retriable interface {
	// Add a job that needs to be retried. It'll be passed to the channel immediately and at set intervals.
	// Returns nil if job already exists.
	// An error is returned if there's a problem with the underlying storage.
	Add(hash hash.SHA256Hash) error
	// Remove a job, it'll no longer be retried.
	// An error is returned if there's a problem with the underlying storage.
	Remove(hash hash.SHA256Hash) error
	// Configure opens the DB connection for persistent job storage and loads existing jobs from disk
	Configure() error
	// Start retrying new and existing jobs
	Start() error
	// Close cancels all jobs and closes the DB
	Close() error
}

type jobCallBack func(hash hash.SHA256Hash)

// NewPayloadRetrier returns a Retriable for payload fetches.
// The payload hashes as []byte should be added as job.
func NewPayloadRetrier(config Config, callback jobCallBack) Retriable {
	return &payloadRetrier{
		config:   config,
		callback: callback,
	}
}

type payloadRetrier struct {
	config   Config
	db       *bbolt.DB
	callback jobCallBack
	ctx      context.Context
	cancel   context.CancelFunc
}

func (p *payloadRetrier) Configure() error {
	p.ctx, p.cancel = context.WithCancel(context.Background())

	dbFile := path.Join(p.config.Datadir, "network", "payload_jobs.db")
	if err := os.MkdirAll(filepath.Dir(dbFile), os.ModePerm); err != nil {
		return fmt.Errorf("unable to setup database: %w", err)
	}

	if p.config.PayloadRetryDelay == 0 {
		p.config.PayloadRetryDelay = 5 * time.Second
	}
	var err error
	p.db, err = bbolt.Open(dbFile, 0600, bbolt.DefaultOptions)
	if err != nil {
		return fmt.Errorf("unable to create BBolt database: %w", err)
	}
	if err = p.db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("payload_jobs"))
		return err
	}); err != nil {
		return fmt.Errorf("unable to create buckets in database: %w", err)
	}
	return nil
}

func (p *payloadRetrier) Start() error {
	return p.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("payload_jobs"))
		return bucket.ForEach(func(k, v []byte) error {
			h := hash.FromSlice(k)
			c := binary.LittleEndian.Uint16(v)
			p.retry(h, c)
			return nil
		})
	})
}

func (p *payloadRetrier) Add(hash hash.SHA256Hash) error {
	if err := p.writeCount(hash, 0); err != nil {
		return err
	}
	p.retry(hash, 0)

	return nil
}

var errContinue = errors.New("continue")

func (p *payloadRetrier) retry(hash hash.SHA256Hash, initialCount uint16) {
	startDelay := p.config.PayloadRetryDelay
	for i := uint16(0); i < initialCount; i++ {
		startDelay *= 2
	}

	go func() {
		err := retry.Do(func() error {
			count, existing, err := p.readCount(hash)
			if err != nil {
				return retry.Unrecoverable(err)
			}
			if existing {
				if err := p.writeCount(hash, count+1); err != nil {
					return retry.Unrecoverable(err)
				}
				p.callback(hash)
				return errContinue
			}

			// no longer exists, so done
			return nil
		},
			retry.Attempts(100),          // should be enough
			retry.MaxDelay(24*time.Hour), // maximum delay of an hour
			retry.Delay(startDelay),      // first retry after 5 seconds, second after 10, 20, 40, etc
			retry.DelayType(retry.BackOffDelay),
			retry.Context(p.ctx),
			retry.LastErrorOnly(true), // only log last error
			retry.OnRetry(func(n uint, err error) {
				log.Logger().Debugf("retrying payload (count=%d) with ref: %s", n, hash.String())
			}),
		)
		if err != nil {
			log.Logger().Errorf("Failed to pass payload query to network: %v", err)
		}
	}()
}

func (p *payloadRetrier) writeCount(hash hash.SHA256Hash, count uint16) error {
	return p.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("payload_jobs"))
		data := make([]byte, 2)
		binary.LittleEndian.PutUint16(data, count)
		return bucket.Put(hash.Slice(), data)
	})
}

func (p *payloadRetrier) readCount(hash hash.SHA256Hash) (count uint16, exists bool, err error) {
	err = p.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("payload_jobs"))
		data := bucket.Get(hash.Slice())
		if data != nil {
			exists = true
			count = binary.LittleEndian.Uint16(data)
		}
		return nil
	})
	return
}

func (p *payloadRetrier) Remove(hash hash.SHA256Hash) error {
	return p.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("payload_jobs"))
		return bucket.Delete(hash.Slice())
	})
}

func (p *payloadRetrier) Close() error {
	// cancel all retries through the context
	p.cancel()
	// close the DB
	return p.db.Close()
}
