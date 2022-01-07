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
	"go.etcd.io/bbolt"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
)

func encodeUint16(value uint16) []byte {
	// uint16 is 2 bytes long
	output := make([]byte, 2)
	binary.LittleEndian.PutUint16(output, value)

	return output
}

func decodeUint16(value []byte) uint16 {
	return binary.LittleEndian.Uint16(value)
}

// Scheduler defines methods for a persistent retry mechanism
type Scheduler interface {
	// Schedule a job that needs to be retried. It'll be passed to the channel immediately and at set intervals.
	// Returns nil if job already exists.
	// An error is returned if there's a problem with the underlying storage.
	Schedule(hash hash.SHA256Hash) error
	// Finished marks the job as finished and removes it from the scheduler
	// An error is returned if there's a problem with the underlying storage.
	Finished(hash hash.SHA256Hash) error
	// Configure opens the DB connection for persistent job storage and loads existing jobs from disk
	Configure() error
	// Start retrying new and existing jobs
	Start() error
	// Close cancels all jobs and closes the DB
	Close() error
}

type jobCallBack func(hash hash.SHA256Hash)

// NewPayloadScheduler returns a Scheduler for payload fetches.
// The payload hashes as []byte should be added as job.
func NewPayloadScheduler(dataDir string, payloadRetryDelay time.Duration, callback jobCallBack) Scheduler {
	return &payloadScheduler{
		dataDir:    dataDir,
		retryDelay: payloadRetryDelay,
		callback:   callback,
	}
}

type payloadScheduler struct {
	dataDir    string
	retryDelay time.Duration
	db         *bbolt.DB
	callback   jobCallBack
	ctx        context.Context
	cancel     context.CancelFunc
}

func (p *payloadScheduler) Configure() error {
	p.ctx, p.cancel = context.WithCancel(context.Background())

	dbFile := path.Join(p.dataDir, "network", "payload_jobs.db")
	if err := os.MkdirAll(filepath.Dir(dbFile), os.ModePerm); err != nil {
		return fmt.Errorf("unable to setup database: %w", err)
	}

	if p.retryDelay == 0 {
		p.retryDelay = 5 * time.Second
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

func (p *payloadScheduler) Start() error {
	return p.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("payload_jobs"))
		return bucket.ForEach(func(k, v []byte) error {
			h := hash.FromSlice(k)
			c := decodeUint16(v)

			p.retry(h, c)

			return nil
		})
	})
}

func (p *payloadScheduler) Schedule(hash hash.SHA256Hash) error {
	if err := p.writeCount(hash, 0); err != nil {
		return err
	}
	p.retry(hash, 0)

	return nil
}

// jobInProgress defines a dummy error that is returned when a job is currently in progress
var jobInProgress = errors.New("job is in progress")

func (p *payloadScheduler) retry(hash hash.SHA256Hash, initialCount uint16) {
	delay := p.retryDelay

	for i := uint16(0); i < initialCount; i++ {
		delay *= 2
	}

	go func(ctx context.Context) {
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

				// has to return an error since `retry.Do` needs to retry until it's marked as finished
				return jobInProgress
			}

			// no longer exists, so done
			return nil
		},
			retry.Attempts(100),          // should be enough
			retry.MaxDelay(24*time.Hour), // maximum delay of an hour
			retry.Delay(delay),           // first retry after 5 seconds, second after 10, 20, 40, etc
			retry.DelayType(retry.BackOffDelay),
			retry.Context(ctx),
			retry.LastErrorOnly(true), // only log last error
			retry.OnRetry(func(n uint, err error) {
				log.Logger().Debugf("retrying payload (count=%d) with ref: %s", n, hash.String())
			}),
		)
		if err != nil {
			log.Logger().Errorf("Failed to pass payload query to network: %v", err)
		}
	}(p.ctx)
}

func (p *payloadScheduler) writeCount(hash hash.SHA256Hash, count uint16) error {
	return p.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("payload_jobs"))

		return bucket.Put(hash.Slice(), encodeUint16(count))
	})
}

func (p *payloadScheduler) readCount(hash hash.SHA256Hash) (count uint16, exists bool, err error) {
	err = p.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("payload_jobs"))
		data := bucket.Get(hash.Slice())

		if data != nil {
			exists = true
			count = decodeUint16(data)
		}

		return nil
	})
	return
}

func (p *payloadScheduler) Finished(hash hash.SHA256Hash) error {
	return p.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte("payload_jobs"))
		return bucket.Delete(hash.Slice())
	})
}

func (p *payloadScheduler) Close() error {
	// cancel all retries through the context
	p.cancel()
	// close the DB
	return p.db.Close()
}
