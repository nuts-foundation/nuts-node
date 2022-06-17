/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

package dag

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/nuts-foundation/go-stoabs"

	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
)

const (
	retriesFailedThreshold = 10
	maxRetries             = 100
)

// Subscriber defines methods for a persistent retry mechanism
type Subscriber interface {
	// Schedule a job that needs to be retried.
	// The job may be ignored due to configured filters
	// Returns nil if job already exists.
	// An error is returned if there's a problem with the underlying storage.
	Schedule(tx stoabs.WriteTx, job Job) error
	// Finished marks the job as finished and removes it from the scheduler
	// An error is returned if there's a problem with the underlying storage.
	Finished(hash hash.SHA256Hash) error
	// Run retrying existing jobs
	Run() error
	// GetFailedJobs retrieves the hashes of failed jobs
	GetFailedJobs() ([]Job, error)
	// Close cancels all jobs and closes the DB
	Close() error
}

func WithRetryDelay(delay time.Duration) SubscriberOption {
	return func(subscriber *subscriber) {
		subscriber.retryDelay = delay
	}
}

func WithPersistency(db stoabs.KVStore) SubscriberOption {
	return func(subscriber *subscriber) {
		subscriber.db = db
	}
}

// Unsafe is the option to call the subscriber after the transaction is closed, only once and without persistency
func Unsafe() SubscriberOption {
	return func(subscriber *subscriber) {
		subscriber.onCommit = true
	}
}

func WithSelectionFilter(filter SubscriptionFilter) SubscriberOption {
	return func(subscriber *subscriber) {
		subscriber.filters = append(subscriber.filters, filter)
	}
}

// NewSubscriber returns a Subscriber that handles transaction events with the given function.
// Various settings can be changed via a SubscriberOption
func NewSubscriber(name string, subscriberFn SubscriberFn, options ...SubscriberOption) (Subscriber, error) {

	ctx, cancel := context.WithCancel(context.Background())
	subscriber := &subscriber{
		name:     name,
		ctx:      ctx,
		cancel:   cancel,
		callback: subscriberFn,
	}

	for _, option := range options {
		option(subscriber)
	}

	return subscriber, nil
}

type subscriber struct {
	db           stoabs.KVStore
	name         string
	retryDelay   time.Duration
	callback     SubscriberFn
	ctx          context.Context
	cancel       context.CancelFunc
	scheduleLock sync.Mutex
	filters      []SubscriptionFilter
	onCommit     bool
}

func (p *subscriber) bucketName() string {
	return fmt.Sprintf("_%s_jobs", p.name)
}

func (p *subscriber) Run() error {
	// nothing to run if this subscriber is not persistent
	if p.db == nil {
		return nil
	}
	return p.db.ReadShelf(p.bucketName(), func(reader stoabs.Reader) error {

		return reader.Iterate(func(k stoabs.Key, v []byte) error {
			job := Job{}
			_ = json.Unmarshal(v, &job)

			p.retry(job)

			return nil
		})
	})
}

func (p *subscriber) GetFailedJobs() (jobs []Job, err error) {
	err = p.db.ReadShelf(p.bucketName(), func(reader stoabs.Reader) error {
		return reader.Iterate(func(k stoabs.Key, data []byte) error {
			if data != nil {
				job := Job{}
				_ = json.Unmarshal(data, &job)

				if job.Count >= retriesFailedThreshold {
					jobs = append(jobs, job)
				}
			}
			return nil
		})
	})

	return
}

func (p *subscriber) Schedule(tx stoabs.WriteTx, job Job) error {
	if p.onCommit {
		tx.AfterCommit(func() {
			// TODO
			_, _ = p.callback(job)
		})
		return nil
	}

	p.scheduleLock.Lock()
	defer p.scheduleLock.Unlock()

	writer, err := tx.GetShelfWriter(p.bucketName())
	if err != nil {
		return err
	}

	existingJob := p.readJob(writer, job.Hash)
	if job.Hash.Equals(existingJob.Hash) {
		// do not schedule existing jobs
		return nil
	}
	// apply filters
	for _, f := range p.filters {
		if !f(job) {
			return nil
		}
	}

	if err := p.writeJob(writer, job); err != nil {
		return err
	}

	tx.AfterCommit(func() {
		p.retry(job)
	})
	return nil
}

// errJobInProgress defines a dummy error that is returned when a job is currently in progress
var errJobInProgress = errors.New("job is in progress")

func (p *subscriber) retry(job Job) {
	delay := p.retryDelay
	initialCount := job.Count

	for i := 0; i < initialCount; i++ {
		delay *= 2
	}

	go func(ctx context.Context) {
		err := retry.Do(func() error {
			var dbJob Job
			if err := p.db.ReadShelf(p.bucketName(), func(reader stoabs.Reader) error {
				dbJob = p.readJob(reader, job.Hash)
				return nil
			}); err != nil {
				return retry.Unrecoverable(err)
			}
			if dbJob.Hash.Empty() {
				// no longer exists so done, this stops any go routine but does not clear the DB entry
				return nil
			}

			dbJob.Count += 1
			if err := p.db.WriteShelf(p.bucketName(), func(writer stoabs.Writer) error {
				return p.writeJob(writer, dbJob)
			}); err != nil {
				return retry.Unrecoverable(err)
			}

			if finished, err := p.callback(dbJob); err != nil {
				log.Logger().Errorf("retry for %s job failed (ref=%s)", p.name, dbJob.Hash.String())
			} else if finished {
				p.Finished(dbJob.Hash)
			}

			// has to return an error since `retry.Do` needs to retry until it's marked as finished
			return errJobInProgress
		},
			retry.Attempts(maxRetries-uint(initialCount)), // should be enough
			retry.MaxDelay(24*time.Hour),                  // maximum delay of an hour
			retry.Delay(delay),                            // first retry after 5 seconds, second after 10, 20, 40, etc
			retry.DelayType(retry.BackOffDelay),
			retry.Context(ctx),
			retry.LastErrorOnly(true), // only log last error
			retry.OnRetry(func(n uint, err error) {
				log.Logger().Debugf("retrying job (count=%d) with ref: %s", n, job.Hash.String())
			}),
		)
		if err != nil {
			log.Logger().Errorf("failed to pass payload query to network: %v", err)
		}
	}(p.ctx)
}

func (p *subscriber) writeJob(writer stoabs.Writer, job Job) error {
	// TODO?
	bytes, _ := json.Marshal(job)

	return writer.Put(stoabs.BytesKey(job.Hash.Slice()), bytes)
}

func (p *subscriber) readJob(reader stoabs.Reader, hash hash.SHA256Hash) (job Job) {
	// TODO
	data, _ := reader.Get(stoabs.BytesKey(hash.Slice()))

	if data != nil {
		if err := json.Unmarshal(data, &job); err != nil {
			panic(err)
		}
	}

	return
}

func (p *subscriber) Finished(hash hash.SHA256Hash) error {
	return p.db.WriteShelf(p.bucketName(), func(writer stoabs.Writer) error {
		return writer.Delete(stoabs.BytesKey(hash.Slice()))
	})
}

func (p *subscriber) Close() error {
	// TODO
	return nil
}
