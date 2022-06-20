/*
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
	"github.com/avast/retry-go/v4"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
	"time"
)

const (
	defaultRetryDelay      = time.Second
	retriesFailedThreshold = 10
	maxRetries             = 100
	// TransactionEventType is used as Type in an Event when a transaction is added to the DAG.
	TransactionEventType = "transaction"
	// PayloadEventType is used as Type in an Event when a payload is written to the DB.
	PayloadEventType = "payload"
)

// Subscriber defines methods for a persistent retry mechanism.
// Storing the event in the DB is separated from notifying the subscribers.
// The event is sent to subscribers after the transaction is committed to prevent timing issues.
type Subscriber interface {
	// Save an event that needs to be retried even after a crash.
	// It will not yet be sent, use Notify to notify subscribers.
	// The event may be ignored due to configured filters.
	// Returns nil if event already exists.
	// An error is returned if there's a problem with the underlying storage.
	Save(tx stoabs.WriteTx, event Event) error
	// Notify the subscribers, if an error occurs it'll be retried later.
	// This does not store the event in the DB, use Save for that.
	Notify(event Event)
	// Finished marks the job as finished and removes it from the scheduler
	// An error is returned if there's a problem with the underlying storage.
	Finished(hash hash.SHA256Hash) error
	// Run retries all existing events.
	Run() error
	// GetFailedEvents retrieves the hashes of failed events
	GetFailedEvents() ([]Event, error)
	// Close cancels all running events. It does not remove them from the DB
	Close() error
}

// SubscriberFn is the function type that needs to be registered for a subscriber
// Returns true if event is received and done, false otherwise
type SubscriberFn func(event Event) (bool, error)

// SubscriptionFilter can be added to a subscription to filter out any unwanted events
// Returns true if the filter applies and the Event is to be received
type SubscriptionFilter func(event Event) bool

// SubscriberOption sets an option on a subscriber
type SubscriberOption func(subscriber *subscriber)

// Event is the metadata that is stored for a subscriber specific event
// The Hash is used as identifier for the Event.
type Event struct {
	// Type of an event, can be used to filter
	Type string `json:"type"`
	// Hash is the ID of the Event, usually the same as the dag.Transaction.Ref()
	Hash hash.SHA256Hash `json:"Hash"`
	// Count is the current number of retries
	Count       int         `json:"count"`
	Transaction Transaction `json:"transaction"`
	Payload     []byte      `json:"payload"`
}

func (j *Event) UnmarshalJSON(bytes []byte) error {
	tmp := &struct {
		Type        string          `json:"type"`
		Hash        hash.SHA256Hash `json:"Hash"`
		Count       int             `json:"count"`
		Transaction string          `json:"transaction"`
		Payload     []byte          `json:"payload"`
	}{}

	if err := json.Unmarshal(bytes, tmp); err != nil {
		return err
	}

	j.Type = tmp.Type
	j.Hash = tmp.Hash
	j.Count = tmp.Count
	j.Payload = tmp.Payload

	tx, err := ParseTransaction([]byte(tmp.Transaction))
	if err != nil {
		return err
	}
	j.Transaction = tx

	return nil
}

// WithRetryDelay sets a custom delay for the subscriber.
// Between each execution the delay is doubled.
func WithRetryDelay(delay time.Duration) SubscriberOption {
	return func(subscriber *subscriber) {
		subscriber.retryDelay = delay
	}
}

// WithPersistency sets the DB to be used for persisting the events.
// Without persistency, the event is lost between restarts.
func WithPersistency(db stoabs.KVStore) SubscriberOption {
	return func(subscriber *subscriber) {
		subscriber.db = db
	}
}

// WithSelectionFilter adds a filter to the subscriber.
// Any unwanted events can be filtered out.
func WithSelectionFilter(filter SubscriptionFilter) SubscriberOption {
	return func(subscriber *subscriber) {
		subscriber.filters = append(subscriber.filters, filter)
	}
}

// NewSubscriber returns a Subscriber that handles transaction events with the given function.
// Various settings can be changed via a SubscriberOption
// A default retry delay of 10 seconds is used.
func NewSubscriber(name string, subscriberFn SubscriberFn, options ...SubscriberOption) Subscriber {

	ctx, cancel := context.WithCancel(context.Background())
	subscriber := &subscriber{
		name:       name,
		ctx:        ctx,
		cancel:     cancel,
		callback:   subscriberFn,
		retryDelay: defaultRetryDelay,
	}

	for _, option := range options {
		option(subscriber)
	}

	return subscriber
}

type subscriber struct {
	db         stoabs.KVStore
	name       string
	retryDelay time.Duration
	callback   SubscriberFn
	ctx        context.Context
	cancel     context.CancelFunc
	filters    []SubscriptionFilter
}

func (p *subscriber) bucketName() string {
	return fmt.Sprintf("_%s_jobs", p.name)
}

func (p *subscriber) isPersistent() bool {
	return p.db != nil
}

func (p *subscriber) Run() error {
	// nothing to run if this subscriber is not persistent
	if !p.isPersistent() {
		return nil
	}
	return p.db.ReadShelf(p.bucketName(), func(reader stoabs.Reader) error {
		return reader.Iterate(func(k stoabs.Key, v []byte) error {
			event := Event{}
			_ = json.Unmarshal(v, &event)

			p.retry(event)

			return nil
		})
	})
}

func (p *subscriber) GetFailedEvents() (events []Event, err error) {
	err = p.db.ReadShelf(p.bucketName(), func(reader stoabs.Reader) error {
		return reader.Iterate(func(k stoabs.Key, data []byte) error {
			if data != nil {
				event := Event{}
				_ = json.Unmarshal(data, &event)

				if event.Count >= retriesFailedThreshold {
					events = append(events, event)
				}
			}
			return nil
		})
	})

	return
}

func (p *subscriber) Save(tx stoabs.WriteTx, event Event) error {
	// non-persistent job
	if p.db == nil {
		return nil
	}

	writer, err := tx.GetShelfWriter(p.bucketName())
	if err != nil {
		return err
	}

	// apply filters
	for _, f := range p.filters {
		if !f(event) {
			return nil
		}
	}

	if existingEvent, err := p.readEvent(writer, event.Hash); err != nil {
		return err
	} else if existingEvent != nil {
		// do not schedule existing jobs
		return nil
	}

	return p.writeEvent(writer, event)
}

func (p *subscriber) Notify(event Event) {
	// apply filters
	for _, f := range p.filters {
		if !f(event) {
			return
		}
	}

	p.retry(event)
}

// errEventInProgress defines a dummy error that is returned when a job is currently in progress
var errEventInProgress = errors.New("job is in progress")

func (p *subscriber) retry(event Event) {
	delay := p.retryDelay
	initialCount := event.Count

	for i := 0; i < initialCount; i++ {
		delay *= 2
	}

	go func(ctx context.Context) {
		err := retry.Do(func() error {
			var dbEvent = &event
			if p.isPersistent() {
				if err := p.db.ReadShelf(p.bucketName(), func(reader stoabs.Reader) error {
					var err error
					dbEvent, err = p.readEvent(reader, event.Hash)
					return err
				}); err != nil {
					return retry.Unrecoverable(err)
				}
				if dbEvent == nil {
					// no longer exists so done, this stops any go routine
					return nil
				}
			}

			dbEvent.Count++
			if p.isPersistent() {
				if err := p.db.WriteShelf(p.bucketName(), func(writer stoabs.Writer) error {
					return p.writeEvent(writer, *dbEvent)
				}); err != nil {
					return retry.Unrecoverable(err)
				}
			}

			if finished, err := p.callback(*dbEvent); err != nil {
				log.Logger().Errorf("retry for %s subscriber failed (ref=%s)", p.name, dbEvent.Hash.String())
			} else if finished {
				return p.Finished(dbEvent.Hash)
			}

			// has to return an error since `retry.Do` needs to retry until it's marked as finished
			return errEventInProgress
		},
			retry.Attempts(maxRetries-uint(initialCount)),
			retry.MaxDelay(24*time.Hour),
			retry.Delay(delay),
			retry.DelayType(retry.BackOffDelay),
			retry.Context(ctx),
			retry.LastErrorOnly(true),
			retry.OnRetry(func(n uint, err error) {
				log.Logger().Debugf("retrying event (count=%d) with ref: %s", n, event.Hash.String())
			}),
		)
		if err != nil {
			log.Logger().Errorf("retry for %s job subscriber (ref=%s): %v", p.name, event.Hash.String(), err)
		}
	}(p.ctx)
}

func (p *subscriber) writeEvent(writer stoabs.Writer, event Event) error {
	bytes, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return writer.Put(stoabs.BytesKey(event.Hash.Slice()), bytes)
}

func (p *subscriber) readEvent(reader stoabs.Reader, hash hash.SHA256Hash) (*Event, error) {
	var event Event
	data, err := reader.Get(stoabs.BytesKey(hash.Slice()))
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, nil
	}

	if err = json.Unmarshal(data, &event); err != nil {
		return nil, err
	}

	return &event, nil
}

func (p *subscriber) Finished(hash hash.SHA256Hash) error {
	if !p.isPersistent() {
		return nil
	}
	return p.db.WriteShelf(p.bucketName(), func(writer stoabs.Writer) error {
		return writer.Delete(stoabs.BytesKey(hash.Slice()))
	})
}

func (p *subscriber) Close() error {
	p.cancel()
	return nil
}
