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

// Notifier defines methods for a persistent retry mechanism.
// Storing the event in the DB is separated from notifying the subscribers.
// The event is sent to subscribers after the transaction is committed to prevent timing issues.
type Notifier interface {
	// Save an event that needs to be retried even after a crash.
	// It will not yet be sent, use Notify to notify the receiver.
	// The event may be ignored due to configured filters.
	// Returns nil if event already exists.
	// An error is returned if there's a problem with the underlying storage.
	Save(tx stoabs.WriteTx, event Event) error
	// Notify the receiver, if an error occurs it'll be retried later.
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

// ReceiverFn is the function type that needs to be registered for a notifier
// Returns true if event is received and done, false otherwise
type ReceiverFn func(event Event) (bool, error)

// NotificationFilter can be added to a notifier to filter out any unwanted events
// Returns true if the filter applies and the Event is to be received
type NotificationFilter func(event Event) bool

// NotifierOption sets an option on a notifier
type NotifierOption func(notifier *notifier)

// Event is the metadata that is stored for a notifier specific event
// The Hash is used as identifier for the Event.
type Event struct {
	// Type of an event, can be used to filter
	Type string `json:"type"`
	// Hash is the ID of the Event, usually the same as the dag.Transaction.Ref()
	Hash hash.SHA256Hash `json:"Hash"`
	// Retries is the current number of retries
	Retries int `json:"retries"`
	// Transaction that was added to the DAG or for which the Payload was written. Mandatory.
	Transaction Transaction `json:"transaction"`
	// Payload that was written to the PayloadStore, optional (private TXs)
	Payload []byte `json:"payload"`
}

func (j *Event) UnmarshalJSON(bytes []byte) error {
	tmp := &struct {
		Type        string          `json:"type"`
		Hash        hash.SHA256Hash `json:"Hash"`
		Retries     int             `json:"retries"`
		Transaction string          `json:"transaction"`
		Payload     []byte          `json:"payload"`
	}{}

	if err := json.Unmarshal(bytes, tmp); err != nil {
		return err
	}

	j.Type = tmp.Type
	j.Hash = tmp.Hash
	j.Retries = tmp.Retries
	j.Payload = tmp.Payload

	tx, err := ParseTransaction([]byte(tmp.Transaction))
	if err != nil {
		return err
	}
	j.Transaction = tx

	return nil
}

// WithRetryDelay sets a custom delay for the notifier.
// Between each execution the delay is doubled.
func WithRetryDelay(delay time.Duration) NotifierOption {
	return func(notifier *notifier) {
		notifier.retryDelay = delay
	}
}

// WithPersistency sets the DB to be used for persisting the events.
// Without persistency, the event is lost between restarts.
func WithPersistency(db stoabs.KVStore) NotifierOption {
	return func(notifier *notifier) {
		notifier.db = db
	}
}

// WithSelectionFilter adds a filter to the notifier.
// Any unwanted events can be filtered out.
func WithSelectionFilter(filter NotificationFilter) NotifierOption {
	return func(notifier *notifier) {
		notifier.filters = append(notifier.filters, filter)
	}
}

// WithContext adds the given context as parent context.
func WithContext(ctx context.Context) NotifierOption {
	return func(notifier *notifier) {
		subCtx, cancelFn := context.WithCancel(ctx)
		notifier.ctx = subCtx
		notifier.cancel = cancelFn
	}
}

// NewNotifier returns a Notifier that handles transaction events with the given function.
// Various settings can be changed via a NotifierOption
// A default retry delay of 10 seconds is used.
func NewNotifier(name string, receiverFn ReceiverFn, options ...NotifierOption) Notifier {

	ctx, cancel := context.WithCancel(context.Background())
	subscriber := &notifier{
		name:       name,
		ctx:        ctx,
		cancel:     cancel,
		receiver:   receiverFn,
		retryDelay: defaultRetryDelay,
	}

	for _, option := range options {
		option(subscriber)
	}

	return subscriber
}

type notifier struct {
	db         stoabs.KVStore
	name       string
	retryDelay time.Duration
	receiver   ReceiverFn
	ctx        context.Context
	cancel     context.CancelFunc
	filters    []NotificationFilter
}

func (p *notifier) shelfName() string {
	return fmt.Sprintf("_%s_jobs", p.name)
}

func (p *notifier) isPersistent() bool {
	return p.db != nil
}

func (p *notifier) Run() error {
	// nothing to run if this notifier is not persistent
	if !p.isPersistent() {
		return nil
	}
	return p.db.ReadShelf(p.shelfName(), func(reader stoabs.Reader) error {
		return reader.Iterate(func(k stoabs.Key, v []byte) error {
			event := Event{}
			_ = json.Unmarshal(v, &event)

			p.retry(event)

			return nil
		})
	})
}

func (p *notifier) GetFailedEvents() (events []Event, err error) {
	err = p.db.ReadShelf(p.shelfName(), func(reader stoabs.Reader) error {
		return reader.Iterate(func(k stoabs.Key, data []byte) error {
			if data != nil {
				event := Event{}
				_ = json.Unmarshal(data, &event)

				if event.Retries >= retriesFailedThreshold {
					events = append(events, event)
				}
			}
			return nil
		})
	})

	return
}

func (p *notifier) Save(tx stoabs.WriteTx, event Event) error {
	// non-persistent job
	if p.db == nil {
		return nil
	}

	writer, err := tx.GetShelfWriter(p.shelfName())
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

func (p *notifier) Notify(event Event) {
	// apply filters
	for _, f := range p.filters {
		if !f(event) {
			return
		}
	}

	p.retry(event)
}

func (p *notifier) retry(event Event) {
	delay := p.retryDelay
	initialCount := event.Retries

	for i := 0; i < initialCount; i++ {
		delay *= 2
	}

	go func(ctx context.Context) {
		err := retry.Do(func() error {
			var dbEvent = &event
			if p.isPersistent() {
				if err := p.db.ReadShelf(p.shelfName(), func(reader stoabs.Reader) error {
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

			dbEvent.Retries++
			if p.isPersistent() {
				if err := p.db.WriteShelf(p.shelfName(), func(writer stoabs.Writer) error {
					return p.writeEvent(writer, *dbEvent)
				}); err != nil {
					return retry.Unrecoverable(err)
				}
			}

			if finished, err := p.receiver(*dbEvent); err != nil {
				log.Logger().Errorf("retry for %s receiver failed (ref=%s)", p.name, dbEvent.Hash.String())
			} else if finished {
				return p.Finished(dbEvent.Hash)
			}

			// has to return an error since `retry.Do` needs to retry until it's marked as finished
			return fmt.Errorf("event is not yet handled by receiver (count=%d, max=%d)", dbEvent.Retries, maxRetries)
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
			log.Logger().Errorf("retry for %s receiver failed (ref=%s): %v", p.name, event.Hash.String(), err)
		}
	}(p.ctx)
}

func (p *notifier) writeEvent(writer stoabs.Writer, event Event) error {
	bytes, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return writer.Put(stoabs.BytesKey(event.Hash.Slice()), bytes)
}

func (p *notifier) readEvent(reader stoabs.Reader, hash hash.SHA256Hash) (*Event, error) {
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

func (p *notifier) Finished(hash hash.SHA256Hash) error {
	if !p.isPersistent() {
		return nil
	}
	return p.db.WriteShelf(p.shelfName(), func(writer stoabs.Writer) error {
		return writer.Delete(stoabs.BytesKey(hash.Slice()))
	})
}

func (p *notifier) Close() error {
	p.cancel()
	return nil
}
