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
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
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

var timeFunc = time.Now

// maxJitter is adjustable for testing purposes
var maxJitter = time.Second

// EventFatal signals that an Event receiver encountered a fatal error and that the Event should not be retried.
type EventFatal struct {
	Err error
}

func (e EventFatal) Error() string {
	// Sprintf in case Err == nil
	return fmt.Sprintf("%s", e.Err)
}

func (e EventFatal) Unwrap() error {
	return e.Err
}

// Notifier defines methods for a persistent retry mechanism.
// Storing the event in the DB is separated from notifying the subscribers.
// The event is sent to subscribers after the transaction is committed to prevent timing issues.
type Notifier interface {
	// Name returns the name of the notifier
	Name() string
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
	// GetFailedEvents retrieves the hashes of failed events.
	// If the notifier is not persistent it'll always return 0.
	GetFailedEvents() ([]Event, error)
	// Close cancels all running events. It does not remove them from the DB
	Close() error
}

// ReceiverFn is the function type that needs to be registered for a notifier
// Returns true if event is received and done, false otherwise
// The Notifier's retry mechanism is aborted when this function's error is wrapped by EventFatal
type ReceiverFn func(event Event) (bool, error)

// NotificationFilter can be added to a notifier to filter out any unwanted events
// Returns true if the filter applies and the Event is to be received
type NotificationFilter func(event Event) bool

// NotifierOption sets an option on a notifier
type NotifierOption func(notifier *notifier)

// Event is the metadata that is stored for a notifier specific event
// The Hash is used as identifier for the Event.
type Event struct {
	// Type of event, can be used to filter
	Type string `json:"type,omitempty"`
	// Hash is the ID of the Event, usually the same as the dag.Transaction.Ref()
	Hash hash.SHA256Hash `json:"Hash"`
	// Retries is the current number of retries
	Retries int `json:"retries"`
	// Latest records the timestamp of the last notification attempt. It is not used in the backoff calculation.
	Latest *time.Time `json:"latest,omitempty"`
	// Transaction that was added to the DAG or for which the Payload was written. Mandatory.
	Transaction Transaction `json:"transaction"`
	// Payload that was written to the PayloadStore, optional (private TXs).
	Payload []byte `json:"payload,omitempty"`
	// Error contains the error of the last try if any.
	Error string `json:"error,omitempty"`
}

func (j *Event) UnmarshalJSON(bytes []byte) error {
	tmp := &struct {
		Type        string          `json:"type,omitempty"`
		Hash        hash.SHA256Hash `json:"Hash"`
		Retries     int             `json:"retries"`
		Latest      *time.Time      `json:"latest,omitempty"`
		Transaction string          `json:"transaction"`
		Payload     []byte          `json:"payload,omitempty"`
		Error       string          `json:"error,omitempty"`
	}{}

	if err := json.Unmarshal(bytes, tmp); err != nil {
		return err
	}

	j.Type = tmp.Type
	j.Hash = tmp.Hash
	j.Retries = tmp.Retries
	j.Latest = tmp.Latest
	j.Payload = tmp.Payload
	j.Error = tmp.Error

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

func withCounters(notifiedCounter prometheus.Counter, finishedCounter prometheus.Counter) NotifierOption {
	return func(notifier *notifier) {
		notifier.notifiedCounter = notifiedCounter
		notifier.finishedCounter = finishedCounter
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
	db              stoabs.KVStore
	name            string
	retryDelay      time.Duration
	receiver        ReceiverFn
	ctx             context.Context
	cancel          context.CancelFunc
	filters         []NotificationFilter
	notifiedCounter prometheus.Counter
	finishedCounter prometheus.Counter
}

func (p notifier) Name() string {
	return p.name
}

func (p notifier) shelfName() string {
	return fmt.Sprintf("_%s_jobs", p.name)
}

func (p notifier) isPersistent() bool {
	return p.db != nil
}

func (p *notifier) Run() error {
	// nothing to run if this notifier is not persistent
	if !p.isPersistent() {
		return nil
	}
	// we're going to retry all events synchronously at startup. For the ones that fail we'll start the retry loop
	failedAtStartup := make([]Event, 0)
	err := p.db.ReadShelf(p.ctx, p.shelfName(), func(reader stoabs.Reader) error {
		return reader.Iterate(func(k stoabs.Key, v []byte) error {
			event := Event{}
			_ = json.Unmarshal(v, &event)

			if err := p.notifyNow(event); err != nil {
				if event.Retries < maxRetries {
					failedAtStartup = append(failedAtStartup, event)
				}
			}

			return nil
		}, stoabs.BytesKey{})
	})
	if err != nil {
		return err
	}

	// for all events from failedAtStartup, call retry
	// this may still produce errors in the logs or even duplicate errors since notifyNow also failed
	// but rather duplicate errors then errors produced from overloading the DB with transactions
	for _, event := range failedAtStartup {
		p.retry(event)
	}
	return nil
}

func (p *notifier) GetFailedEvents() (events []Event, err error) {
	if !p.isPersistent() {
		return []Event{}, nil
	}
	err = p.db.ReadShelf(p.ctx, p.shelfName(), func(reader stoabs.Reader) error {
		return reader.Iterate(func(k stoabs.Key, data []byte) error {
			if data != nil {
				event := Event{}
				_ = json.Unmarshal(data, &event)

				if event.Retries >= retriesFailedThreshold {
					events = append(events, event)
				}
			}
			return nil
		}, stoabs.BytesKey{})
	})

	return
}

func (p *notifier) Save(tx stoabs.WriteTx, event Event) error {
	// non-persistent job
	if p.db == nil {
		return nil
	}

	// check if tx is on the same DB
	if tx.Store() != p.db {
		return errors.New("trying to save Event on different DB")
	}

	writer := tx.GetShelfWriter(p.shelfName())

	// apply filters
	for _, f := range p.filters {
		if !f(event) {
			return nil
		}
	}

	// only schedule new events
	_, err := p.readEvent(writer, event.Hash)
	if errors.Is(err, stoabs.ErrKeyNotFound) {
		return p.writeEvent(writer, event)
	}

	if err != nil {
		return err
	}

	return nil
}

func (p *notifier) Notify(event Event) {
	// apply filters
	for _, f := range p.filters {
		if !f(event) {
			return
		}
	}

	if err := p.notifyNow(event); err != nil {
		notifyErrMsg := "Notify event dropped"
		if !errors.As(err, new(EventFatal)) {
			p.retry(event)
			notifyErrMsg = "Notify event rescheduled"
		}
		if errors.Is(err, errEventIncomplete) {
			p.logNotificationResponse(event, err, logrus.DebugLevel, notifyErrMsg)
		} else {
			p.logNotificationResponse(event, err, logrus.ErrorLevel, notifyErrMsg)
		}
	}
}

func (p *notifier) retry(event Event) {
	delay := p.retryDelay
	initialCount := event.Retries + 1

	for i := 0; i < initialCount; i++ {
		delay *= 2
	}

	go func(ctx context.Context) {
		// also an initial delay
		time.Sleep(delay)
		err := retry.Do(func() error {
			return p.notifyNow(event)
		},
			retry.Attempts(maxRetries-uint(initialCount)),
			retry.MaxDelay(24*time.Hour),
			retry.MaxJitter(maxJitter),
			retry.Delay(delay),
			retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
			retry.Context(ctx),
			retry.LastErrorOnly(true),
			retry.OnRetry(func(n uint, err error) {
				// logs after every failed attempt
				if errors.Is(err, errEventIncomplete) {
					// debug level if errEventIncomplete
					p.logNotificationResponse(event, err, logrus.DebugLevel, "Retrying event (attempt %d/%d)", n, maxRetries)
				} else {
					// error level for all other errors
					p.logNotificationResponse(event, err, logrus.ErrorLevel, "Retrying event (attempt %d/%d)", n, maxRetries)
				}
			}),
		)
		if err != nil {
			// logs after maxRetries failed attempts, or receiving a retry.Unrecoverable() error
			p.logNotificationResponse(event, err, logrus.ErrorLevel, "Retry failed")
		}
	}(p.ctx)
}

func (p *notifier) logNotificationResponse(event Event, err error, level logrus.Level, msg string, args ...interface{}) {
	log.Logger().
		WithError(err).
		WithField(core.LogFieldTransactionRef, event.Hash.String()).
		WithField(core.LogFieldEventSubscriber, p.name).
		Logf(level, msg, args...)
}

var errEventIncomplete = errors.New("receiver did not finish or fail")

// notifyNow is used to call the receiverFn synchronously.
// This is used for the first run and with every retry.
func (p *notifier) notifyNow(event Event) error {
	p.incNotified()

	var dbEvent = &event
	if p.isPersistent() {
		err := p.db.ReadShelf(p.ctx, p.shelfName(), func(reader stoabs.Reader) error {
			var err error
			dbEvent, err = p.readEvent(reader, event.Hash)
			return err
		})
		if err != nil {
			if errors.Is(err, stoabs.ErrKeyNotFound) {
				// no longer exists so done, this stops any go routine
				return nil
			}
			return retry.Unrecoverable(err)
		}
		if dbEvent == nil {
			// no longer exists so done, this stops any go routine
			return nil
		}
	}

	finished, err := p.receiver(*dbEvent)
	if err != nil {
		if errors.As(err, new(EventFatal)) {
			// mark as failed event
			dbEvent.Retries = maxRetries
			err = retry.Unrecoverable(err)
		}
	} else if finished {
		return p.Finished(dbEvent.Hash)
	} else {
		// not sure if the event was handled by the receiver, so must return an error to trigger a retry
		err = errEventIncomplete
	}

	dbEvent.Error = err.Error() // err != nil
	dbEvent.Retries++
	now := timeFunc()
	dbEvent.Latest = &now
	if p.isPersistent() {
		if err := p.db.WriteShelf(p.ctx, p.shelfName(), func(writer stoabs.Writer) error {
			return p.writeEvent(writer, *dbEvent)
		}); err != nil {
			return retry.Unrecoverable(err)
		}
	}

	// has to return an error since `retry.Do` needs to retry until it's marked as finished
	return err
}

func (p *notifier) writeEvent(writer stoabs.Writer, event Event) error {
	bytes, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return writer.Put(stoabs.BytesKey(event.Hash.Slice()), bytes)
}

func (p *notifier) readEvent(reader stoabs.Reader, hash hash.SHA256Hash) (*Event, error) {
	data, err := reader.Get(stoabs.BytesKey(hash.Slice()))
	if err != nil {
		return nil, err
	}

	event := new(Event)
	if err = json.Unmarshal(data, event); err != nil {
		return nil, err
	}

	return event, nil
}

func (p *notifier) Finished(hash hash.SHA256Hash) error {
	p.incFinished()
	if !p.isPersistent() {
		return nil
	}
	return p.db.WriteShelf(p.ctx, p.shelfName(), func(writer stoabs.Writer) error {
		return writer.Delete(stoabs.BytesKey(hash.Slice()))
	})
}

func (p *notifier) Close() error {
	p.cancel()
	return nil
}

func (p *notifier) incFinished() {
	if p.finishedCounter != nil {
		p.finishedCounter.Inc()
	}
}

func (p *notifier) incNotified() {
	if p.notifiedCounter != nil {
		p.notifiedCounter.Inc()
	}
}
