// Nutstx implements Nuts transaction appliance.
package nutstx

import (
	"context"
	"errors"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/stream"
)

// Feed Aggregates from the event-stream.
type Feed struct {
	Aggregates []Aggregate
	lastLiveMS atomic.Int64
}

// SyncFrom updates Appender continuously until it encounters a retrieval error.
func (f *Feed) SyncFrom(ctx context.Context, source stream.Iterator) error {
	backoff := time.NewTicker(200 * time.Millisecond)
	defer backoff.Stop()

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		event, err := source.NextEvent()
		switch err {
		case nil:
			f.applyEvent(event)

		case stream.NoData:
			select {
			case tick := <-backoff.C:
				// The tick can be old but that's OK.
				// It will catch up at some point.
				// Noth worth an additional time.Now.
				f.lastLiveMS.Store(tick.UnixMilli())
			case <-ctx.Done():
				return ctx.Err()
			}

		default:
			return err
		}
	}
}

func (f *Feed) applyEvent(e stream.Event) {
	msg, err := jws.ParseString(e.JWS)
	if err != nil {
		log.Printf("nutstx: unusable JWS %q from event-stream: %s", e.JWS, err)
		return
	}

	sigs := msg.Signatures()
	if l := len(sigs); l != 1 {
		log.Printf("nutstx: got JWS %q with %d signatures from event-stream", e.JWS, l)
		return
	}
	h := sigs[0].ProtectedHeaders()

	var wg sync.WaitGroup
	wg.Add(len(f.Aggregates))
	for _, a := range f.Aggregates {
		go func(a Aggregate) {
			defer wg.Done()
			a.ApplyEvent(e, h)
		}(a)
	}
	wg.Wait()
}

// InsertionQueue handles inbound events. It deals with the circular dependency,
// in which the SignatureAggregate state leads input validation (at ValidEvent).
//
// Multiple goroutines may invoke methods on an InsertionQueue simultaneously.
type InsertionQueue struct {
	stream.Appender // destination
	stream.Recents  // deduplication
	SignatureAggregate
	*Feed // update state reference
}

// Insert commits a stream.Event if it matches the acceptance criteria.
func (q *InsertionQueue) Insert(ctx context.Context, e stream.Event) error {
	err := ValidEvent(e, q.SignatureAggregate.ByKeyIDOrNil)
	if errors.Is(err, ErrKeyNotFound) {
		// retry with any and all pending transactions applied
		err := q.awaitLiveAfter(ctx, time.Now())
		if err != nil {
			return err
		}
		err = ValidEvent(e, q.SignatureAggregate.ByKeyIDOrNil)
	}
	if err != nil {
		return err
	}

	if q.SeenRecently(e) {
		return nil // already present
	}

	err = q.AppendEvent(e)
	if err != nil {
		if errors.Is(err, stream.ErrSizeMax) {
			return err
		}
		// 🚨 event-stream malfuntion is fatal
		log.Fatal("exit on: ", err)
	}

	return nil
}

func (q *InsertionQueue) awaitLiveAfter(ctx context.Context, t time.Time) error {
	var wait *time.Ticker // lazy initiation
	for {
		last := q.Feed.LastLive()
		if last.After(t) {
			return nil
		}

		if wait == nil {
			wait = time.NewTicker(time.Second)
			defer wait.Stop()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-wait.C:
			continue
		}
	}
}

// LastLive returns the most recent moment where Appender reached
// the latest event-stream entry available, with zero for never.
func (f *Feed) LastLive() time.Time {
	ms := f.lastLiveMS.Load()
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms)
}
