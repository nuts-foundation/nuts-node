// Nutstx implements Nuts transaction appliance.
package nutstx

import (
	"context"
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/jws"
	"github.com/nuts-foundation/nuts-node/stream"
)

// SyncFrom applies the stream to the Aggregates until end-of-stream.
func SyncFrom(source stream.Iterator, dst ...Aggregate) error {
	for {
		event, err := source.NextEvent()
		if err != nil {
			if errors.Is(err, stream.NoData) {
				return nil // OK
			}
			return err
		}
		applyEvent(event, dst)
	}
}

func applyEvent(e stream.Event, aggs []Aggregate) {
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
	wg.Add(len(aggs))
	for _, a := range aggs {
		go func(a Aggregate) {
			defer wg.Done()
			a.ApplyEvent(e, h)
		}(a)
	}
	wg.Wait()
}

// View provides live aggregates from an event stream.
type View struct {
	liveQueue chan live
	livePool  sync.Pool

	filePath string
}

type live struct {
	*AggregateSet
	time.Time
	stream.Iterator
}

// NewFileView follows a file (from stream.OpenAppender).
func NewFileView(file string, queueN int) *View {
	v := View{
		liveQueue: make(chan live, queueN),
		filePath:  file,
	}
	go v.enqueueN(queueN)
	return &v
}

var ErrLiveFuture = errors.New("nutstx: live view from future not available")

// LiveSince returns aggregates no older than notBefore.
func (v *View) LiveSince(ctx context.Context, notBefore time.Time) (*AggregateSet, time.Time, error) {
	tolerance := time.Since(notBefore)
	if tolerance < 0 {
		return nil, time.Time{}, ErrLiveFuture
	}

	// pool cache only works with some tollerance
	for tolerance >= time.Second {
		p := v.livePool.Get()
		if p == nil {
			break // empty
		}
		l := p.(live)
		if l.Time.Before(notBefore) {
			continue // discard old
		}
		v.livePool.Put(l) // reuse
		return l.AggregateSet, l.Time, nil
	}

	// roll queue until within tolerance
	for {
		select {
		case l := <-v.liveQueue:
			if l.Time.Before(notBefore) {
				// too old; back in line
				go v.freshen(l)
				continue
			}

			go v.fork(l)

			return l.AggregateSet, l.Time, nil

		case <-ctx.Done():
			return nil, time.Time{}, ctx.Err()
		}
	}
}

// Freshen gets l all remaining events (since the last .Time) and it enquies l
// back into liveQueue.
func (v *View) freshen(l live) {
	err := SyncFrom(l.Iterator, l.AggregateSet.List()...)
	if err != nil {
		log.Print("nutstx: aggregate set stranded on event stream read: ", err)
		if err := l.Iterator.Close(); err != nil {
			log.Print(err)
		}
		v.enqueueN(1) // replace with new
		return        // discards l
	}
	v.liveQueue <- l // requeue
}

// Fork uses the Iterator and the snapshots from l to branch of a new child into
// liveQueue.
func (v *View) fork(l live) {
	child := live{
		AggregateSet: NewAggregateSet(),
		Iterator:     l.Iterator, // pass
	}
	childAggs := child.List()
	aggs := l.List()

	// copy snapshots of each aggregate
	errs := make(chan error, len(aggs))
	for i := range aggs {
		go func(i int) {
			r, w := io.Pipe()
			go func() {
				w.CloseWithError(aggs[i].WriteTo(w))
			}()
			errs <- childAggs[i].ReadFrom(r)
		}(i)
	}

	var fatal bool
	for range aggs {
		err := <-errs
		if err != nil {
			log.Print("nutstx: live set stranded on ", err)
			fatal = true
		}
	}
	if fatal {
		v.enqueueN(1) // start form scratch
	} else {
		v.freshen(child)
	}
}

func (v *View) enqueueN(n int) {
	for i := 0; i < n; i++ {
		set := NewAggregateSet()
		source := stream.OpenIterator(v.filePath)
		err := SyncFrom(source, set.List()...)
		if err != nil {
			backoff := 5 * time.Second
			t := time.NewTimer(backoff)
			log.Printf("nutstx: event-stream launch retry in %s on: %s", backoff, err)
			if err := source.Close(); err != nil {
				log.Print(err)
			}
			<-t.C
			continue
		}

		v.liveQueue <- live{
			AggregateSet: set,
			Time:         time.Now(),
			Iterator:     source,
		}
	}
}

// InsertionQueue handles inbound events. It deals with the circular dependency,
// in which the SignatureAggregate state leads input validation (at ValidEvent).
//
// Multiple goroutines may invoke methods on an InsertionQueue simultaneously.
type InsertionQueue struct {
	stream.Appender // destination
	stream.Recents  // deduplication
	*View
}

// Insert commits a stream.Event if it matches the acceptance criteria.
func (q *InsertionQueue) Insert(ctx context.Context, e stream.Event) error {
	err := ValidEvent(ctx, e, q.View.LiveSince)
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
