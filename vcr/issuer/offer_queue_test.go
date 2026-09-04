/*
 * Copyright (C) 2026 Nuts community
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

package issuer

import (
	"context"
	"errors"
	"path"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avast/retry-go/v4"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/go-stoabs/bbolt"
	"github.com/stretchr/testify/require"
)

func testOfferQueueCredential(t *testing.T, id string) vc.VerifiableCredential {
	uri := ssi.MustParseURI(id)
	return vc.VerifiableCredential{
		ID:                &uri,
		Issuer:            ssi.MustParseURI("did:nuts:issuer"),
		CredentialSubject: []map[string]any{{"id": "did:nuts:holder"}},
	}
}

func testOfferQueueStore(t *testing.T) stoabs.KVStore {
	dbPath := path.Join(t.TempDir(), "offer_queue.db")
	db, err := bbolt.CreateBBoltStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close(context.Background()) })
	return db
}

// withFastRetryTiming overrides the package-level retry timing vars for the duration of the test.
func withFastRetryTiming(t *testing.T, window time.Duration) {
	originalWindow, originalInitial, originalMax := offerRetryWindow, offerRetryInitialDelay, offerRetryMaxDelay
	offerRetryWindow = window
	offerRetryInitialDelay = time.Millisecond
	offerRetryMaxDelay = 10 * time.Millisecond
	t.Cleanup(func() {
		offerRetryWindow, offerRetryInitialDelay, offerRetryMaxDelay = originalWindow, originalInitial, originalMax
	})
}

func TestOfferQueue_Schedule(t *testing.T) {
	t.Run("succeeds on first attempt", func(t *testing.T) {
		withFastRetryTiming(t, time.Second)
		db := testOfferQueueStore(t)
		var attempts atomic.Int32
		done := make(chan struct{})
		q := newOfferQueue(db,
			func(_ context.Context, _ vc.VerifiableCredential) error {
				attempts.Add(1)
				close(done)
				return nil
			},
			func(_ context.Context, _ vc.VerifiableCredential) { t.Fatal("giveUp should not be called") },
		)
		t.Cleanup(func() { _ = q.Close() })

		require.NoError(t, q.Schedule(testOfferQueueCredential(t, "did:nuts:issuer#1")))

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for attempt")
		}
		require.Equal(t, int32(1), attempts.Load())

		// Finished offers are removed from the persisted queue.
		require.Eventually(t, func() bool {
			jobs, err := q.all()
			require.NoError(t, err)
			return len(jobs) == 0
		}, time.Second, 10*time.Millisecond)
	})

	t.Run("retries after a failure, then succeeds", func(t *testing.T) {
		withFastRetryTiming(t, time.Second)
		db := testOfferQueueStore(t)
		var attempts atomic.Int32
		done := make(chan struct{})
		q := newOfferQueue(db,
			func(_ context.Context, _ vc.VerifiableCredential) error {
				if attempts.Add(1) < 3 {
					return errors.New("transient failure")
				}
				close(done)
				return nil
			},
			func(_ context.Context, _ vc.VerifiableCredential) { t.Fatal("giveUp should not be called") },
		)
		t.Cleanup(func() { _ = q.Close() })

		require.NoError(t, q.Schedule(testOfferQueueCredential(t, "did:nuts:issuer#2")))

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for eventual success")
		}
		require.GreaterOrEqual(t, attempts.Load(), int32(3))
	})

	t.Run("gives up once the retry window is exhausted", func(t *testing.T) {
		// A generous window relative to the 1ms initial delay set by withFastRetryTiming: needs enough
		// margin that at least one attempt reliably completes before the deadline, even under scheduling
		// jitter/CPU contention in CI, while still keeping the test itself fast.
		withFastRetryTiming(t, 500*time.Millisecond)
		db := testOfferQueueStore(t)
		var attempts atomic.Int32
		givenUp := make(chan vc.VerifiableCredential, 1)
		q := newOfferQueue(db,
			func(_ context.Context, _ vc.VerifiableCredential) error {
				attempts.Add(1)
				return errors.New("permanent failure: wallet unreachable")
			},
			func(_ context.Context, credential vc.VerifiableCredential) {
				givenUp <- credential
			},
		)
		t.Cleanup(func() { _ = q.Close() })

		credential := testOfferQueueCredential(t, "did:nuts:issuer#3")
		require.NoError(t, q.Schedule(credential))

		select {
		case got := <-givenUp:
			require.Equal(t, credential.ID.String(), got.ID.String())
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for give-up")
		}
		require.Greater(t, attempts.Load(), int32(0))

		// The dead-lettered job stays persisted, marked as given up.
		failed, err := q.GetFailedOffers()
		require.NoError(t, err)
		require.Len(t, failed, 1)
		require.True(t, failed[0].GivenUp)
		require.Equal(t, credential.ID.String(), failed[0].Credential.ID.String())
		// The persisted Error must show why delivery kept failing, not just that the window ran out:
		// retry.Do() would otherwise discard the last real error in favor of a bare context error once
		// the deadline is hit between attempts (see retry.WrapContextErrorWithLastError in offer_queue.go).
		require.Contains(t, failed[0].Error, "wallet unreachable")
	})

	t.Run("an unrecoverable error stops retrying immediately", func(t *testing.T) {
		// The queue itself has no special-cased errors; it's the caller's job to wrap an error with
		// retry.Unrecoverable() to signal "don't bother retrying" (this is exactly what
		// issuer.retryOfferAttempt does for errOfferNoLongerSupported - see issuer_test.go for that).
		withFastRetryTiming(t, time.Second)
		db := testOfferQueueStore(t)
		var attempts atomic.Int32
		givenUp := make(chan struct{})
		q := newOfferQueue(db,
			func(_ context.Context, _ vc.VerifiableCredential) error {
				attempts.Add(1)
				return retry.Unrecoverable(errOfferNoLongerSupported)
			},
			func(_ context.Context, _ vc.VerifiableCredential) { close(givenUp) },
		)
		t.Cleanup(func() { _ = q.Close() })

		require.NoError(t, q.Schedule(testOfferQueueCredential(t, "did:nuts:issuer#4")))

		select {
		case <-givenUp:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for give-up")
		}
		require.Equal(t, int32(1), attempts.Load())
	})
}

func TestOfferQueue_Run(t *testing.T) {
	t.Run("resumes a persisted job from a previous run", func(t *testing.T) {
		withFastRetryTiming(t, time.Second)
		db := testOfferQueueStore(t)
		credential := testOfferQueueCredential(t, "did:nuts:issuer#5")

		// Simulate state left behind by a previous process, as if Schedule() had run then the process
		// stopped before the job finished.
		bootstrapQueue := newOfferQueue(db, nil, nil)
		require.NoError(t, bootstrapQueue.save(offerJob{Credential: credential, FirstAttempt: time.Now()}))

		done := make(chan struct{})
		q := newOfferQueue(db,
			func(_ context.Context, _ vc.VerifiableCredential) error {
				close(done)
				return nil
			},
			func(_ context.Context, _ vc.VerifiableCredential) { t.Fatal("giveUp should not be called") },
		)
		t.Cleanup(func() { _ = q.Close() })

		require.NoError(t, q.Run())

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for resumed job to be retried")
		}
	})

	t.Run("does not resume a job that already gave up", func(t *testing.T) {
		withFastRetryTiming(t, time.Second)
		db := testOfferQueueStore(t)
		credential := testOfferQueueCredential(t, "did:nuts:issuer#6")

		bootstrapQueue := newOfferQueue(db, nil, nil)
		require.NoError(t, bootstrapQueue.save(offerJob{Credential: credential, FirstAttempt: time.Now(), GivenUp: true}))

		q := newOfferQueue(db,
			func(_ context.Context, _ vc.VerifiableCredential) error {
				t.Fatal("attempt should not be called for an already given-up job")
				return nil
			},
			func(_ context.Context, _ vc.VerifiableCredential) { t.Fatal("giveUp should not be called again") },
		)
		t.Cleanup(func() { _ = q.Close() })

		require.NoError(t, q.Run())
		time.Sleep(50 * time.Millisecond) // give any (unwanted) goroutine a chance to run
	})
}

func TestOfferQueue_Close(t *testing.T) {
	t.Run("stops in-flight retries without marking the job given up", func(t *testing.T) {
		withFastRetryTiming(t, time.Second)
		db := testOfferQueueStore(t)
		attempted := make(chan struct{}, 10)
		q := newOfferQueue(db,
			func(_ context.Context, _ vc.VerifiableCredential) error {
				select {
				case attempted <- struct{}{}:
				default:
				}
				return errors.New("still failing")
			},
			func(_ context.Context, _ vc.VerifiableCredential) { t.Fatal("giveUp should not be called on shutdown") },
		)

		credential := testOfferQueueCredential(t, "did:nuts:issuer#7")
		require.NoError(t, q.Schedule(credential))

		select {
		case <-attempted:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for first attempt")
		}
		require.NoError(t, q.Close()) // blocks until the retry goroutine has actually stopped

		jobs, err := q.all()
		require.NoError(t, err)
		require.Len(t, jobs, 1)
		require.False(t, jobs[0].GivenUp)
	})

	t.Run("blocks until an in-flight attempt returns", func(t *testing.T) {
		withFastRetryTiming(t, time.Second)
		db := testOfferQueueStore(t)
		inAttempt := make(chan struct{})
		releaseAttempt := make(chan struct{})
		var attemptReturned atomic.Bool
		q := newOfferQueue(db,
			func(_ context.Context, _ vc.VerifiableCredential) error {
				close(inAttempt)
				<-releaseAttempt
				attemptReturned.Store(true)
				return errors.New("still failing")
			},
			func(_ context.Context, _ vc.VerifiableCredential) { t.Fatal("giveUp should not be called on shutdown") },
		)

		require.NoError(t, q.Schedule(testOfferQueueCredential(t, "did:nuts:issuer#8")))
		select {
		case <-inAttempt:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for the attempt to start")
		}

		closeDone := make(chan struct{})
		go func() {
			require.NoError(t, q.Close())
			close(closeDone)
		}()

		select {
		case <-closeDone:
			t.Fatal("Close() returned before the in-flight attempt returned")
		case <-time.After(100 * time.Millisecond):
		}

		close(releaseAttempt)
		select {
		case <-closeDone:
		case <-time.After(5 * time.Second):
			t.Fatal("Close() did not return after the in-flight attempt returned")
		}
		require.True(t, attemptReturned.Load())
	})

	t.Run("gives up waiting after the shutdown grace period", func(t *testing.T) {
		withFastRetryTiming(t, time.Second)
		original := offerQueueShutdownGrace
		offerQueueShutdownGrace = 50 * time.Millisecond
		t.Cleanup(func() { offerQueueShutdownGrace = original })

		db := testOfferQueueStore(t)
		stuck := make(chan struct{})
		q := newOfferQueue(db,
			func(_ context.Context, _ vc.VerifiableCredential) error {
				<-stuck // never returns on its own; ignores cancellation, like a misbehaving attempt would
				return nil
			},
			func(_ context.Context, _ vc.VerifiableCredential) {},
		)
		t.Cleanup(func() { close(stuck) })

		require.NoError(t, q.Schedule(testOfferQueueCredential(t, "did:nuts:issuer#9")))

		start := time.Now()
		require.NoError(t, q.Close())
		require.Less(t, time.Since(start), time.Second, "Close() should have given up waiting after the grace period")
	})
}
