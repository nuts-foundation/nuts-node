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
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/avast/retry-go/v4"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/log"
)

const offerQueueShelfName = "openid4vci_offer_queue"

// offerRetryWindow is the maximum total wall-clock time an offer is retried for, counted from the first
// failed attempt (across restarts, since it's read from persisted state), before the offer is considered
// dead-lettered and the give-up callback is invoked. Modeled on the private-payload-fetch notifier
// (network/dag/notifier.go), which bounds retries the same way, but by attempt count within a delay cap
// rather than a fixed wall-clock window; a window fits this use case better since delivery here depends on
// a remote party's node being reachable/fixed, not on local retry cadence.
var offerRetryWindow = 24 * time.Hour

// offerRetryInitialDelay is the delay before the first retry; it then increases (with jitter) after every
// subsequent failure, capped at offerRetryMaxDelay. Matches the starting delay already used by
// network/dag/notifier.go's default.
var offerRetryInitialDelay = time.Second

// offerRetryMaxDelay caps the delay between individual retry attempts, so a job still checks in reasonably
// often across the full offerRetryWindow instead of the delay growing unbounded.
var offerRetryMaxDelay = time.Hour

// offerAttemptFn attempts to deliver a single credential offer. Returning nil means delivery succeeded.
type offerAttemptFn func(ctx context.Context, credential vc.VerifiableCredential) error

// offerGiveUpFn is called exactly once, when an offer's retry window has been exhausted without success.
type offerGiveUpFn func(ctx context.Context, credential vc.VerifiableCredential)

// errOfferNoLongerSupported signals that OpenID4VCI is no longer usable for this offer (e.g. the wallet or
// issuer stopped supporting it between retries) and that retrying further won't help.
var errOfferNoLongerSupported = errors.New("wallet or issuer no longer supports OpenID4VCI")

// offerJob is the persisted state of a single retrying credential offer.
type offerJob struct {
	Credential   vc.VerifiableCredential `json:"credential"`
	FirstAttempt time.Time               `json:"firstAttempt"`
	Retries      int                     `json:"retries"`
	Latest       *time.Time              `json:"latest,omitempty"`
	Error        string                  `json:"error,omitempty"`
	// GivenUp indicates the retry window was exhausted; the offer is dead-lettered.
	GivenUp bool `json:"givenUp,omitempty"`
}

// offerQueueShutdownGrace bounds how long Close() waits for in-flight retry goroutines to actually stop
// after being cancelled, before giving up on the wait and returning anyway. A well-behaved attempt (HTTP
// call using the per-job context) should stop almost immediately; this is a safety net against one that
// doesn't, so node shutdown can't hang forever on it.
var offerQueueShutdownGrace = 5 * time.Second

// offerQueue is a persistent, retrying queue for OpenID4VCI credential offers that failed on the initial
// synchronous attempt. Modeled on network/dag's private-payload-fetch notifier: durable per-job state,
// exponential backoff via retry-go, but bounded by a fixed total retry window rather than an attempt count.
type offerQueue struct {
	db      stoabs.KVStore
	attempt offerAttemptFn
	giveUp  offerGiveUpFn
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// newOfferQueue creates an offerQueue backed by db. attempt is called for every (re)try; giveUp is called
// once when an offer's retry window is exhausted.
func newOfferQueue(db stoabs.KVStore, attempt offerAttemptFn, giveUp offerGiveUpFn) *offerQueue {
	ctx, cancel := context.WithCancel(context.Background())
	return &offerQueue{
		db:      db,
		attempt: attempt,
		giveUp:  giveUp,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Schedule persists the credential and starts retrying its offer in the background.
func (q *offerQueue) Schedule(credential vc.VerifiableCredential) error {
	job := offerJob{
		Credential:   credential,
		FirstAttempt: time.Now(),
	}
	if err := q.save(job); err != nil {
		return err
	}
	q.spawn(job)
	return nil
}

// Run resumes retrying every persisted offer that hasn't given up yet. Call once at startup.
func (q *offerQueue) Run() error {
	jobs, err := q.all()
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if job.GivenUp {
			continue
		}
		q.spawn(job)
	}
	return nil
}

// GetFailedOffers returns offers whose retry window has been exhausted (dead-lettered).
func (q *offerQueue) GetFailedOffers() ([]offerJob, error) {
	jobs, err := q.all()
	if err != nil {
		return nil, err
	}
	var failed []offerJob
	for _, job := range jobs {
		if job.GivenUp {
			failed = append(failed, job)
		}
	}
	return failed, nil
}

// Close stops all in-flight retries and waits (up to offerQueueShutdownGrace) for them to actually return,
// so a caller closing the underlying store right after Close() returns doesn't race an in-flight save().
// Persisted jobs are left untouched; Run() picks them back up on the next startup.
func (q *offerQueue) Close() error {
	q.cancel()
	stopped := make(chan struct{})
	go func() {
		q.wg.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(offerQueueShutdownGrace):
		log.Logger().Warn("Timed out waiting for OpenID4VCI offer retries to stop; some may still be running")
	}
	return nil
}

// spawn starts (or resumes) retrying job in the background, tracked by q.wg so Close() can wait for it.
func (q *offerQueue) spawn(job offerJob) {
	q.wg.Add(1)
	go func() {
		defer q.wg.Done()
		q.retry(job)
	}()
}

func (q *offerQueue) retry(job offerJob) {
	deadline := job.FirstAttempt.Add(offerRetryWindow)
	ctx, cancel := context.WithDeadline(q.ctx, deadline)
	defer cancel()

	// retry.Do calls the given function immediately on its first attempt; delay only applies *between*
	// attempts. But the offer was already attempted once synchronously, right before it was scheduled
	// (that's why it's here), so wait before this first retry rather than immediately re-attempting a
	// very likely still-failing operation.
	select {
	case <-time.After(offerRetryInitialDelay):
	case <-ctx.Done():
		// No attempt has been made in this run yet, so ctx.Err() alone (e.g. "context deadline exceeded")
		// carries no delivery-failure detail. Keep whatever real error a previous run already recorded
		// (job.Error, persisted by OnRetry below) rather than overwriting it with a bare context error.
		deadlineErr := ctx.Err()
		if job.Error != "" {
			deadlineErr = fmt.Errorf("%w (last recorded error: %s)", deadlineErr, job.Error)
		}
		q.settle(job, deadlineErr)
		return
	}

	err := retry.Do(func() error {
		return q.attempt(ctx, job.Credential)
	},
		retry.Context(ctx),
		retry.Attempts(0), // unbounded attempts; the context deadline is the real bound
		retry.Delay(offerRetryInitialDelay),
		retry.MaxDelay(offerRetryMaxDelay),
		retry.MaxJitter(offerRetryInitialDelay),
		retry.DelayType(retry.CombineDelay(retry.BackOffDelay, retry.RandomDelay)),
		retry.LastErrorOnly(true),
		// Without this, retry.Do() returns a bare context error (e.g. "context deadline exceeded") when the
		// offerRetryWindow deadline is hit between attempts, discarding the actual last delivery failure -
		// exactly the detail a dead-lettered job's persisted Error should show an operator.
		retry.WrapContextErrorWithLastError(true),
		retry.OnRetry(func(n uint, retryErr error) {
			job.Retries++
			now := time.Now()
			job.Latest = &now
			job.Error = retryErr.Error()
			if saveErr := q.save(job); saveErr != nil {
				log.Logger().WithError(saveErr).Warn("Failed to persist OpenID4VCI offer retry state")
			}
			log.Logger().
				WithError(retryErr).
				WithField(core.LogFieldCredentialID, job.Credential.ID.String()).
				Debugf("Retrying OpenID4VCI credential offer (attempt %d)", n)
		}),
	)
	q.settle(job, err)
}

// settle handles the outcome of a retry() run, whether from retry.Do itself or from the pre-first-attempt
// wait being cancelled before ever calling attempt.
func (q *offerQueue) settle(job offerJob, err error) {
	if err == nil {
		if finishErr := q.finish(job); finishErr != nil {
			log.Logger().WithError(finishErr).Warn("Failed to remove finished OpenID4VCI offer from retry queue")
		}
		return
	}
	if errors.Is(q.ctx.Err(), context.Canceled) {
		// Queue was closed (e.g. node shutting down), not the job's own deadline. Leave it persisted as-is;
		// Run() resumes it on the next startup, still counting from its original FirstAttempt.
		return
	}
	// Either the retry window (24h) was exhausted, or the offer became unsupported (errOfferNoLongerSupported).
	job.GivenUp = true
	now := time.Now()
	job.Latest = &now
	job.Error = err.Error()
	if saveErr := q.save(job); saveErr != nil {
		log.Logger().WithError(saveErr).Warn("Failed to persist OpenID4VCI offer as given up")
	}
	q.giveUp(q.ctx, job.Credential)
}

// Persistence operations deliberately use context.Background() rather than q.ctx: q.ctx is cancelled by
// Close() to stop in-flight retries, but reading/writing the persisted queue (e.g. from GetFailedOffers(),
// callable independently of whether the queue is still running) must keep working regardless.

func (q *offerQueue) save(job offerJob) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	return q.db.WriteShelf(context.Background(), offerQueueShelfName, func(writer stoabs.Writer) error {
		return writer.Put(stoabs.BytesKey(job.Credential.ID.String()), data)
	})
}

func (q *offerQueue) finish(job offerJob) error {
	return q.db.WriteShelf(context.Background(), offerQueueShelfName, func(writer stoabs.Writer) error {
		return writer.Delete(stoabs.BytesKey(job.Credential.ID.String()))
	})
}

func (q *offerQueue) all() ([]offerJob, error) {
	var jobs []offerJob
	err := q.db.ReadShelf(context.Background(), offerQueueShelfName, func(reader stoabs.Reader) error {
		return reader.Iterate(func(_ stoabs.Key, v []byte) error {
			var job offerJob
			if err := json.Unmarshal(v, &job); err != nil {
				return err
			}
			jobs = append(jobs, job)
			return nil
		}, stoabs.BytesKey{})
	})
	return jobs, err
}
