package openid4vci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"sync"
	"sync/atomic"
	"time"
)

type FlowStore interface {
	// Store saves a new Flow in the store.
	Store(ctx context.Context, flow Flow) error
	// StoreReference saves a reference to the given Flow, for looking it up later.
	// This is used for finding a flow given a secret, e.g. pre-authorized code, authorization code or nonce.
	// like a database index. The reference must be unique for all flows.
	// The expiry is the time-to-live for the reference. After this time, the reference is automatically deleted.
	// If the flow does not exist, or the reference does already exist, it returns an error.
	StoreReference(ctx context.Context, flowID string, refType string, reference string, expiry time.Time) error
	// FindByReference finds a Flow by its reference.
	// If the flow does not exist, it returns nil.
	FindByReference(ctx context.Context, refType string, reference string) (*Flow, error)
	// DeleteReference deletes the reference from the store.
	// It does not return an error if it doesn't exist anymore.
	DeleteReference(ctx context.Context, refType string, reference string) error
}

var _ FlowStore = (*flowStore)(nil)

const flowsShelf = "flows"
const referencesShelf = "refs"
const pruneInterval = 10 * time.Minute

type flowStore struct {
	store     stoabs.KVStore
	lastPrune atomic.Pointer[time.Time]
	pruneMux  *sync.Mutex
}

type referenceValue struct {
	FlowID string    `json:"flow_id"`
	Expiry time.Time `json:"exp"`
}

func (o *flowStore) Store(ctx context.Context, flow Flow) error {
	return o.store.WriteShelf(ctx, flowsShelf, func(writer stoabs.Writer) error {
		// Check if it doesn't already exist
		exists, err := o.flowExists(writer, flow.ID)
		if err != nil {
			return err
		}
		if exists {
			return errors.New("OAuth2 flow with this ID already exists")
		}
		data, _ := json.Marshal(o.store)
		return writer.Put(stoabs.BytesKey(flow.ID), data)
	})
}

func (o *flowStore) StoreReference(ctx context.Context, flowID string, refType string, reference string, expiry time.Time) error {
	o.pruneIfStale(time.Now())
	if len(reference) == 0 {
		return errors.New("invalid reference")
	}
	if err := o.validateFlowExists(ctx, flowID); err != nil {
		return err
	}
	return o.store.WriteShelf(ctx, referencesShelf, func(writer stoabs.Writer) error {
		_, err := writer.Get(o.refKey(refType, reference))
		if err == nil {
			return errors.New("reference already exists")
		}
		if !errors.Is(err, stoabs.ErrKeyNotFound) {
			return err
		}
		data, _ := json.Marshal(referenceValue{FlowID: flowID, Expiry: expiry})
		return writer.Put(o.refKey(refType, reference), data)
	})
}

func (o *flowStore) FindByReference(ctx context.Context, refType string, reference string) (*Flow, error) {
	o.pruneIfStale(time.Now())
	var flowID string
	err := o.store.ReadShelf(ctx, referencesShelf, func(reader stoabs.Reader) error {
		valueBytes, err := reader.Get(o.refKey(refType, reference))
		if errors.Is(err, stoabs.ErrKeyNotFound) {
			// Reference not found
			return nil
		}
		if err != nil {
			// Other error occurred
			return err
		}
		var value referenceValue
		err = json.Unmarshal(valueBytes, &value)
		if err != nil {
			return fmt.Errorf("invalid stored reference: %w", err)
		}
		if value.Expiry.Before(time.Now()) {
			// Reference expired
			return nil
		}
		flowID = value.FlowID
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(flowID) == 0 {
		return nil, nil
	}
	var result *Flow
	err = o.store.ReadShelf(ctx, flowsShelf, func(reader stoabs.Reader) error {
		flowBytes, err := reader.Get(stoabs.BytesKey(flowID))
		if errors.Is(err, stoabs.ErrKeyNotFound) {
			// Flow not found
			return nil
		}
		if err != nil {
			// Other error occurred
			return err
		}
		var flow Flow
		if err := json.Unmarshal(flowBytes, &flow); err != nil {
			return fmt.Errorf("invalid stored flow: %w", err)
		}
		if flow.Expiry.Before(time.Now()) {
			// Flow expired
			return nil
		}
		result = &flow
		return nil
	})
	return result, err
}

func (o *flowStore) DeleteReference(ctx context.Context, refType string, reference string) error {
	o.pruneIfStale(time.Now())
	return o.store.WriteShelf(ctx, referencesShelf, func(writer stoabs.Writer) error {
		return writer.Delete(o.refKey(refType, reference))
	})
}

// pruneIfStale checks if the last prune was more than 10 minutes ago and if so, starts a new prune operation.
// Pruning is only intended to clean up old references, so it's not a problem if it's not done immediately after a flow or reference expired.
func (o *flowStore) pruneIfStale(moment time.Time) {
	// If TryLock fails, another prune operation is already running and this one can be skipped.
	if o.pruneMux.TryLock() {
		defer o.pruneMux.Unlock()
		lastPrune := o.lastPrune.Load()
		if lastPrune == nil || time.Since(*lastPrune) > pruneInterval {
			o.lastPrune.Store(&moment)
			// Actual prune is non-blocking
			go func() {
				referencesPruned, err := o.prune(context.Background())
				if err != nil {
					log.Logger().WithError(err).Errorf("Failed to prune OpenID4VCI flow references")
				}
				if referencesPruned > 0 {
					log.Logger().Debugf("Pruned %d expired OpenID4VCI flow references", referencesPruned)
				}
			}()
		}
	}
}

func (o *flowStore) prune(ctx context.Context) (int, error) {
	var count int
	return count, o.store.WriteShelf(ctx, referencesShelf, func(writer stoabs.Writer) error {
		// Find expired references and delete them
		err := writer.Iterate(func(key stoabs.Key, value []byte) error {
			var ref referenceValue
			err := json.Unmarshal(value, &ref)
			if err == nil && ref.Expiry.Before(time.Now()) {
				count++
				return writer.Delete(key)
			}
			return nil
		}, stoabs.BytesKey{})
		return err
	})
}

func (o *flowStore) validateFlowExists(ctx context.Context, flowID string) error {
	// There's a small chance for a race condition here,
	// the flow could be deleted between the existence check and subsequent actions (e.g. writing an access token).
	// Since there are no foreign keys in the store, the access token will be orphaned.
	// But one or two orphaned access tokens won't hurt, since they can't be used anyway.
	return o.store.ReadShelf(ctx, flowsShelf, func(reader stoabs.Reader) error {
		exists, err := o.flowExists(reader, flowID)
		if err != nil {
			return err
		}
		if !exists {
			return errors.New("OAuth2 flow with this ID does not exist")
		}
		return nil
	})
}

func (o *flowStore) flowExists(reader stoabs.Reader, flowID string) (bool, error) {
	if len(flowID) == 0 {
		return false, errors.New("invalid ID")
	}
	_, err := reader.Get(stoabs.BytesKey(flowID))
	if err == nil {
		return true, nil
	}
	if !errors.Is(err, stoabs.ErrKeyNotFound) {
		return false, err
	}
	return false, nil
}

func (o *flowStore) refKey(refType string, reference string) stoabs.BytesKey {
	return stoabs.BytesKey(refType + ":" + reference)
}
