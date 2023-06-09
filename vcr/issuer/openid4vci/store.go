package openid4vci

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-stoabs"
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"sync"
	"time"
)

type Store interface {
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
	// Close signals the store to close any owned resources.
	Close()
}

var _ Store = (*stoabsStore)(nil)

const flowsShelf = "flows"
const referencesShelf = "refs"
const pruneInterval = 10 * time.Minute

type stoabsStore struct {
	store    stoabs.KVStore
	routines *sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewStoabsStore creates a new Store backed by a stoabs.KVStore.
func NewStoabsStore(store stoabs.KVStore) Store {
	result := &stoabsStore{
		store:    store,
		routines: &sync.WaitGroup{},
	}
	result.startPruning()
	return result
}

type referenceValue struct {
	FlowID string    `json:"flow_id"`
	Expiry time.Time `json:"exp"`
}

func (o *stoabsStore) Store(ctx context.Context, flow Flow) error {
	return o.store.WriteShelf(ctx, flowsShelf, func(writer stoabs.Writer) error {
		// Check if it doesn't already exist
		exists, err := o.flowExists(writer, flow.ID)
		if err != nil {
			return err
		}
		if exists {
			return errors.New("OAuth2 flow with this ID already exists")
		}
		data, _ := json.Marshal(flow)
		return writer.Put(stoabs.BytesKey(flow.ID), data)
	})
}

func (o *stoabsStore) StoreReference(ctx context.Context, flowID string, refType string, reference string, expiry time.Time) error {
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

func (o *stoabsStore) FindByReference(ctx context.Context, refType string, reference string) (*Flow, error) {
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

func (o *stoabsStore) DeleteReference(ctx context.Context, refType string, reference string) error {
	return o.store.WriteShelf(ctx, referencesShelf, func(writer stoabs.Writer) error {
		return writer.Delete(o.refKey(refType, reference))
	})
}

func (o *stoabsStore) Close() {
	// Signal pruner to stop and wait for it to finish
	o.cancel()
	o.routines.Wait()
}

func (o *stoabsStore) startPruning() {
	o.ctx, o.cancel = context.WithCancel(context.Background())
	ticker := time.NewTicker(pruneInterval)
	go func() {
		select {
		case <-o.ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
			flowsPruned, refsPruned, err := o.prune(context.Background(), time.Now())
			if err != nil {
				log.Logger().WithError(err).Errorf("Failed to prune OpenID4VCI flows/references")
			}
			if flowsPruned > 0 || refsPruned > 0 {
				log.Logger().Debugf("Pruned %d expired OpenID4VCI flows and %d expired refs", flowsPruned, refsPruned)
			}
		}
	}()
}

func (o *stoabsStore) prune(ctx context.Context, moment time.Time) (int, int, error) {
	var flowCount int
	var refCount int
	var err error
	// Find expired references and delete them
	err = o.store.WriteShelf(ctx, referencesShelf, func(writer stoabs.Writer) error {
		err := writer.Iterate(func(key stoabs.Key, value []byte) error {
			var ref referenceValue
			err := json.Unmarshal(value, &ref)
			if err == nil && ref.Expiry.Before(moment) {
				refCount++
				return writer.Delete(key)
			}
			return nil
		}, stoabs.BytesKey{})
		return err
	})
	if err != nil {
		return flowCount, refCount, err
	}
	// Find expired flows and delete them
	err = o.store.WriteShelf(ctx, flowsShelf, func(writer stoabs.Writer) error {
		err := writer.Iterate(func(key stoabs.Key, value []byte) error {
			var flow Flow
			err := json.Unmarshal(value, &flow)
			if err == nil && flow.Expiry.Before(moment) {
				flowCount++
				return writer.Delete(key)
			}
			return nil
		}, stoabs.BytesKey{})
		return err
	})
	return flowCount, refCount, err
}

func (o *stoabsStore) validateFlowExists(ctx context.Context, flowID string) error {
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

func (o *stoabsStore) flowExists(reader stoabs.Reader, flowID string) (bool, error) {
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

func (o *stoabsStore) refKey(refType string, reference string) stoabs.BytesKey {
	return stoabs.BytesKey(refType + ":" + reference)
}
