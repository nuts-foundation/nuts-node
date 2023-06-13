/*
 * Copyright (C) 2023 Nuts community
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
	"github.com/nuts-foundation/nuts-node/vcr/log"
	"sync"
	"time"
)

// OpenIDStore defines the storage API for OpenID Credential Issuance flows.
type OpenIDStore interface {
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

var _ OpenIDStore = (*openidMemoryStore)(nil)

var openidStorePruneInterval = 10 * time.Minute

type openidMemoryStore struct {
	mux      *sync.RWMutex
	flows    map[string]Flow
	refs     map[string]map[string]referenceValue
	routines *sync.WaitGroup
	ctx      context.Context
	cancel   context.CancelFunc
}

// NewOpenIDMemoryStore creates a new in-memory OpenIDStore.
func NewOpenIDMemoryStore() OpenIDStore {
	result := &openidMemoryStore{
		mux:      &sync.RWMutex{},
		flows:    map[string]Flow{},
		refs:     map[string]map[string]referenceValue{},
		routines: &sync.WaitGroup{},
	}
	result.ctx, result.cancel = context.WithCancel(context.Background())
	result.startPruning(openidStorePruneInterval)
	return result
}

type referenceValue struct {
	FlowID string    `json:"flow_id"`
	Expiry time.Time `json:"exp"`
}

func (o *openidMemoryStore) Store(_ context.Context, flow Flow) error {
	if len(flow.ID) == 0 {
		return errors.New("invalid flow ID")
	}
	o.mux.Lock()
	defer o.mux.Unlock()
	if o.flows[flow.ID].ID != "" {
		return errors.New("OAuth2 flow with this ID already exists")
	}
	o.flows[flow.ID] = flow
	return nil
}

func (o *openidMemoryStore) StoreReference(_ context.Context, flowID string, refType string, reference string, expiry time.Time) error {
	if len(reference) == 0 {
		return errors.New("invalid reference")
	}
	o.mux.Lock()
	defer o.mux.Unlock()
	if o.flows[flowID].ID == "" {
		return errors.New("OAuth2 flow with this ID does not exist")
	}
	if o.refs[refType] == nil {
		o.refs[refType] = map[string]referenceValue{}
	}
	if _, ok := o.refs[refType][reference]; ok {
		return errors.New("reference already exists")
	}
	o.refs[refType][reference] = referenceValue{FlowID: flowID, Expiry: expiry}
	return nil
}

func (o *openidMemoryStore) FindByReference(_ context.Context, refType string, reference string) (*Flow, error) {
	o.mux.RLock()
	defer o.mux.RUnlock()

	refMap := o.refs[refType]
	if refMap == nil {
		return nil, nil
	}
	value, ok := refMap[reference]
	if !ok {
		return nil, nil
	}
	if value.Expiry.Before(time.Now()) {
		return nil, nil
	}

	flow := o.flows[value.FlowID]
	if flow.Expiry.Before(time.Now()) {
		return nil, nil
	}
	return &flow, nil
}

func (o *openidMemoryStore) DeleteReference(_ context.Context, refType string, reference string) error {
	o.mux.Lock()
	defer o.mux.Unlock()

	if o.refs[refType] == nil {
		return nil
	}
	delete(o.refs[refType], reference)
	return nil
}

func (o *openidMemoryStore) Close() {
	// Signal pruner to stop and wait for it to finish
	o.cancel()
	o.routines.Wait()
}

func (o *openidMemoryStore) startPruning(interval time.Duration) {
	ticker := time.NewTicker(interval)
	o.routines.Add(1)
	go func(ctx context.Context) {
		defer o.routines.Done()
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				flowsPruned, refsPruned := o.prune()
				if flowsPruned > 0 || refsPruned > 0 {
					log.Logger().Debugf("Pruned %d expired OpenID4VCI flows and %d expired refs", flowsPruned, refsPruned)
				}
			}
		}
	}(o.ctx)
}

func (o *openidMemoryStore) prune() (int, int) {
	o.mux.Lock()
	defer o.mux.Unlock()

	moment := time.Now()

	// Find expired flows and delete them
	var flowCount int
	for id, flow := range o.flows {
		if flow.Expiry.Before(moment) {
			flowCount++
			delete(o.flows, id)
		}
	}
	// Find expired refs and delete them
	var refCount int
	for _, refMap := range o.refs {
		for reference, value := range refMap {
			if value.Expiry.Before(moment) {
				refCount++
				delete(refMap, reference)
			}
		}
	}

	return flowCount, refCount
}
