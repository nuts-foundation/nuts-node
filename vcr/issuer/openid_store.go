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
	"github.com/nuts-foundation/nuts-node/storage"
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
	StoreReference(ctx context.Context, flowID string, refType string, reference string) error
	// FindByReference finds a Flow by its reference.
	// If the flow does not exist, it returns nil.
	FindByReference(ctx context.Context, refType string, reference string) (*Flow, error)
	// DeleteReference deletes the reference from the store.
	// It does not return an error if it doesn't exist anymore.
	DeleteReference(ctx context.Context, refType string, reference string) error
}

var _ OpenIDStore = (*openidMemoryStore)(nil)

type openidMemoryStore struct {
	sessionDatabase storage.SessionDatabase
}

// NewOpenIDMemoryStore creates a new in-memory OpenIDStore.
func NewOpenIDMemoryStore(sessionDatabase storage.SessionDatabase) OpenIDStore {
	return &openidMemoryStore{
		sessionDatabase: sessionDatabase,
	}
}

func (o *openidMemoryStore) Store(_ context.Context, flow Flow) error {
	if len(flow.ID) == 0 {
		return errors.New("invalid flow ID")
	}
	store := o.sessionDatabase.GetStore(TokenTTL, "openid4vci", "flow")
	if store.Exists(flow.ID) {
		return errors.New("OAuth2 flow with this ID already exists")
	}
	return store.Put(flow.ID, flow)
}

func (o *openidMemoryStore) StoreReference(_ context.Context, flowID string, refType string, reference string) error {
	if len(reference) == 0 {
		return errors.New("invalid reference")
	}
	refStore := o.sessionDatabase.GetStore(TokenTTL, "openid4vci", refType)
	flowStore := o.sessionDatabase.GetStore(TokenTTL, "openid4vci", "flow")
	if !flowStore.Exists(flowID) {
		return errors.New("OAuth2 flow with this ID does not exist")
	}
	if refStore.Exists(reference) {
		return errors.New("reference already exists")
	}
	return refStore.Put(reference, flowID)
}

func (o *openidMemoryStore) FindByReference(_ context.Context, refType string, reference string) (*Flow, error) {
	refStore := o.sessionDatabase.GetStore(TokenTTL, "openid4vci", refType)
	flowStore := o.sessionDatabase.GetStore(TokenTTL, "openid4vci", "flow")
	if !refStore.Exists(reference) {
		return nil, nil
	}
	var flowID string
	err := refStore.Get(reference, &flowID)
	if err != nil {
		return nil, err
	}
	var flow Flow
	err = flowStore.Get(flowID, &flow)
	return &flow, err
}

func (o *openidMemoryStore) DeleteReference(_ context.Context, refType string, reference string) error {
	refStore := o.sessionDatabase.GetStore(TokenTTL, "openid4vci", refType)
	return refStore.Delete(reference)
}
