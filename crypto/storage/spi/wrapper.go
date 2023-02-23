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

package spi

import (
	"context"
	"crypto"
	"fmt"
	"github.com/nuts-foundation/nuts-node/core"
	"regexp"
)

// wrapper wraps a Storage backend and checks the validity of the kid on each of the relevant functions before
// forwarding the call to the wrapped backend.
type wrapper struct {
	kidPattern     *regexp.Regexp
	wrappedBackend Storage
}

func (w wrapper) Name() string {
	return w.wrappedBackend.Name()
}

func (w wrapper) CheckHealth(ctx context.Context) map[string]core.Health {
	return w.wrappedBackend.CheckHealth(ctx)
}

// NewValidatedKIDBackendWrapper creates a new wrapper for storage backends.
// Every call to the backend which takes a kid as param, gets the kid validated against the provided kidPattern.
func NewValidatedKIDBackendWrapper(backend Storage, kidPattern *regexp.Regexp) Storage {
	return wrapper{
		kidPattern:     kidPattern,
		wrappedBackend: backend,
	}
}

func (w wrapper) validateKID(kid string) error {
	if !w.kidPattern.MatchString(kid) {
		return fmt.Errorf("invalid key ID: %s", kid)
	}
	return nil
}

func (w wrapper) GetPrivateKey(kid string) (crypto.Signer, error) {
	if err := w.validateKID(kid); err != nil {
		return nil, err
	}
	return w.wrappedBackend.GetPrivateKey(kid)
}

func (w wrapper) PrivateKeyExists(kid string) bool {
	if err := w.validateKID(kid); err != nil {
		return false
	}
	return w.wrappedBackend.PrivateKeyExists(kid)
}

func (w wrapper) SavePrivateKey(kid string, key crypto.PrivateKey) error {
	if err := w.validateKID(kid); err != nil {
		return err
	}
	return w.wrappedBackend.SavePrivateKey(kid, key)
}

func (w wrapper) ListPrivateKeys() []string {
	return w.wrappedBackend.ListPrivateKeys()
}
