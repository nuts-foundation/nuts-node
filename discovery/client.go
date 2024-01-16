/*
 * Copyright (C) 2024 Nuts community
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

package discovery

import (
	"context"
	"fmt"
	"github.com/nuts-foundation/nuts-node/discovery/api/v1/client"
	"github.com/nuts-foundation/nuts-node/discovery/log"
	"time"
)

// clientUpdater is responsible for updating the presentations for the given services, at the given interval.
// Callers should only call update().
type clientUpdater struct {
	services map[string]ServiceDefinition
	store    *sqlStore
	client   client.HTTPClient
	verifier presentationVerifier
}

func newClientUpdater(services map[string]ServiceDefinition, store *sqlStore, verifier presentationVerifier, client client.HTTPClient) *clientUpdater {
	return &clientUpdater{
		services: services,
		store:    store,
		client:   client,
		verifier: verifier,
	}
}

// update starts a blocking loop that updates the presentations for the given services, at the given interval.
// It returns when the context is cancelled.
func (u *clientUpdater) update(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	u.doUpdate(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.doUpdate(ctx)
		}
	}
}

func (u *clientUpdater) doUpdate(ctx context.Context) {
	for _, service := range u.services {
		if err := u.updateService(ctx, service); err != nil {
			log.Logger().Errorf("Failed to update service (id=%s): %s", service.ID, err)
		}
	}
}

func (u *clientUpdater) updateService(ctx context.Context, service ServiceDefinition) error {
	currentTag, err := u.store.getTag(service.ID)
	if err != nil {
		return err
	}
	presentations, tag, err := u.client.Get(ctx, service.Endpoint, string(currentTag))
	if err != nil {
		return fmt.Errorf("failed to get presentations from discovery service (id=%s): %w", service.ID, err)
	}
	for _, presentation := range presentations {
		if err := u.verifier(service, presentation); err != nil {
			log.Logger().WithError(err).Warnf("Presentation verification failed, not adding it (service=%s, id=%s)", service.ID, presentation.ID)
			continue
		}
		if err := u.store.add(service.ID, presentation, Tag(tag)); err != nil {
			return fmt.Errorf("failed to store presentation (service=%s, id=%s): %w", service.ID, presentation.ID, err)
		}
	}
	return nil
}
