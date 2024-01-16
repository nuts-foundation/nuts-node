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
	"errors"
	"fmt"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/discovery/api/v1/client"
	"github.com/nuts-foundation/nuts-node/discovery/log"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"time"
)

// clientRegistrationManager is a client component, responsible for managing registrations on a Discovery Service.
// It automatically refreshes registered Verifiable Presentations when they are about to expire.
type clientRegistrationManager interface {
	activate(ctx context.Context, serviceID string, subjectDID did.DID) error
	deactivate(ctx context.Context, serviceID string, subjectDID did.DID) error
	// refresh is a blocking call to periodically refresh registrations.
	// It checks for Verifiable Presentations that are about to expire, and should be refreshed on the Discovery Service.
	// It will exit when the given context is cancelled.
	refresh(ctx context.Context, interval time.Duration)
}

var _ clientRegistrationManager = &defaultClientRegistrationManager{}

type defaultClientRegistrationManager struct {
	services map[string]ServiceDefinition
	store    *sqlStore
	client   client.HTTPClient
	vcr      vcr.VCR
}

func newRegistrationManager(services map[string]ServiceDefinition, store *sqlStore, client client.HTTPClient, vcr vcr.VCR) *defaultClientRegistrationManager {
	instance := &defaultClientRegistrationManager{
		services: services,
		store:    store,
		client:   client,
		vcr:      vcr,
	}
	return instance
}

func (r *defaultClientRegistrationManager) activate(ctx context.Context, serviceID string, subjectDID did.DID) error {
	service, serviceExists := r.services[serviceID]
	if !serviceExists {
		return ErrServiceNotFound
	}
	var asSoonAsPossible time.Time
	if err := r.store.updatePresentationRefreshTime(serviceID, subjectDID, &asSoonAsPossible); err != nil {
		return err
	}
	log.Logger().Debugf("Registering Verifiable Presentation on Discovery Service (service=%s, did=%s)", service.ID, subjectDID)
	err := r.registerPresentation(ctx, subjectDID, service)
	if err != nil {
		// failed, will be retried on next scheduled refresh
		return errors.Join(ErrPresentationRegistrationFailed, err)
	}
	log.Logger().Debugf("Successfully registered Verifiable Presentation on Discovery Service (service=%s, did=%s)", serviceID, subjectDID)

	// Set presentation to be refreshed before it expires
	// TODO: When to refresh? For now, we refresh when the registration is about to expire (75% of max age)
	refreshVPAfter := time.Now().Add(time.Duration(float64(service.PresentationMaxValidity)*0.75) * time.Second)
	if err := r.store.updatePresentationRefreshTime(serviceID, subjectDID, &refreshVPAfter); err != nil {
		return fmt.Errorf("unable to update Verifiable Presentation refresh time: %w", err)
	}
	return nil
}

func (r *defaultClientRegistrationManager) deactivate(ctx context.Context, serviceID string, subjectDID did.DID) error {
	// delete DID/service combination from DB, so it won't be registered again
	err := r.store.updatePresentationRefreshTime(serviceID, subjectDID, nil)
	if err != nil {
		return err
	}

	// if the DID has an active registration, retract it
	presentations, err := r.store.search(serviceID, map[string]string{
		"credentialSubject.id": subjectDID.String(),
	})
	if err != nil {
		return errors.Join(ErrPresentationRegistrationFailed, err)
	}
	if len(presentations) == 0 {
		// no registration, nothing to do
		return nil
	}
	// found an active registration, try to delete it from the discovery server
	service := r.services[serviceID]
	presentation, err := r.buildPresentation(ctx, subjectDID, service, nil, map[string]interface{}{
		"retract_jti": presentations[0].ID.String(),
	})
	if err != nil {
		return errors.Join(ErrPresentationRegistrationFailed, err)
	}
	err = r.client.Register(ctx, service.Endpoint, *presentation)
	if err != nil {
		return errors.Join(ErrPresentationRegistrationFailed, err)
	}
	return nil
}

func (r *defaultClientRegistrationManager) registerPresentation(ctx context.Context, subjectDID did.DID, service ServiceDefinition) error {
	presentation, err := r.findCredentialsAndBuildPresentation(ctx, subjectDID, service)
	if err != nil {
		return err
	}
	return r.client.Register(ctx, service.Endpoint, *presentation)
}

func (r *defaultClientRegistrationManager) findCredentialsAndBuildPresentation(ctx context.Context, subjectDID did.DID, service ServiceDefinition) (*vc.VerifiablePresentation, error) {
	credentials, err := r.vcr.Wallet().List(ctx, subjectDID)
	if err != nil {
		return nil, err
	}
	matchingCredentials, _, err := service.PresentationDefinition.Match(credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to match Discovery Service's Presentation Definition (service=%s, did=%s): %w", service.ID, subjectDID, err)
	}
	if len(matchingCredentials) == 0 {
		return nil, fmt.Errorf("DID wallet does not have credentials required for registration on Discovery Service (service=%s, did=%s)", service.ID, subjectDID)
	}
	return r.buildPresentation(ctx, subjectDID, service, matchingCredentials, nil)
}

func (r *defaultClientRegistrationManager) buildPresentation(ctx context.Context, subjectDID did.DID, service ServiceDefinition,
	credentials []vc.VerifiableCredential, additionalProperties map[string]interface{}) (*vc.VerifiablePresentation, error) {
	nonce := nutsCrypto.GenerateNonce()
	// Make sure the presentation is not valid for longer than the max validity as defined by the Service Definitio.
	expires := time.Now().Add(time.Duration(service.PresentationMaxValidity-1) * time.Second).Truncate(time.Second)
	return r.vcr.Wallet().BuildPresentation(ctx, credentials, holder.PresentationOptions{
		ProofOptions: proof.ProofOptions{
			Created:              time.Now(),
			Domain:               &service.ID,
			Expires:              &expires,
			Nonce:                &nonce,
			AdditionalProperties: additionalProperties,
		},
		Format: vc.JWTPresentationProofFormat,
	}, &subjectDID, false)
}

func (r *defaultClientRegistrationManager) doRefresh(ctx context.Context, now time.Time) error {
	log.Logger().Debug("Refreshing Verifiable Presentations on Discovery Services")
	serviceIDs, dids, err := r.store.getPresentationsToBeRefreshed(now)
	if err != nil {
		return err
	}
	for i, serviceID := range serviceIDs {
		if err := r.activate(ctx, serviceID, dids[i]); err != nil {
			log.Logger().WithError(err).Warnf("Failed to refresh Verifiable Presentation (service=%s, did=%s)", serviceID, dids[i])
		}
	}
	return nil
}

func (r *defaultClientRegistrationManager) refresh(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// do the first refresh immediately
	do := func() {
		if err := r.doRefresh(audit.Context(ctx, "app", ModuleName, "RefreshVerifiablePresentations"), time.Now()); err != nil {
			log.Logger().WithError(err).Errorf("Failed to refresh Verifiable Presentations")
		}
	}
	do()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			do()
		}
	}
}

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
