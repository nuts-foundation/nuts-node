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

// registrationManager is responsible for managing registrations on a Discovery Service.
type registrationManager interface {
	register(ctx context.Context, serviceID string, subjectDID did.DID) error
	unregister(ctx context.Context, serviceID string, subjectDID did.DID) error
	refreshRegistrations(ctx context.Context, interval time.Duration)
}

var _ registrationManager = &scheduledRegistrationManager{}

type scheduledRegistrationManager struct {
	services map[string]ServiceDefinition
	store    *sqlStore
	client   client.HTTPClient
	vcr      vcr.VCR
}

func newRegistrationManager(services map[string]ServiceDefinition, store *sqlStore, client client.HTTPClient, vcr vcr.VCR) *scheduledRegistrationManager {
	instance := &scheduledRegistrationManager{
		services: services,
		store:    store,
		client:   client,
		vcr:      vcr,
	}
	return instance
}

func (r *scheduledRegistrationManager) register(ctx context.Context, serviceID string, subjectDID did.DID) error {
	service, serviceExists := r.services[serviceID]
	if !serviceExists {
		return ErrServiceNotFound
	}
	// TODO: When to refresh? For now, we refresh when the registration is about to expire (75% of max age)
	registrationRenewal := time.Now().Add(time.Duration(float64(service.PresentationMaxValidity)*0.75) * time.Second)
	log.Logger().Debugf("Refreshing registration DID on Discovery Service (service=%s, did=%s)", serviceID, subjectDID)
	if err := r.store.updateDIDRegistrationTime(serviceID, subjectDID, &registrationRenewal); err != nil {
		return fmt.Errorf("unable to update DID registration: %w", err)
	}
	err := r.registerPresentation(ctx, subjectDID, service)
	if err != nil {
		// retry registration asap
		var next time.Time
		_ = r.store.updateDIDRegistrationTime(serviceID, subjectDID, &next)
		return errors.Join(ErrRegistrationFailed, err)
	}
	log.Logger().Debugf("Successfully refreshed registration DID on Discovery Service (service=%s, did=%s)", serviceID, subjectDID)
	return nil
}

func (r *scheduledRegistrationManager) unregister(ctx context.Context, serviceID string, subjectDID did.DID) error {
	// delete DID/service combination from DB, so it won't be registered again
	err := r.store.updateDIDRegistrationTime(serviceID, subjectDID, nil)
	if err != nil {
		return err
	}

	// if the DID has an active registration, retract it
	presentations, err := r.store.search(serviceID, map[string]string{
		"credentialSubject.id": subjectDID.String(),
	})
	if err != nil {
		return errors.Join(ErrRegistrationFailed, err)
	}
	if len(presentations) == 0 {
		return nil
	}
	service := r.services[serviceID]
	presentation, err := r.buildPresentation(ctx, subjectDID, service, nil, map[string]interface{}{
		"retract_jti": presentations[0].ID.String(),
	})
	if err != nil {
		return errors.Join(ErrRegistrationFailed, err)
	}
	err = r.client.Register(ctx, service.Endpoint, *presentation)
	if err != nil {
		return errors.Join(ErrRegistrationFailed, err)
	}
	return nil
}

func (r *scheduledRegistrationManager) registerPresentation(ctx context.Context, subjectDID did.DID, service ServiceDefinition) error {
	presentation, err := r.findCredentialsAndBuildPresentation(ctx, subjectDID, service)
	if err != nil {
		return err
	}
	return r.client.Register(ctx, service.Endpoint, *presentation)
}

func (r *scheduledRegistrationManager) findCredentialsAndBuildPresentation(ctx context.Context, subjectDID did.DID, service ServiceDefinition) (*vc.VerifiablePresentation, error) {
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

func (r *scheduledRegistrationManager) buildPresentation(ctx context.Context, subjectDID did.DID, service ServiceDefinition,
	credentials []vc.VerifiableCredential, additionalProperties map[string]interface{}) (*vc.VerifiablePresentation, error) {
	nonce := nutsCrypto.GenerateNonce()
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

func (r *scheduledRegistrationManager) doRefreshRegistrations(ctx context.Context, now time.Time) error {
	log.Logger().Debug("Renewing DID registrations on Discovery Services")
	serviceIDs, dids, err := r.store.getStaleDIDRegistrations(now)
	if err != nil {
		return err
	}
	for i, serviceID := range serviceIDs {
		if err := r.register(ctx, serviceID, dids[i]); err != nil {
			log.Logger().WithError(err).Warnf("Failed to renew DID registration (service=%s, did=%s)", serviceID, dids[i])
		}
	}
	return nil
}

func (r *scheduledRegistrationManager) refreshRegistrations(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// do the first refresh immediately
	do := func() {
		if err := r.doRefreshRegistrations(audit.Context(ctx, "app", ModuleName, "RefreshRegistration"), time.Now()); err != nil {
			log.Logger().WithError(err).Errorf("Failed to renew DID registrations")
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
