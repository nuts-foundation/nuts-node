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
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/discovery/api/server/client"
	"github.com/nuts-foundation/nuts-node/discovery/log"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vcr/holder"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/nuts-foundation/nuts-node/vcr/signature/proof"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"strings"
	"time"
)

// clientRegistrationManager is a client component, responsible for managing registrations on a Discovery Service.
// It can refresh registered Verifiable Presentations when they are about to expire.
type clientRegistrationManager interface {
	activate(ctx context.Context, serviceID, subjectID string, parameters map[string]interface{}) error
	deactivate(ctx context.Context, serviceID, subjectID string) error
	// refresh checks which Verifiable Presentations that are about to expire, and should be refreshed on the Discovery Service.
	refresh(ctx context.Context, now time.Time) error
}

var _ clientRegistrationManager = &defaultClientRegistrationManager{}

type defaultClientRegistrationManager struct {
	services       map[string]ServiceDefinition
	store          *sqlStore
	client         client.HTTPClient
	vcr            vcr.VCR
	subjectManager didsubject.SubjectManager
}

func newRegistrationManager(services map[string]ServiceDefinition, store *sqlStore, client client.HTTPClient, vcr vcr.VCR, subjectManager didsubject.SubjectManager) *defaultClientRegistrationManager {
	return &defaultClientRegistrationManager{
		services:       services,
		store:          store,
		client:         client,
		vcr:            vcr,
		subjectManager: subjectManager,
	}
}

func (r *defaultClientRegistrationManager) activate(ctx context.Context, serviceID, subjectID string, parameters map[string]interface{}) error {
	service, serviceExists := r.services[serviceID]
	if !serviceExists {
		return ErrServiceNotFound
	}
	subjectDIDs, err := r.subjectManager.ListDIDs(ctx, subjectID)
	if err != nil {
		return err
	}
	var asSoonAsPossible time.Time
	if err := r.store.updatePresentationRefreshTime(serviceID, subjectID, parameters, &asSoonAsPossible); err != nil {
		return err
	}
	log.Logger().Debugf("Registering Verifiable Presentation on Discovery Service (service=%s, subject=%s)", service.ID, subjectID)

	var registeredDIDs []string
	var loopErrs []error
	for _, subjectDID := range subjectDIDs {
		err := r.registerPresentation(ctx, subjectDID, service, parameters)
		if err != nil {
			if !errors.Is(err, pe.ErrNoCredentials) { // ignore missing credentials
				loopErrs = append(loopErrs, fmt.Errorf("%s: %w", subjectDID.String(), err))
			} else {
				// trace logging for missing credentials
				log.Logger().Tracef("Missing credentials for Discovery Service (service=%s, subject=%s, did=%s): %s", service.ID, subjectID, subjectDID, err.Error())
			}
		} else {
			registeredDIDs = append(registeredDIDs, subjectDID.String())
		}
	}
	if len(registeredDIDs) == 0 {
		if len(registeredDIDs) != len(subjectDIDs) && len(loopErrs) == 0 {
			// all registrations failed on missing credentials. can only be false if using complex presentation definitions
			loopErrs = append(loopErrs, fmt.Errorf("failed registration for service=%s, subject=%s: %w", serviceID, subjectID, pe.ErrNoCredentials))
		}
		// registration failed for all subjectDIDs, will be retried on next scheduled refresh
		return fmt.Errorf("%w: %w", ErrPresentationRegistrationFailed, errors.Join(loopErrs...))
	}
	log.Logger().Debugf("Successfully registered Verifiable Presentation on Discovery Service (service=%s, subject=%s, dids=[%s])", serviceID, subjectID, strings.Join(registeredDIDs, ","))
	if len(loopErrs) != 0 {
		log.Logger().Infof("Failed registration of Verifiable Presentation on Discovery Service (service=%s, subject=%s): %s", serviceID, subjectID, errors.Join(loopErrs...))
	}

	// Set presentation to be refreshed before it expires
	// TODO: When to refresh? For now, we refresh when the registration is about at 45% of max age. This means a refresh can fail once without consequence.
	refreshVPAfter := time.Now().Add(time.Duration(float64(service.PresentationMaxValidity)*0.45) * time.Second)
	if err := r.store.updatePresentationRefreshTime(serviceID, subjectID, parameters, &refreshVPAfter); err != nil {
		return fmt.Errorf("unable to update Verifiable Presentation refresh time: %w", err)
	}
	return nil
}

func (r *defaultClientRegistrationManager) deactivate(ctx context.Context, serviceID, subjectID string) error {
	// delete DID/service combination from DB, so it won't be registered again
	err := r.store.updatePresentationRefreshTime(serviceID, subjectID, nil, nil)
	if err != nil {
		return err
	}
	// subject is now successfully deactivated for the service, anything after this point is best effort
	subjectDIDs, err := r.subjectManager.ListDIDs(ctx, subjectID)
	if err != nil {
		// this could be a didsubject.ErrSubjectNotFound after the subject has been deactivated
		// still fail in this case since we no longer have the keys to sign a retraction
		return err
	}

	// find all active presentations
	vps2D, err := r.store.getSubjectVPsOnService(serviceID, subjectDIDs)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrPresentationRegistrationFailed, err)
	}

	// retract active registrations for all DIDs
	// failures are collected and merged into a single error
	service := r.services[serviceID]
	var loopErrs []error
	for did, vps := range vps2D {
		for _, vp := range vps {
			if vp.IsType(retractionPresentationType) {
				// is already retracted
				continue
			}
			err = r.deregisterPresentation(ctx, did, service, vp)
			if err != nil {
				loopErrs = append(loopErrs, err)
			}
		}
	}
	if len(loopErrs) > 0 {
		return fmt.Errorf("%w: %w", ErrPresentationRegistrationFailed, errors.Join(loopErrs...))
	}

	return nil
}

func (r *defaultClientRegistrationManager) deregisterPresentation(ctx context.Context, subjectDID did.DID, service ServiceDefinition, vp vc.VerifiablePresentation) error {
	presentation, err := r.buildPresentation(ctx, subjectDID, service, nil, map[string]interface{}{
		"retract_jti": vp.ID.String(),
	})
	if err != nil {
		return err
	}
	return r.client.Register(ctx, service.Endpoint, *presentation)
}

func (r *defaultClientRegistrationManager) registerPresentation(ctx context.Context, subjectDID did.DID, service ServiceDefinition, parameters map[string]interface{}) error {
	presentation, err := r.findCredentialsAndBuildPresentation(ctx, subjectDID, service, parameters)
	if err != nil {
		return err
	}
	return r.client.Register(ctx, service.Endpoint, *presentation)
}

func (r *defaultClientRegistrationManager) findCredentialsAndBuildPresentation(ctx context.Context, subjectDID did.DID, service ServiceDefinition, parameters map[string]interface{}) (*vc.VerifiablePresentation, error) {
	credentials, err := r.vcr.Wallet().List(ctx, subjectDID)
	if err != nil {
		return nil, err
	}
	// add registration params as credential
	if len(parameters) > 0 {
		registrationCredential := vc.VerifiableCredential{
			Context:           []ssi.URI{vc.VCContextV1URI(), credential.NutsV1ContextURI},
			Type:              []ssi.URI{vc.VerifiableCredentialTypeV1URI(), credential.DiscoveryRegistrationCredentialTypeV1URI()},
			CredentialSubject: []interface{}{parameters},
		}
		credentials = append(credentials, credential.AutoCorrectSelfAttestedCredential(registrationCredential, subjectDID))
	}

	matchingCredentials, _, err := service.PresentationDefinition.Match(credentials)
	const errStr = "failed to match Discovery Service's Presentation Definition (service=%s, did=%s): %w"
	if err != nil {
		return nil, fmt.Errorf(errStr, service.ID, subjectDID, err)
	}
	return r.buildPresentation(ctx, subjectDID, service, matchingCredentials, nil)
}

func (r *defaultClientRegistrationManager) buildPresentation(ctx context.Context, subjectDID did.DID, service ServiceDefinition,
	credentials []vc.VerifiableCredential, additionalProperties map[string]interface{}) (*vc.VerifiablePresentation, error) {
	nonce := nutsCrypto.GenerateNonce()
	// Make sure the presentation is not valid for longer than the max validity as defined by the Service Definitio.
	expires := time.Now().Add(time.Duration(service.PresentationMaxValidity-1) * time.Second).Truncate(time.Second)
	holderURI := subjectDID.URI()
	return r.vcr.Wallet().BuildPresentation(ctx, credentials, holder.PresentationOptions{
		ProofOptions: proof.ProofOptions{
			Created:              time.Now(),
			Domain:               &service.ID,
			Expires:              &expires,
			Nonce:                &nonce,
			AdditionalProperties: additionalProperties,
		},
		Format: vc.JWTPresentationProofFormat,
		Holder: &holderURI,
	}, &subjectDID, false)
}

func (r *defaultClientRegistrationManager) refresh(ctx context.Context, now time.Time) error {
	log.Logger().Debug("Refreshing own registered Verifiable Presentations on Discovery Services")
	refreshCandidates, err := r.store.getSubjectsToBeRefreshed(now)
	if err != nil {
		return err
	}
	var loopErrs []error
	for _, candidate := range refreshCandidates {
		if err = r.activate(ctx, candidate.ServiceID, candidate.SubjectID, candidate.Parameters); err != nil {
			var loopErr error
			if errors.Is(err, didsubject.ErrSubjectNotFound) {
				// Subject has probably been deactivated. Remove from service or registration will be retried every refresh interval.
				err = r.store.updatePresentationRefreshTime(candidate.ServiceID, candidate.SubjectID, candidate.Parameters, nil)
				if err != nil {
					loopErr = fmt.Errorf("failed to remove unknown subject (service=%s, subject=%s): %w", candidate.ServiceID, candidate.SubjectID, err)
				} else {
					loopErr = fmt.Errorf("removed unknown subject (service=%s, subject=%s)", candidate.ServiceID, candidate.SubjectID)
				}
			} else {
				loopErr = fmt.Errorf("failed to refresh Verifiable Presentation (service=%s, subject=%s): %w", candidate.ServiceID, candidate.SubjectID, err)
			}
			loopErrs = append(loopErrs, loopErr)
		}
	}
	if len(loopErrs) > 0 {
		return errors.Join(loopErrs...)
	}
	return nil
}

// clientUpdater is responsible for updating the local copy of Discovery Services
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

func (u *clientUpdater) update(ctx context.Context) error {
	log.Logger().Debug("Checking for new Verifiable Presentations from Discovery Services")
	var result error = nil
	for _, service := range u.services {
		if err := u.updateService(ctx, service); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (u *clientUpdater) updateService(ctx context.Context, service ServiceDefinition) error {
	currentTimestamp, err := u.store.getTimestamp(service.ID)
	if err != nil {
		return err
	}
	log.Logger().
		WithField("discoveryService", service.ID).
		Tracef("Checking for new Verifiable Presentations from Discovery Service (timestamp: %d)", currentTimestamp)
	presentations, serverTimestamp, err := u.client.Get(ctx, service.Endpoint, currentTimestamp)
	if err != nil {
		return fmt.Errorf("failed to get presentations from discovery service (id=%s): %w", service.ID, err)
	}
	for _, presentation := range presentations {
		if err := u.verifier(service, presentation); err != nil {
			log.Logger().WithError(err).Warnf("Presentation verification failed, not adding it (service=%s, id=%s)", service.ID, presentation.ID)
			continue
		}
		if err := u.store.add(service.ID, presentation, serverTimestamp); err != nil {
			return fmt.Errorf("failed to store presentation (service=%s, id=%s): %w", service.ID, presentation.ID, err)
		}
		log.Logger().
			WithField("discoveryService", service.ID).
			WithField("presentationID", presentation.ID).
			Trace("Loaded new Verifiable Presentation from Discovery Service")
	}
	return nil
}
