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

package discovery

import (
	"context"
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/audit"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/discovery/api/server/client"
	"github.com/nuts-foundation/nuts-node/discovery/log"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/nuts-foundation/nuts-node/vdr/didsubject"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

const ModuleName = "Discovery"

// ErrInvalidPresentation is returned when a client tries to register a Verifiable Presentation that is invalid.
var ErrInvalidPresentation = errors.New("presentation is invalid for registration")

var (
	errUnsupportedPresentationFormat           = errors.New("only JWT presentations are supported")
	errPresentationWithoutID                   = errors.New("presentation does not have an ID")
	errPresentationWithoutExpiration           = errors.New("presentation does not have an expiration")
	errPresentationValidityExceedsCredentials  = errors.New("presentation is valid longer than the credential(s) it contains")
	errPresentationDoesNotFulfillDefinition    = errors.New("presentation does not fulfill Presentation ServiceDefinition")
	errRetractionReferencesUnknownPresentation = errors.New("retraction presentation refers to a non-existing presentation")
	errRetractionContainsCredentials           = errors.New("retraction presentation must not contain credentials")
	errInvalidRetractionJTIClaim               = errors.New("invalid/missing 'retract_jti' claim for retraction presentation")
	errCyclicForwardingDetected                = errors.New("cyclic forwarding detected")
)

var _ core.Injectable = &Module{}
var _ core.Runnable = &Module{}
var _ core.Configurable = &Module{}
var _ Server = &Module{}
var _ Client = &Module{}

var retractionPresentationType = ssi.MustParseURI("RetractedVerifiablePresentation")

// New creates a new Module.
func New(storageInstance storage.Engine, vcrInstance vcr.VCR, subjectManager didsubject.SubjectManager) *Module {
	m := &Module{
		storageInstance: storageInstance,
		vcrInstance:     vcrInstance,
		subjectManager:  subjectManager,
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.routines = new(sync.WaitGroup)
	return m
}

// Module is the main entry point for discovery services.
type Module struct {
	config              Config
	httpClient          client.HTTPClient
	storageInstance     storage.Engine
	store               *sqlStore
	registrationManager clientRegistrationManager
	serverDefinitions   map[string]ServiceDefinition
	allDefinitions      map[string]ServiceDefinition
	vcrInstance         vcr.VCR
	subjectManager      didsubject.SubjectManager
	clientUpdater       *clientUpdater
	ctx                 context.Context
	cancel              context.CancelFunc
	routines            *sync.WaitGroup
	publicURL           *url.URL
}

func (m *Module) Configure(serverConfig core.ServerConfig) error {
	if m.config.Definitions.Directory == "" {
		return nil
	}
	// check if directory exists
	_, err := os.Stat(m.config.Definitions.Directory)
	if err != nil {
		if os.IsNotExist(err) && m.config.Definitions.Directory == DefaultConfig().Definitions.Directory {
			// assume this is the default config value and do not fail
			return nil
		}
		return fmt.Errorf("failed to load discovery defintions: %w", err)
	}

	m.publicURL, err = serverConfig.ServerURL()
	if err != nil {
		return err
	}

	m.allDefinitions, err = loadDefinitions(m.config.Definitions.Directory)
	if err != nil {
		return err
	}
	if len(m.config.Server.IDs) > 0 {
		// Get the definitions that are enabled for this server
		serverDefinitions := make(map[string]ServiceDefinition)
		for _, serviceID := range m.config.Server.IDs {
			if service, exists := m.allDefinitions[serviceID]; !exists {
				return fmt.Errorf("service definition '%s' not found", serviceID)
			} else {
				serverDefinitions[serviceID] = service
			}
		}
		m.serverDefinitions = serverDefinitions
	}
	m.httpClient = client.New(serverConfig.Strictmode, serverConfig.HTTPClient.Timeout, nil)
	return nil
}

func (m *Module) Start() error {
	var err error
	m.store, err = newSQLStore(m.storageInstance.GetSQLDatabase(), m.allDefinitions)
	if err != nil {
		return err
	}
	m.clientUpdater = newClientUpdater(m.allDefinitions, m.store, m.verifyRegistration, m.httpClient)
	m.registrationManager = newRegistrationManager(m.allDefinitions, m.store, m.httpClient, m.vcrInstance, m.subjectManager)
	if m.config.Client.RefreshInterval > 0 {
		m.routines.Add(1)
		go func() {
			defer m.routines.Done()
			m.update()
		}()
	}
	return nil
}

func (m *Module) Shutdown() error {
	m.cancel()
	m.routines.Wait()
	return nil
}

func (m *Module) Name() string {
	return ModuleName
}

func (m *Module) Config() interface{} {
	return &m.config
}

// Register is a Discovery Server function that registers a presentation on the given Discovery Service.
// See interface.go for more information.
func (m *Module) Register(context context.Context, serviceID string, presentation vc.VerifiablePresentation) error {
	// First, simple sanity checks
	_, isServer := m.serverDefinitions[serviceID]
	if !isServer {
		// forward to configured server
		service, exists := m.allDefinitions[serviceID]
		if !exists {
			return ErrServiceNotFound
		}

		// check If X-Forwarded-Host header is set, if set it must not be the same as service.Endpoint
		if cycleDetected(context, service) {
			return errCyclicForwardingDetected
		}

		// forward to configured server
		log.Logger().Infof("Forwarding Register request to configured server (service=%s)", serviceID)
		return m.httpClient.Register(context, service.Endpoint, presentation)
	}
	definition := m.allDefinitions[serviceID]
	if err := m.verifyRegistration(definition, presentation); err != nil {
		return err
	}

	return m.store.add(serviceID, presentation, 0)
}

func (m *Module) verifyRegistration(definition ServiceDefinition, presentation vc.VerifiablePresentation) error {
	// First, simple sanity checks
	if presentation.Format() != vc.JWTPresentationProofFormat {
		return errors.Join(ErrInvalidPresentation, errUnsupportedPresentationFormat)
	}
	if presentation.ID == nil {
		return errors.Join(ErrInvalidPresentation, errPresentationWithoutID)
	}
	// Make sure the presentation is intended for this service
	if err := validateAudience(definition, presentation.JWT().Audience()); err != nil {
		return err
	}
	expiration := presentation.JWT().Expiration()
	if expiration.IsZero() {
		return errors.Join(ErrInvalidPresentation, errPresentationWithoutExpiration)
	}
	// VPs should not be valid for too long, as that would prevent the server from pruning them.
	if time.Until(expiration) > time.Duration(definition.PresentationMaxValidity)*time.Second {
		return errors.Join(ErrInvalidPresentation, fmt.Errorf("presentation is valid for too long (max %s)", time.Duration(definition.PresentationMaxValidity)*time.Second))
	}
	credentialSubjectID, err := credential.PresentationSigner(presentation)
	if err != nil {
		return err
	}
	// Check if the issuer uses a supported DID method
	if len(definition.DIDMethods) > 0 && !slices.Contains(definition.DIDMethods, credentialSubjectID.Method) {
		return errors.Join(ErrInvalidPresentation, ErrDIDMethodsNotSupported)
	}

	// Check if the presentation already exists
	exists, err := m.store.exists(definition.ID, credentialSubjectID.String(), presentation.ID.String())
	if err != nil {
		return err
	}
	if exists {
		return errors.Join(ErrInvalidPresentation, ErrPresentationAlreadyExists)
	}
	// Depending on the presentation type, we need to validate different properties before storing it.
	if presentation.IsType(retractionPresentationType) {
		err = m.validateRetraction(definition.ID, presentation)
	} else {
		err = m.validateRegistration(definition, presentation)
	}
	if err != nil {
		return errors.Join(ErrInvalidPresentation, err)
	}
	// Check signature of presentation and contained credential(s)
	_, err = m.vcrInstance.Verifier().VerifyVP(presentation, true, true, nil)
	if err != nil {
		return errors.Join(ErrInvalidPresentation, fmt.Errorf("presentation verification failed: %w", err))
	}
	return nil
}

func (m *Module) validateRegistration(definition ServiceDefinition, presentation vc.VerifiablePresentation) error {
	// VP can't be valid longer than the credentialRecord it contains
	expiration := presentation.JWT().Expiration()
	for _, cred := range presentation.VerifiableCredential {
		if cred.ExpirationDate != nil && expiration.After(*cred.ExpirationDate) {
			return errPresentationValidityExceedsCredentials
		}
	}

	// VP must fulfill the PEX Presentation ServiceDefinition
	// We don't have a PresentationSubmission, so we can't use Validate().
	creds, _, err := definition.PresentationDefinition.Match(presentation.VerifiableCredential)
	if err != nil {
		return fmt.Errorf("verifiable presentation doesn't match required presentation definition: %w", err)
	}
	if len(creds) != len(presentation.VerifiableCredential) {
		// it could be the case that the VP contains a registration credential and the matching credentials do not.
		// only return errPresentationDoesNotFulfillDefinition if both contain the registration credential or neither do.
		vpContainsRegistrationCredential := false
		for _, cred := range presentation.VerifiableCredential {
			if slices.Contains(cred.Type, credential.DiscoveryRegistrationCredentialTypeV1URI()) {
				vpContainsRegistrationCredential = true
				break
			}
		}
		matchingContainsRegistrationCredential := false
		for _, cred := range creds {
			if slices.Contains(cred.Type, credential.DiscoveryRegistrationCredentialTypeV1URI()) {
				matchingContainsRegistrationCredential = true
				break
			}
		}
		if vpContainsRegistrationCredential && !matchingContainsRegistrationCredential && len(presentation.VerifiableCredential)-len(creds) == 1 {
			return nil
		}

		return errPresentationDoesNotFulfillDefinition
	}
	return nil
}

func (m *Module) validateRetraction(serviceID string, presentation vc.VerifiablePresentation) error {
	// Presentation might be a retraction (deletion of an earlier credentialRecord) must contain no credentials, and refer to the VP being retracted by ID.
	// If those conditions aren't met, we don't need to register the retraction.
	if len(presentation.VerifiableCredential) > 0 {
		return errRetractionContainsCredentials
	}
	// Check that the retraction refers to an existing presentation.
	// If not, it might've already been removed due to expiry or superseded by a newer presentation.
	retractJTIRaw, _ := presentation.JWT().Get("retract_jti")
	retractJTI, ok := retractJTIRaw.(string)
	if !ok || retractJTI == "" {
		return errInvalidRetractionJTIClaim
	}
	signerDID, _ := credential.PresentationSigner(presentation) // checked before
	exists, err := m.store.exists(serviceID, signerDID.String(), retractJTI)
	if err != nil {
		return err
	}
	if !exists {
		return errRetractionReferencesUnknownPresentation
	}
	return nil
}

// Get is a Discovery Server function that retrieves the presentations for the given service, starting at timestamp+1.
// See interface.go for more information.
func (m *Module) Get(context context.Context, serviceID string, startAfter int) (map[string]vc.VerifiablePresentation, int, error) {
	_, exists := m.serverDefinitions[serviceID]
	if !exists {
		// forward to configured server
		service, exists := m.allDefinitions[serviceID]
		if !exists {
			return nil, 0, ErrServiceNotFound
		}

		// check If X-Forwarded-Host header is set, if set it must not be the same as service.Endpoint
		if cycleDetected(context, service) {
			return nil, 0, errCyclicForwardingDetected
		}

		log.Logger().Infof("Forwarding Get request to configured server (service=%s)", serviceID)
		return m.httpClient.Get(context, service.Endpoint, startAfter)
	}
	return m.store.get(serviceID, startAfter)
}

func cycleDetected(ctx context.Context, service ServiceDefinition) bool {
	host := forwardedHost(ctx)
	if host == "" {
		return false
	}
	myUri, err := url.Parse(host)
	if err != nil {
		return false
	}
	targetUri, err := url.Parse(service.Endpoint)
	if err != nil {
		return false
	}

	return myUri.Host == targetUri.Host
}

func forwardedHost(ctx context.Context) string {
	// get value from context using "X-Forwarded-Host" key
	forwardedHostValue := ctx.Value(XForwardedHostContextKey{})
	host, ok := forwardedHostValue.(string)
	if !ok {
		return ""
	}
	return host
}

// ActivateServiceForSubject is a Discovery Client function that activates a service for a subject.
// See interface.go for more information.
func (m *Module) ActivateServiceForSubject(ctx context.Context, serviceID, subjectID string, parameters map[string]interface{}) error {
	log.Logger().Debugf("Activating service for subject (subject=%s, service=%s)", subjectID, serviceID)

	if parameters == nil {
		parameters = make(map[string]interface{})
	}
	// create authServerURL and add to parameters if not present
	if _, ok := parameters[authServerURLField]; !ok {
		parameters[authServerURLField] = m.publicURL.JoinPath("/oauth2/", subjectID).String()
	}

	err := m.registrationManager.activate(ctx, serviceID, subjectID, parameters)
	if err != nil {
		if errors.Is(err, ErrPresentationRegistrationFailed) {
			log.Logger().WithError(err).Warnf("Presentation registration failed, will be retried later (subject=%s,service=%s)", subjectID, serviceID)
		}
		return err
	}

	log.Logger().Infof("Successfully activated service for subject (subject=%s,service=%s)", subjectID, serviceID)
	_ = m.clientUpdater.updateService(ctx, m.allDefinitions[serviceID])
	return nil
}

// DeactivateServiceForSubject is a Discovery Client function that deactivates a service for a subject.
// See interface.go for more information.
func (m *Module) DeactivateServiceForSubject(ctx context.Context, serviceID, subjectID string) error {
	log.Logger().Infof("Deactivating service for subject (subject=%s, service=%s)", subjectID, serviceID)
	return m.registrationManager.deactivate(ctx, serviceID, subjectID)
}

func (m *Module) Services() []ServiceDefinition {
	result := make([]ServiceDefinition, 0, len(m.allDefinitions))
	for _, definition := range m.allDefinitions {
		result = append(result, definition)
	}
	return result
}

// GetServiceActivation is a Discovery Client function that retrieves the activation status of a service for a subject.
// See interface.go for more information.
func (m *Module) GetServiceActivation(ctx context.Context, serviceID, subjectID string) (bool, []vc.VerifiablePresentation, error) {
	refreshTime, err := m.store.getPresentationRefreshTime(serviceID, subjectID)
	if err != nil {
		return false, nil, err
	}
	if refreshTime == nil {
		return false, nil, nil
	}
	// subject is activated for service

	subjectDIDs, err := m.subjectManager.ListDIDs(ctx, subjectID)
	if err != nil {
		// can only happen if DB is offline/corrupt, or between deactivating a subject and its next refresh on the service (didsubject.ErrSubjectNotFound)
		return true, nil, err
	}

	vps2D, err := m.store.getSubjectVPsOnService(serviceID, subjectDIDs)
	if err != nil {
		return true, nil, err // DB err
	}
	var results []vc.VerifiablePresentation
	for _, vps := range vps2D {
		results = append(results, vps...)
	}
	return true, results, nil
}

func loadDefinitions(directory string) (map[string]ServiceDefinition, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("unable to read definitions directory '%s': %w", directory, err)
	}
	result := make(map[string]ServiceDefinition)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		filePath := path.Join(directory, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("unable to read service definition file '%s': %w", filePath, err)
		}
		definition, err := ParseServiceDefinition(data)
		if err != nil {
			return nil, fmt.Errorf("unable to parse service definition file '%s': %w", filePath, err)
		}
		if _, exists := result[definition.ID]; exists {
			return nil, fmt.Errorf("duplicate service definition ID '%s' in file '%s'", definition.ID, filePath)
		}
		result[definition.ID] = *definition
	}
	return result, nil
}

// Search is a Discovery Client function that searches for presentations which credential(s) match the given query.
// See interface.go for more information.
func (m *Module) Search(serviceID string, query map[string]string) ([]SearchResult, error) {
	service, exists := m.allDefinitions[serviceID]
	if !exists {
		return nil, ErrServiceNotFound
	}
	matchingVPs, err := m.store.search(serviceID, query)
	if err != nil {
		return nil, err
	}
	var result []SearchResult
	for _, matchingVP := range matchingVPs {
		// Match credentials to Presentation Definition, to resolve map with InputDescriptorId -> CredentialValue
		submissionVCs, inputDescriptorMappingObjects, err := service.PresentationDefinition.Match(matchingVP.VerifiableCredential)
		var fields map[string]interface{}
		if err != nil {
			log.Logger().Infof("Search() is unable to build submission for VP '%s': %s", matchingVP.ID, err)
		} else {
			credentialMap := make(map[string]vc.VerifiableCredential)
			for i := 0; i < len(inputDescriptorMappingObjects); i++ {
				credentialMap[inputDescriptorMappingObjects[i].Id] = submissionVCs[i]
			}
			fields, err = service.PresentationDefinition.ResolveConstraintsFields(credentialMap)
			if err != nil {
				log.Logger().Infof("Search() is unable to resolve Input Descriptor Constraints Fields map for VP '%s': %s", matchingVP.ID, err)
			}
		}

		// extract registrationParameters from VP
		registrationParameters := extractParameters(matchingVP)

		result = append(result, SearchResult{
			Presentation: matchingVP,
			Fields:       fields,
			Parameters:   registrationParameters,
		})
	}
	return result, nil
}

func extractParameters(vp vc.VerifiablePresentation) map[string]interface{} {
	result := make(map[string]interface{})
	credentials := vp.VerifiableCredential
	for _, cred := range credentials {
		if slices.Contains(cred.Type, credential.DiscoveryRegistrationCredentialTypeV1URI()) {
			credentialSubject := make([]credential.DiscoveryRegistrationCredentialSubject, 0)
			err := cred.UnmarshalCredentialSubject(&credentialSubject)
			if err != nil {
				// a vp uploaded by another party might contain something we can't unmarshal
				// without the extracted parameters, this VP will probably be useless anyway.
				log.Logger().WithError(err).Infof("Failed to unmarshal Discovery Registration Credential Subject (vp.id=%s)", vp.ID)
				continue
			}
			if len(credentialSubject) > 0 {
				result = credentialSubject[0]
				// remove id since it was automatically added by the AutoCorrect function
				// we only want the parameters that were originally set (+authServerURL)
				delete(result, "id")
			}
		}
	}

	return result
}

func (m *Module) update() {
	ticker := time.NewTicker(m.config.Client.RefreshInterval)
	defer ticker.Stop()
	ctx := audit.Context(m.ctx, "app", ModuleName, "RefreshDiscoveryClient")
	do := func() {
		// Refresh registrations first, to make sure we have (our own) latest presentations when we load them from the Discovery Service
		err := m.registrationManager.refresh(ctx, time.Now())
		if err != nil {
			log.Logger().WithError(err).Errorf("Failed to refresh own Verifiable Presentations on Discovery Service")
		}
		err = m.clientUpdater.update(m.ctx)
		if err != nil {
			log.Logger().WithError(err).Errorf("Failed to load latest Verifiable Presentations from Discovery Service")
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

// validateAudience checks if the given audience of the presentation matches the service ID.
func validateAudience(service ServiceDefinition, audience []string) error {
	for _, audienceID := range audience {
		if audienceID == service.ID {
			return nil
		}
	}
	return errors.New("aud claim is missing or invalid")
}
