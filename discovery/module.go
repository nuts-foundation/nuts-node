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
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/discovery/log"
	"github.com/nuts-foundation/nuts-node/storage"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"os"
	"path"
	"strings"
	"time"
)

const ModuleName = "Discovery"

// ErrServerModeDisabled is returned when a client invokes a Discovery Server (Add or Get) operation on the node,
// for a Discovery Service which it doesn't serve.
var ErrServerModeDisabled = errors.New("node is not a discovery server for this service")

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
)

var _ core.Injectable = &Module{}
var _ core.Runnable = &Module{}
var _ core.Configurable = &Module{}
var _ Server = &Module{}
var _ Client = &Module{}

var retractionPresentationType = ssi.MustParseURI("RetractedVerifiablePresentation")

// New creates a new Module.
func New(storageInstance storage.Engine, vcrInstance vcr.VCR) *Module {
	return &Module{
		storageInstance: storageInstance,
		vcrInstance:     vcrInstance,
	}
}

// Module is the main entry point for discovery services.
type Module struct {
	config            Config
	storageInstance   storage.Engine
	store             *sqlStore
	serverDefinitions map[string]ServiceDefinition
	allDefinitions    map[string]ServiceDefinition
	vcrInstance       vcr.VCR
}

func (m *Module) Configure(_ core.ServerConfig) error {
	if m.config.Definitions.Directory == "" {
		return nil
	}
	var err error
	m.allDefinitions, err = loadDefinitions(m.config.Definitions.Directory)
	if err != nil {
		return err
	}
	if len(m.config.Server.DefinitionIDs) > 0 {
		// Get the definitions that are enabled for this server
		serverDefinitions := make(map[string]ServiceDefinition)
		for _, definitionID := range m.config.Server.DefinitionIDs {
			if definition, exists := m.allDefinitions[definitionID]; !exists {
				return fmt.Errorf("service definition '%s' not found", definitionID)
			} else {
				serverDefinitions[definitionID] = definition
			}
		}
		m.serverDefinitions = serverDefinitions
	}
	return nil
}

func (m *Module) Start() error {
	var err error
	m.store, err = newSQLStore(m.storageInstance.GetSQLDatabase(), m.allDefinitions, m.serverDefinitions)
	if err != nil {
		return err
	}
	return nil
}

func (m *Module) Shutdown() error {
	return nil
}

func (m *Module) Name() string {
	return ModuleName
}

func (m *Module) Config() interface{} {
	return &m.config
}

// Add registers a presentation on the given Discovery Service.
// See interface.go for more information.
func (m *Module) Add(serviceID string, presentation vc.VerifiablePresentation) error {
	// First, simple sanity checks
	definition, isServer := m.serverDefinitions[serviceID]
	if !isServer {
		return ErrServerModeDisabled
	}
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
	if int(expiration.Sub(time.Now()).Seconds()) > definition.PresentationMaxValidity {
		return errors.Join(ErrInvalidPresentation, fmt.Errorf("presentation is valid for too long (max %s)", time.Duration(definition.PresentationMaxValidity)*time.Second))
	}
	// Check if the presentation already exists
	credentialSubjectID, err := credential.PresentationSigner(presentation)
	if err != nil {
		return err
	}
	exists, err := m.store.exists(serviceID, credentialSubjectID.String(), presentation.ID.String())
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
	return m.store.add(definition.ID, presentation, nil)
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
		return err
	}
	if len(creds) != len(presentation.VerifiableCredential) {
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

// Get retrieves the presentations for the given service, starting at the given tag.
// See interface.go for more information.
func (m *Module) Get(serviceID string, tag *Tag) ([]vc.VerifiablePresentation, *Tag, error) {
	if _, exists := m.serverDefinitions[serviceID]; !exists {
		return nil, nil, ErrServerModeDisabled
	}
	return m.store.get(serviceID, tag)
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

		result = append(result, SearchResult{
			Presentation: matchingVP,
			Fields:       fields,
		})
	}
	return result, nil
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
