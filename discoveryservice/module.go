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

package discoveryservice

import (
	"errors"
	"fmt"
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/storage"
	"os"
	"path"
	"strings"
	"time"
)

const ModuleName = "DiscoveryService"

var ErrServerModeDisabled = errors.New("node is not a discovery server for this service")

var _ core.Injectable = &Module{}
var _ core.Runnable = &Module{}
var _ core.Configurable = &Module{}
var _ Server = &Module{}

// var _ Client = &Module{}
var retractionPresentationType = ssi.MustParseURI("RetractedVerifiablePresentation")

func New(storageInstance storage.Engine) *Module {
	return &Module{
		storageInstance: storageInstance,
	}
}

type Module struct {
	config            Config
	storageInstance   storage.Engine
	store             *sqlStore
	serverDefinitions map[string]Definition
	services          map[string]Definition
}

func (m *Module) Configure(_ core.ServerConfig) error {
	if m.config.Definitions.Directory == "" {
		return nil
	}
	var err error
	m.services, err = loadDefinitions(m.config.Definitions.Directory)
	if err != nil {
		return err
	}
	if len(m.config.Server.DefinitionIDs) > 0 {
		// Get the definitions that are enabled for this server
		serverDefinitions := make(map[string]Definition)
		for _, definitionID := range m.config.Server.DefinitionIDs {
			if definition, exists := m.services[definitionID]; !exists {
				return fmt.Errorf("definition '%s' not found", definitionID)
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
	m.store, err = newSQLStore(m.storageInstance.GetSQLDatabase(), m.services)
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

func (m *Module) Add(serviceID string, presentation vc.VerifiablePresentation) error {
	definition, exists := m.services[serviceID]
	if !exists {
		return ErrServiceNotFound
	}
	if _, isMaintainer := m.serverDefinitions[serviceID]; !isMaintainer {
		return ErrServerModeDisabled
	}
	if presentation.Format() != vc.JWTPresentationProofFormat {
		return errors.New("only JWT presentations are supported")
	}
	// TODO: validate signature
	if presentation.ID == nil {
		return errors.New("presentation does not have an ID")
	}
	expiration := presentation.JWT().Expiration()
	// VPs should not be valid for too short; unnecessary overhead at the server and clients.
	// Also protects against expiration not being set at all. The factor is somewhat arbitrary.
	minValidity := float64(definition.PresentationMaxValidity / 4)
	if expiration.Sub(time.Now()).Seconds() < minValidity {
		return fmt.Errorf("presentation is not valid for long enough (min %s)", time.Duration(minValidity)*time.Second)
	}
	// VPs should not be valid for too long, as that would prevent the server from pruning them.
	if int(expiration.Sub(time.Now()).Seconds()) > definition.PresentationMaxValidity {
		return fmt.Errorf("presentation is valid for too long (max %s)", time.Duration(definition.PresentationMaxValidity)*time.Second)
	}

	if presentation.IsType(retractionPresentationType) {
		return m.addRetraction(definition.ID, presentation)
	} else {
		return m.addPresentation(definition, presentation)
	}
}

func (m *Module) addPresentation(definition Definition, presentation vc.VerifiablePresentation) error {
	// Must contain credentials
	if len(presentation.VerifiableCredential) == 0 {
		return errors.New("presentation must contain at least one credentialRecord")
	}
	// VP can't be valid longer than the credentialRecord it contains
	expiration := presentation.JWT().Expiration()
	for _, cred := range presentation.VerifiableCredential {
		exp := cred.JWT().Expiration()
		if !exp.IsZero() && expiration.After(exp) {
			return fmt.Errorf("presentation is valid longer than the credentialRecord(s) it contains")
		}
	}
	// VP must fulfill the PEX Presentation Definition
	creds, _, err := definition.PresentationDefinition.Match(presentation.VerifiableCredential)
	if err != nil || len(creds) != len(presentation.VerifiableCredential) {
		return fmt.Errorf("presentation does not fulfill Presentation Definition: %w", err)
	}
	return m.store.add(definition.ID, presentation, nil)
}

func (m *Module) addRetraction(serviceID string, presentation vc.VerifiablePresentation) error {
	// Presentation might be a retraction (deletion of an earlier credentialRecord) must contain no credentials, and refer to the VP being retracted by ID.
	// If those conditions aren't met, we don't need to register the retraction.
	if len(presentation.VerifiableCredential) > 0 {
		return errors.New("retraction presentation must not contain credentials")
	}
	// Check that the retraction refers to a presentation that:
	// - is owned by the signer (same DID)
	// - exists (if not, it might've already been removed due to expiry, or superseeded by a newer presentation)
	var retractJTIString string
	if retractJTIRaw, ok := presentation.JWT().Get("retract_jti"); !ok {
		return errors.New("retraction presentation does not contain 'retract_jti' claim")
	} else {
		if retractJTIString, ok = retractJTIRaw.(string); !ok {
			return errors.New("retraction presentation 'retract_jti' claim is not a string")
		}
	}
	signer := presentation.JWT().Issuer()
	signerDID, err := did.ParseDID(signer)
	if err != nil {
		return fmt.Errorf("retraction presentation issuer is not a valid DID: %w", err)
	}
	retractJTI, err := did.ParseDIDURL(retractJTIString)
	if err != nil {
		return fmt.Errorf("retraction presentation 'retract_jti' claim is not a valid DID URL: %w", err)
	}
	if !signerDID.Equals(retractJTI.DID) {
		return errors.New("retraction presentation 'retract_jti' claim does not match JWT issuer")
	}
	exists, err := m.store.exists(serviceID, signer, retractJTIString)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("retraction presentation refers to a non-existing presentation")
	}
	return m.store.add(serviceID, presentation, nil)
}

func (m *Module) Get(serviceID string, startAt Timestamp) ([]vc.VerifiablePresentation, *Timestamp, error) {
	if _, exists := m.services[serviceID]; !exists {
		return nil, nil, ErrServiceNotFound
	}
	return m.store.get(serviceID, startAt)
}

func loadDefinitions(directory string) (map[string]Definition, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("unable to read definitions directory '%s': %w", directory, err)
	}
	result := make(map[string]Definition)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		filePath := path.Join(directory, entry.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("unable to read definition file '%s': %w", filePath, err)
		}
		definition, err := ParseDefinition(data)
		if err != nil {
			return nil, fmt.Errorf("unable to parse definition file '%s': %w", filePath, err)
		}
		if _, exists := result[definition.ID]; exists {
			return nil, fmt.Errorf("duplicate definition ID '%s' in file '%s'", definition.ID, filePath)
		}
		result[definition.ID] = *definition
	}
	return result, nil
}
