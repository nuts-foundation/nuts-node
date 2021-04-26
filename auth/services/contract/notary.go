/*
 * Nuts node
 * Copyright (C) 2021 Nuts community
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
 */

package contract

import (
	"errors"
	"fmt"
	"time"

	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/auth/services/validator"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/nuts-foundation/nuts-node/vdr/types"

	"github.com/nuts-foundation/nuts-node/auth/services"

	"github.com/nuts-foundation/nuts-node/auth/contract"
)

type contractNotaryService struct {
	conceptFinder    vcr.ConceptFinder
	keyResolver      types.KeyResolver
	privateKeyStore  crypto.Accessor
	contractValidity time.Duration
}

var timenow = time.Now

// NewContractNotary accepts the registry and crypto Nuts engines and returns a ContractNotary
func NewContractNotary(finder vcr.ConceptFinder, keyResolver types.KeyResolver, keyStore crypto.Accessor, contractValidity time.Duration) services.ContractNotary {
	return &contractNotaryService{
		conceptFinder:    finder,
		contractValidity: contractValidity,
		keyResolver:      keyResolver,
		privateKeyStore:  keyStore,
	}
}

// DrawUpContract accepts a template and fills in the Party, validFrom time and its duration.
// If validFrom is zero, the current time is used.
// If the duration is 0 than the default duration is used.
func (s *contractNotaryService) DrawUpContract(template contract.Template, orgID did.DID, validFrom time.Time, validDuration time.Duration) (*contract.Contract, error) {
	// Test if the org in managed by this node:
	signingKeyID, err := s.keyResolver.ResolveSigningKeyID(orgID, &validFrom)
	if errors.Is(err, types.ErrNotFound) {
		return nil, fmt.Errorf("could not draw up contract: organization not found")
	} else if err != nil {
		return nil, fmt.Errorf("could not draw up contract: %w", err)
	}

	if !s.privateKeyStore.PrivateKeyExists(signingKeyID) {
		return nil, fmt.Errorf("could not draw up contract: organization is not managed by this node: %w", validator.ErrMissingOrganizationKey)
	}

	// DrawUpContract draws up a contract for a specific organisation from a template
	result, err := s.conceptFinder.Get(concept.OrganizationConcept, orgID.String())
	if err != nil {
		return nil, fmt.Errorf("could not draw up contract: %w", err)
	}
	orgName, err := result.GetString(concept.OrganizationName)
	if err != nil {
		return nil, fmt.Errorf("could not draw up contract, could not extract organization name: %w", err)
	}
	orgCity, err := result.GetString(concept.OrganizationCity)
	if err != nil {
		return nil, fmt.Errorf("could not draw up contract, could not extract organization city: %w", err)
	}

	contractAttrs := map[string]string{
		contract.LegalEntityAttr:     orgName,
		contract.LegalEntityCityAttr: orgCity,
	}

	if validDuration == 0 {
		validDuration = s.contractValidity
	}
	if validFrom.IsZero() {
		validFrom = timenow()
	}

	drawnUpContract, err := template.Render(contractAttrs, validFrom, validDuration)
	if err != nil {
		return nil, fmt.Errorf("could not draw up contract: %w", err)
	}
	return drawnUpContract, nil
}
