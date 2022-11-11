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

package irma

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-node/auth/services"

	"github.com/nuts-foundation/nuts-node/auth/contract"

	"github.com/nuts-foundation/nuts-node/auth/test"

	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/assert"
)

func TestSignedIrmaContract_VerifySignature(t *testing.T) {

	irmaConfig := func(t *testing.T) *irma.Configuration {
		t.Helper()
		irmaConfig, err := irma.NewConfiguration("../../../development/irma", irma.ConfigurationOptions{})
		require.NoError(t, err)
		require.NoError(t, irmaConfig.ParseFolder())
		return irmaConfig
	}

	irmaContractVerifier := func(t *testing.T) *contractVerifier {
		t.Helper()
		return &contractVerifier{irmaConfig: irmaConfig(t), validContracts: contract.StandardContractTemplates}
	}

	t.Run("an empty contract is Invalid", func(t *testing.T) {
		sic := &SignedIrmaContract{}
		cv := irmaContractVerifier(t)
		res, err := cv.verifyAll(sic, nil)
		require.NoError(t, err)
		assert.Equal(t, services.Invalid, res.ValidationResult)
	})

	t.Run("a valid contract with a valid IRMA config is Valid", func(t *testing.T) {
		t.Skip("migrate to v3 contracts")
		validJsonContract := test.ValidIrmaContract
		cv := irmaContractVerifier(t)

		sic, err := cv.ParseIrmaContract([]byte(validJsonContract))
		require.NoError(t, err)

		location, _ := time.LoadLocation(contract.AmsterdamTimeZone)
		checkTime := time.Date(2019, time.October, 1, 13, 46, 00, 0, location)
		res, err := cv.verifyAll(sic.(*SignedIrmaContract), &checkTime)
		assert.NoError(t, err)
		assert.Equal(t, services.Valid, res.ValidationResult)
	})

	t.Run("valid contract signed with a missing attributes fails validation", func(t *testing.T) {
		t.Skip("Migrate to v3 contract")
		validTestContracts := contract.TemplateStore{
			"NL": {"BehandelaarLogin": {
				"v3": &contract.Template{
					Type:               "BehandelaarLogin",
					Version:            "v1",
					Language:           "NL",
					SignerAttributes:   []string{"nuts.missing.attribute", "gemeente.personalData.fullname", "gemeente.personalData.firstnames", "gemeente.personalData.prefix", "gemeente.personalData.familyname"},
					Template:           `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan {{acting_party}} om namens {{legal_entity}} en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van {{valid_from}} tot {{valid_to}}.`,
					TemplateAttributes: []string{"acting_party", "legal_entity", "valid_from", "valid_to"},
					Regexp:             `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan (.+) om namens (.+) en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van (.+) tot (.+).`,
				},
			}}}

		cv := &contractVerifier{irmaConfig: irmaConfig(t), validContracts: validTestContracts}

		validJsonContract := test.ValidIrmaContract2
		sic, err := cv.ParseIrmaContract([]byte(validJsonContract))
		require.NoError(t, err)
		res, err := cv.verifyAll(sic.(*SignedIrmaContract), nil)
		assert.NoError(t, err)
		assert.Equal(t, services.Invalid, res.ValidationResult)
	})
}
