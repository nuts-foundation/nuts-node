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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/goodsign/monday"
	"github.com/stretchr/testify/assert"
)

func TestContract_extractParams(t *testing.T) {
	template := &Template{
		Type:               "Simple",
		Template:           "ik geef toestemming voor {{voor}} aan {{wie}}.",
		TemplateAttributes: []string{"voor", "wie"},
		Regexp:             `^ik geef toestemming voor (.*) aan (.*)\.$`,
	}

	t.Run("a good text returns the Params", func(t *testing.T) {
		contractText := "ik geef toestemming voor orgaandonatie aan Henk."

		expectedParams := map[string]string{"voor": "orgaandonatie", "wie": "Henk"}

		contract := Contract{
			RawContractText: contractText,
			Template:        template,
		}

		err := contract.initParams()
		assert.NoError(t, err)

		if !reflect.DeepEqual(expectedParams, contract.Params) {
			t.Errorf("expected different Params, expected %v, got %v", expectedParams, contract.Params)
		}
	})

	t.Run("an invalid text returns an error", func(t *testing.T) {
		contractText := "ik ga niet akkoord."

		template := &Template{
			Type:     "Simple",
			Template: "ik geef toestemming voor {{voor}} aan {{wie}}.",
			Regexp:   `^ik geef toestemming voor (.*) aan (.*)\.$`,
		}

		contract := Contract{
			RawContractText: contractText,
			Template:        template,
		}

		err := contract.initParams()

		assert.ErrorContains(t, err, "invalid contract text")
		assert.Equal(t, 0, len(contract.Params))
	})
}

func TestContract_Verify(t *testing.T) {
	template := &Template{
		Type:               "Simple",
		Template:           "ik geef toestemming van {{valid_from}} tot {{valid_to}}.",
		TemplateAttributes: []string{ValidFromAttr, ValidToAttr},
	}

	timeInAmsterdam := func() time.Time {
		amsterdamLocation, _ := time.LoadLocation(AmsterdamTimeZone)
		return time.Now().In(amsterdamLocation)
	}

	t.Run("a valid contract returns no error", func(t *testing.T) {
		validFromStr := monday.Format(timeInAmsterdam().Add(-30*time.Minute), timeLayout, monday.LocaleNlNL)
		validToStr := monday.Format(timeInAmsterdam().Add(30*time.Minute), timeLayout, monday.LocaleNlNL)
		params := map[string]string{"language": "NL", ValidFromAttr: validFromStr, ValidToAttr: validToStr}

		contract := Contract{
			Template: template,
			Params:   params,
		}
		err := contract.Verify()
		assert.NoError(t, err)
	})

	t.Run("time range checks", func(t *testing.T) {

		t.Run("a contract with invalid time range returns an error", func(t *testing.T) {
			validFromStr := monday.Format(timeInAmsterdam().Add(30*time.Minute), timeLayout, monday.LocaleNlNL)
			validToStr := monday.Format(timeInAmsterdam().Add(-30*time.Minute), timeLayout, monday.LocaleNlNL)
			params := map[string]string{"language": "NL", ValidFromAttr: validFromStr, ValidToAttr: validToStr}

			contract := Contract{
				Template: template,
				Params:   params,
			}

			err := contract.Verify()
			expected := "invalid contract text: invalid period: [valid_from] must become before [valid_to]"
			if err == nil || err.Error() != expected {
				t.Errorf("expected '%v', got '%v'", expected, err)
			}
		})

		t.Run("a contract valid in the future is invalid", func(t *testing.T) {
			validFromStr := monday.Format(timeInAmsterdam().Add(30*time.Minute), timeLayout, monday.LocaleNlNL)
			validToStr := monday.Format(timeInAmsterdam().Add(130*time.Minute), timeLayout, monday.LocaleNlNL)
			params := map[string]string{"language": "NL", ValidFromAttr: validFromStr, ValidToAttr: validToStr}

			contract := Contract{
				Template: template,
				Params:   params,
			}

			err := contract.Verify()

			assert.EqualError(t, err, "invalid contract text: invalid period: contract is not yet valid")
		})

		t.Run("an expired contract is invalid", func(t *testing.T) {
			validFromStr := monday.Format(timeInAmsterdam().Add(-130*time.Minute), timeLayout, monday.LocaleNlNL)
			validToStr := monday.Format(timeInAmsterdam().Add(-30*time.Minute), timeLayout, monday.LocaleNlNL)
			params := map[string]string{"language": "NL", ValidFromAttr: validFromStr, ValidToAttr: validToStr}

			contract := Contract{
				Template: template,
				Params:   params,
			}

			err := contract.Verify()

			assert.EqualError(t, err, "invalid contract text: invalid period: contract is expired")
		})
	})

	t.Run("missing parameters", func(t *testing.T) {

		t.Run("no valid_from returns an error", func(t *testing.T) {
			validToStr := monday.Format(timeInAmsterdam().Add(130*time.Minute), timeLayout, monday.LocaleNlNL)
			params := map[string]string{"language": "NL", ValidToAttr: validToStr}
			contract := Contract{
				Template: template,
				Params:   params,
			}
			err := contract.Verify()
			expected := "invalid contract text: value for [valid_from] is missing"
			assert.EqualError(t, err, expected)
		})

		t.Run("no valid_to returns an error", func(t *testing.T) {
			validFromStr := monday.Format(timeInAmsterdam().Add(30*time.Minute), timeLayout, monday.LocaleNlNL)
			params := map[string]string{"language": "NL", ValidFromAttr: validFromStr}
			contract := Contract{
				Template: template,
				Params:   params,
			}
			err := contract.Verify()
			expected := "invalid contract text: value for [valid_to] is missing"
			assert.EqualError(t, err, expected)
		})
	})

	t.Run("misformed time strings", func(t *testing.T) {

		t.Run("a misformed valid_from returns an error", func(t *testing.T) {
			validFromStr := "vandaag"
			validToStr := monday.Format(timeInAmsterdam().Add(130*time.Minute), timeLayout, monday.LocaleNlNL)
			params := map[string]string{"language": "NL", ValidFromAttr: validFromStr, ValidToAttr: validToStr}
			contract := Contract{
				Template: template,
				Params:   params,
			}
			err := contract.Verify()
			expected := `invalid contract text: unable to parse [valid_from]: invalid time string [vandaag]: parsing time "vandaag" as "Monday, 2 January 2006 15:04:05": cannot parse "vandaag" as "Monday"`
			assert.EqualError(t, err, expected)
		})

		t.Run("a misformed valid_to returns an error", func(t *testing.T) {
			validFromStr := monday.Format(timeInAmsterdam().Add(130*time.Minute), timeLayout, monday.LocaleNlNL)
			validToStr := "morgen"
			params := map[string]string{"language": "NL", ValidFromAttr: validFromStr, ValidToAttr: validToStr}
			contract := Contract{
				Template: template,
				Params:   params,
			}
			err := contract.Verify()
			expected := `invalid contract text: unable to parse [valid_to]: invalid time string [morgen]: parsing time "morgen" as "Monday, 2 January 2006 15:04:05": cannot parse "morgen" as "Monday"`
			assert.EqualError(t, err, expected)
		})

	})
}

func TestParseContractString(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		// note that the contract text contains an ampersand (&) to test if it is properly url encoded
		rawText := "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens Toon & Zoonen en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42."
		signedContract, err := ParseContractString(rawText, StandardContractTemplates)

		require.NoError(t, err)
		require.NotNil(t, signedContract)
		assert.Equal(t, "Toon & Zoonen", signedContract.Params["legal_entity"])
		assert.Equal(t, "dinsdag, 1 oktober 2019 13:30:42", signedContract.Params["valid_from"])
		assert.Equal(t, "dinsdag, 1 oktober 2019 14:30:42", signedContract.Params["valid_to"])
		assert.Equal(t, "Demo EHR", signedContract.Params["acting_party"])
	})

	t.Run("Missing legalEntity returns error", func(t *testing.T) {
		rawText := "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens  en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42."
		signedContract, err := ParseContractString(rawText, StandardContractTemplates)

		assert.Nil(t, signedContract)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrInvalidContractText))
	})
}
