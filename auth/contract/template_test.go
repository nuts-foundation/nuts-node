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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/goodsign/monday"
)

func TestContract_StandardTemplates(t *testing.T) {
	t.Run("v1", func(t *testing.T) {
		attrs := map[string]string{
			LegalEntityAttr: "Zorg & Zo",
			ActingPartyAttr: "Alpha & Beta",
		}
		t.Run("NL", func(t *testing.T) {
			tpl := StandardContractTemplates.Get("BehandelaarLogin", "NL", "v1")
			require.NotNil(t, tpl)

			actual, err := tpl.Render(attrs, time.Date(2020, 1, 1, 1, 1, 1, 0, time.UTC), time.Hour)

			require.NoError(t, err)
			assert.Equal(t, "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Alpha & Beta om namens Zorg & Zo en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van woensdag, 1 januari 2020 02:01:01 tot woensdag, 1 januari 2020 03:01:01.", actual.RawContractText)
		})
	})
	t.Run("v3", func(t *testing.T) {
		attrs := map[string]string{
			LegalEntityAttr:     "Zorg & Zo",
			LegalEntityCityAttr: "A & B",
		}
		t.Run("NL", func(t *testing.T) {
			tpl := StandardContractTemplates.Get("BehandelaarLogin", "NL", "v3")
			require.NotNil(t, tpl)

			actual, err := tpl.Render(attrs, time.Date(2020, 1, 1, 1, 1, 1, 0, time.UTC), time.Hour)

			require.NoError(t, err)
			assert.Equal(t, "NL:BehandelaarLogin:v3 Hierbij verklaar ik te handelen in naam van Zorg & Zo te A & B. Deze verklaring is geldig van woensdag, 1 januari 2020 02:01:01 tot woensdag, 1 januari 2020 03:01:01.", actual.RawContractText)
		})
		t.Run("EN", func(t *testing.T) {
			tpl := StandardContractTemplates.Get("PractitionerLogin", "EN", "v3")
			require.NotNil(t, tpl)

			actual, err := tpl.Render(attrs, time.Date(2020, 1, 1, 1, 1, 1, 0, time.UTC), time.Hour)

			require.NoError(t, err)
			assert.Equal(t, "EN:PractitionerLogin:v3 I hereby declare to act on behalf of Zorg & Zo located in A & B. This declaration is valid from Wednesday, 1 January 2020 02:01:01 until Wednesday, 1 January 2020 03:01:01.", actual.RawContractText)
		})
	})
}

func TestContract_RenderTemplate(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		template := &Template{Type: "Simple", Template: "ga je akkoord met {{wat}} van {{valid_from}} tot {{valid_to}}?", Locale: "nl_NL"}
		now := time.Now()
		result, err := template.Render(map[string]string{"wat": "alles"}, now, 60*time.Minute)
		require.NoError(t, err)
		amsterdamLocation, _ := time.LoadLocation(AmsterdamTimeZone)

		from := monday.Format(now.In(amsterdamLocation).Add(0), timeLayout, monday.LocaleNlNL)
		to := monday.Format(now.In(amsterdamLocation).Add(60*time.Minute), timeLayout, monday.LocaleNlNL)

		expected := fmt.Sprintf("ga je akkoord met alles van %s tot %s?", from, to)
		if result.RawContractText != expected {
			t.Errorf("Error while rendering the Template: got '%v', expected '%v'", result, expected)
		}
	})
	t.Run("with ampersand (triple escape)", func(t *testing.T) {
		template := &Template{Type: "Simple", Template: "ampersand & in text and message {{{wat}}} van {{valid_from}} tot {{valid_to}}?", Locale: "nl_NL"}
		now := time.Now()
		result, err := template.Render(map[string]string{"wat": "&"}, now, 60*time.Minute)
		require.NoError(t, err)
		amsterdamLocation, _ := time.LoadLocation(AmsterdamTimeZone)

		from := monday.Format(now.In(amsterdamLocation).Add(0), timeLayout, monday.LocaleNlNL)
		to := monday.Format(now.In(amsterdamLocation).Add(60*time.Minute), timeLayout, monday.LocaleNlNL)

		expected := fmt.Sprintf("ampersand & in text and message & van %s tot %s?", from, to)
		assert.Equal(t, expected, result.RawContractText)
	})
}

func TestParseTime(t *testing.T) {
	t.Run("parse Dutch time", func(t *testing.T) {
		contractTime := "Woensdag, 3 April 2019 16:36:06"
		parsedTime, err := parseTime(contractTime, "NL")
		if err != nil {
			t.Error("expected date to be parsed")
		}

		location, _ := time.LoadLocation(AmsterdamTimeZone)
		expectedTime := time.Date(2019, 4, 3, 16, 36, 06, 0, location)

		if parsedTime == nil || !parsedTime.Equal(expectedTime) {
			t.Errorf("expected dutch time to be parsed. Got %v, expected %v", parsedTime, expectedTime)
		}
	})

	t.Run("parse English time", func(t *testing.T) {
		contractTime := "Wednesday, 3 April 2019 16:36:06"
		parsedTime, err := parseTime(contractTime, "EN")
		if err != nil {
			t.Error("expected date to be parsed")
		}

		location, _ := time.LoadLocation(AmsterdamTimeZone)
		expectedTime := time.Date(2019, 4, 3, 16, 36, 06, 0, location)

		if parsedTime == nil || !parsedTime.Equal(expectedTime) {
			t.Errorf("expected English time to be parsed. Got %v, expected %v", parsedTime, expectedTime)
		}
	})

	t.Run("parse rubbish", func(t *testing.T) {
		contractTime := "Today is gonna be the day"
		parsedTime, err := parseTime(contractTime, "EN")
		if err == nil {
			t.Error("expected an error to occur")
		}

		if parsedTime != nil {
			t.Errorf("expected parsedTime to be nil. got %v", parsedTime)
		}
	})

	t.Run("parse date with wrong day", func(t *testing.T) {
		t.Skip("This is not supported by the 'monday' package. Should we build it ourselves?")
		contractTime := "Dinsdag, 3 April 2019 16:36:06"
		parsedTime, err := parseTime(contractTime, "NL")
		if err == nil {
			t.Error("expected an error to occur")
		}

		if parsedTime != nil {
			t.Errorf("expected parsedTime to be nil. got %v", parsedTime)
		}
	})
}
