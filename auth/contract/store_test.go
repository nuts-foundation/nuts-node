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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTemplateStore_FindFromRawContractText(t *testing.T) {
	t.Run("a correct triple returns the contract", func(t *testing.T) {
		expected := StandardContractTemplates[Language("NL")][Type("BehandelaarLogin")][Version("v1")]
		rawContractText := "NL:BehandelaarLogin:v1"
		got, err := StandardContractTemplates.FindFromRawContractText(rawContractText)
		assert.NoError(t, err)
		if got != expected {
			t.Errorf("Expected different contract. Expected: %v, got: %v", expected, got)
		}
	})

	t.Run("an unknown triple returns an error", func(t *testing.T) {
		rawContractText := "DE:BehandelaarLogin:v1"

		got, err := StandardContractTemplates.FindFromRawContractText(rawContractText)
		assert.EqualError(t, err, "could not find contract template for language 'DE', type 'BehandelaarLogin' and version 'v1'")
		assert.Nil(t, got)
	})

	t.Run("a valid triple other than at the start of the contents returns a nil", func(t *testing.T) {
		rawContractText := "some other text NL:BehandelaarLogin:v1"

		got, err := StandardContractTemplates.FindFromRawContractText(rawContractText)
		assert.EqualError(t, err, "invalid contract text: could not extract contract version, language and type")
		assert.Nil(t, got)
	})

}

func TestTemplateStore_Find(t *testing.T) {
	t.Run("It finds a known Dutch Template", func(t *testing.T) {
		want := Type("BehandelaarLogin")
		if got := StandardContractTemplates.Get(want, "NL", "v3"); got.Type != want {
			t.Errorf("NewByType() = %v, want %v", got, want)
		}
	})

	t.Run("It uses the latest version if no version is provided", func(t *testing.T) {
		want := Version("v3")
		if got := StandardContractTemplates.Get("BehandelaarLogin", "NL", ""); got.Version != want {
			t.Errorf("Wrong language %v, want %v", got, want)
		}
	})

	t.Run("It finds a known English Template", func(t *testing.T) {
		want := Type("PractitionerLogin")
		if got := StandardContractTemplates.Get(want, "EN", "v3"); got.Type != want {
			t.Errorf("NewByType() = %v, want %v", got, want)
		}
	})

	t.Run("An unknown contract should return a nil", func(t *testing.T) {
		want := Type("UnknownContract")
		if got := StandardContractTemplates.Get(want, "NL", "v3"); got != nil {
			t.Errorf("NewByType() = %v, want %v", got, nil)
		}
	})
}
