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

package usecase

import (
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

var jwtVP vc.VerifiablePresentation

var testDefinition = Definition{
	Endpoint: "http://example.com/usecase",
}

func init() {
	const rawVP = `eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpudXRzOkd2a3p4c2V6SHZFYzhuR2hnejZYbzNqYnFrSHdzd0xtV3czQ1l0Q203aEFXI2FiYy1tZXRob2QtMSIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2OTc2OTY3NDEsImlzcyI6ImRpZDpudXRzOkd2a3p4c2V6SHZFYzhuR2hnejZYbzNqYnFrSHdzd0xtV3czQ1l0Q203aEFXIiwibmJmIjoxNjk3NjEwMzQxLCJzdWIiOiJkaWQ6bnV0czpHdmt6eHNlekh2RWM4bkdoZ3o2WG8zamJxa0h3c3dMbVd3M0NZdENtN2hBVyIsInZwIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIl0sInR5cGUiOiJWZXJpZmlhYmxlUHJlc2VudGF0aW9uIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL251dHMubmwvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3czYy1jY2cuZ2l0aHViLmlvL2xkcy1qd3MyMDIwL2NvbnRleHRzL2xkcy1qd3MyMDIwLXYxLmpzb24iXSwiY3JlZGVudGlhbFN1YmplY3QiOnsiY29tcGFueSI6eyJjaXR5IjoiSGVuZ2VsbyIsIm5hbWUiOiJEZSBiZXN0ZSB6b3JnIn0sImlkIjoiZGlkOm51dHM6R3ZrenhzZXpIdkVjOG5HaGd6NlhvM2picWtId3N3TG1XdzNDWXRDbTdoQVcifSwiaWQiOiJkaWQ6bnV0czo0dHpNYVdmcGl6VktlQThmc2NDM0pUZFdCYzNhc1VXV01qNWhVRkhkV1gzSCNmNDNiZWY0Zi0xYTc5LTQzNjQtOTJmMy0zZmM3NDNmYTlmMTkiLCJpc3N1YW5jZURhdGUiOiIyMDIxLTEyLTI0VDEzOjIxOjI5LjA4NzIwNSswMTowMCIsImlzc3VlciI6ImRpZDpudXRzOjR0ek1hV2ZwaXpWS2VBOGZzY0MzSlRkV0JjM2FzVVdXTWo1aFVGSGRXWDNIIiwicHJvb2YiOnsiY3JlYXRlZCI6IjIwMjEtMTItMjRUMTM6MjE6MjkuMDg3MjA1KzAxOjAwIiwiandzIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJbUkyTkNJNlptRnNjMlVzSW1OeWFYUWlPbHNpWWpZMElsMTkuLmhQTTJHTGMxSzlkMkQ4U2J2ZTAwNHg5U3VtakxxYVhUaldoVWh2cVdSd3hmUldsd2ZwNWdIRFVZdVJvRWpoQ1hmTHQtX3Uta25DaFZtSzk4ME4zTEJ3IiwicHJvb2ZQdXJwb3NlIjoiTnV0c1NpZ25pbmdLZXlUeXBlIiwidHlwZSI6Ikpzb25XZWJTaWduYXR1cmUyMDIwIiwidmVyaWZpY2F0aW9uTWV0aG9kIjoiZGlkOm51dHM6R3ZrenhzZXpIdkVjOG5HaGd6NlhvM2picWtId3N3TG1XdzNDWXRDbTdoQVcjYWJjLW1ldGhvZC0xIn0sInR5cGUiOlsiQ29tcGFueUNyZWRlbnRpYWwiLCJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdfX19.v3beJvGa3HeImU3VLvsrZjnHs0krKPaCdTEh-qHS7j26LIQYcMHhrLkIexrpPO5z0TKSDnKq5Jl10SWaJpLRIA`
	vp, err := vc.ParseVerifiablePresentation(rawVP)
	if err != nil {
		panic(err)
	}
	jwtVP = *vp
}

func Test_list_exists(t *testing.T) {
	t.Run("empty list", func(t *testing.T) {
		l, err := createList(testDefinition)
		require.NoError(t, err)
		assert.False(t, l.exists(jwtVP))
	})
	t.Run("non-empty list, no match", func(t *testing.T) {
		l, err := createList(testDefinition)
		require.NoError(t, err)
		require.NoError(t, l.add(jwtVP))
		assert.False(t, l.exists(vc.VerifiablePresentation{}))
	})
	t.Run("non-empty list, match", func(t *testing.T) {
		l, err := createList(testDefinition)
		require.NoError(t, err)
		require.NoError(t, l.add(jwtVP))
		assert.True(t, l.exists(jwtVP))
	})
}

func Test_list_get(t *testing.T) {
	vp1, err := vc.ParseVerifiablePresentation(`{"id": "did:example:issuer#1"}`)
	require.NoError(t, err)
	vp2, err := vc.ParseVerifiablePresentation(`{"id": "did:example:issuer#2"}`)
	require.NoError(t, err)

	t.Run("empty list, empty timestamp", func(t *testing.T) {
		l, err := createList(testDefinition)
		require.NoError(t, err)
		presentations, timestamp := l.get(0)
		assert.Empty(t, presentations)
		assert.Empty(t, timestamp)
	})
	t.Run("1 entry, empty timestamp", func(t *testing.T) {
		l, err := createList(testDefinition)
		require.NoError(t, err)
		require.NoError(t, l.add(*vp1))
		presentations, timestamp := l.get(0)
		assert.Equal(t, []vc.VerifiablePresentation{*vp1}, presentations)
		assert.Equal(t, Timestamp(1), timestamp)
	})
	t.Run("2 entries, empty timestamp", func(t *testing.T) {
		l, err := createList(testDefinition)
		require.NoError(t, err)
		require.NoError(t, l.add(*vp1))
		require.NoError(t, l.add(*vp2))
		presentations, timestamp := l.get(0)
		assert.Equal(t, []vc.VerifiablePresentation{*vp1, *vp2}, presentations)
		assert.Equal(t, Timestamp(2), timestamp)
	})
	t.Run("2 entries, start after first", func(t *testing.T) {
		l, err := createList(testDefinition)
		require.NoError(t, err)
		require.NoError(t, l.add(*vp1))
		require.NoError(t, l.add(*vp2))
		presentations, timestamp := l.get(1)
		assert.Equal(t, []vc.VerifiablePresentation{*vp2}, presentations)
		assert.Equal(t, Timestamp(2), timestamp)
	})
	t.Run("2 entries, start after end", func(t *testing.T) {
		l, err := createList(testDefinition)
		require.NoError(t, err)
		require.NoError(t, l.add(*vp1))
		require.NoError(t, l.add(*vp2))
		presentations, timestamp := l.get(2)
		assert.Equal(t, []vc.VerifiablePresentation{}, presentations)
		assert.Equal(t, Timestamp(2), timestamp)
	})
}

func Test_list_add(t *testing.T) {
	vp1, err := vc.ParseVerifiablePresentation(`{"id": "did:example:issuer#1"}`)
	require.NoError(t, err)

	t.Run("already exists", func(t *testing.T) {
		l, err := createList(testDefinition)
		require.NoError(t, err)
		err = l.add(*vp1)
		require.NoError(t, err)
		err = l.add(*vp1)
		assert.Equal(t, ErrPresentationAlreadyExists, err)
	})
}

func Test_maintainer_Add(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		m, err := newMaintainer("", []Definition{testDefinition})
		require.NoError(t, err)

		err = m.Add("usecase", jwtVP)
		assert.NoError(t, err)

		_, timestamp, err := m.Get("usecase", 0)
		assert.NoError(t, err)
		assert.Equal(t, Timestamp(1), *timestamp)
	})
	t.Run("already exists", func(t *testing.T) {
		m, err := newMaintainer("", []Definition{testDefinition})
		require.NoError(t, err)

		err = m.Add("usecase", jwtVP)
		assert.NoError(t, err)
		err = m.Add("usecase", jwtVP)
		assert.EqualError(t, err, "presentation already exists")
	})
	t.Run("list unknown", func(t *testing.T) {
		m, err := newMaintainer("", []Definition{testDefinition})
		require.NoError(t, err)
		err = m.Add("unknown", jwtVP)
		assert.EqualError(t, err, "list not found")
	})
}

func Test_maintainer_Get(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		m, err := newMaintainer("", []Definition{testDefinition})
		require.NoError(t, err)
		err = m.Add("usecase", jwtVP)
		assert.NoError(t, err)

		vps, timestamp, err := m.Get("usecase", 0)
		assert.NoError(t, err)
		assert.Equal(t, []vc.VerifiablePresentation{jwtVP}, vps)
		assert.Equal(t, Timestamp(1), *timestamp)
	})
	t.Run("list unknown", func(t *testing.T) {
		m, err := newMaintainer("", []Definition{testDefinition})
		require.NoError(t, err)
		_, _, err = m.Get("unknown", 0)
		assert.EqualError(t, err, "list not found")
	})
}
