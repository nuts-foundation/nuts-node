/*
 * Nuts node
 * Copyright (C) 2022 Nuts community
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

package jsonld

import (
	"github.com/nuts-foundation/nuts-node/json"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
)

func TestPath_IsEmpty(t *testing.T) {
	t.Run("true for empty list", func(t *testing.T) {
		assert.True(t, Path{}.IsEmpty())
	})

	t.Run("true for nil", func(t *testing.T) {
		var p Path = nil

		assert.True(t, p.IsEmpty())
	})

	t.Run("false", func(t *testing.T) {
		assert.False(t, NewPath("not empty").IsEmpty())
	})
}

func TestPath_Head(t *testing.T) {
	t.Run("empty string for empty Path", func(t *testing.T) {
		assert.Equal(t, "", Path{}.Head())
	})

	t.Run("empty string for nil", func(t *testing.T) {
		var p Path = nil

		assert.Equal(t, "", p.Head())
	})

	t.Run("head otherwise", func(t *testing.T) {
		assert.Equal(t, "head", NewPath("head").Head())
	})
}

func TestPath_Tail(t *testing.T) {
	t.Run("nil for empty Path", func(t *testing.T) {
		assert.Nil(t, Path{}.Tail())
	})

	t.Run("nil for len <= 1", func(t *testing.T) {
		assert.Nil(t, NewPath("head").Tail())
		assert.Nil(t, NewPath().Tail())
	})

	t.Run("tail otherwise", func(t *testing.T) {
		assert.Equal(t, NewPath("tail"), NewPath("head", "tail").Tail())
	})
}

func TestExpanded_ValueAt(t *testing.T) {
	marshalled := make(map[string]interface{})
	if err := json.Unmarshal([]byte(JSONLDExample), &marshalled); err != nil {
		t.Fatal(err)
	}
	expanded, err := ld.NewJsonLdProcessor().Expand(marshalled, nil)
	if err != nil {
		t.Fatal(err)
	}

	document := Document(expanded)

	t.Run("ok - find the root identifier", func(t *testing.T) {
		values := document.ValueAt(NewPath())

		assert.Len(t, values, 1)
		assert.Equal(t, "123456782", values[0].String())
	})

	t.Run("ok - find a single string value", func(t *testing.T) {
		values := document.ValueAt(NewPath("http://example.com/name"))

		assert.Len(t, values, 1)
		assert.Equal(t, "Jane Doe", values[0].String())
	})

	t.Run("ok - find a single nested string value", func(t *testing.T) {
		values := document.ValueAt(NewPath("http://example.com/parents", "http://example.com/name"))

		assert.Len(t, values, 1)
		assert.Equal(t, "John Doe", values[0].String())
	})

	t.Run("ok - find a single nested string value in a list", func(t *testing.T) {
		values := document.ValueAt(NewPath("http://example.com/children", "http://example.com/name"))

		assert.Len(t, values, 1)
		assert.Equal(t, "John Doe", values[0].String())
	})

	t.Run("ok - find multiple list values", func(t *testing.T) {
		values := document.ValueAt(NewPath("http://example.com/telephone"))

		assert.Len(t, values, 2)
		assert.Equal(t, "06-12345678", values[0].String())
		assert.Equal(t, "06-87654321", values[1].String())
	})

	t.Run("ok - find a nested @type", func(t *testing.T) {
		values := document.ValueAt(NewPath("http://example.com/parents", "@type"))

		assert.Len(t, values, 1)
		assert.Equal(t, "http://example.com/Person", values[0].String())
	})

	t.Run("ok - find a nested @type in a list", func(t *testing.T) {
		values := document.ValueAt(NewPath("http://example.com/children", "@type"))

		assert.Len(t, values, 1)
		assert.Equal(t, "http://example.com/Person", values[0].String())
	})

	t.Run("ok - find a single id value", func(t *testing.T) {
		values := document.ValueAt(NewPath("http://example.com/url"))

		assert.Len(t, values, 1)
		assert.Equal(t, "http://www.janedoe.com", values[0].String())
	})

	t.Run("ok - empty for incomplete path", func(t *testing.T) {
		values := document.ValueAt(NewPath("http://example.com/children"))

		assert.Len(t, values, 0)
	})
}
