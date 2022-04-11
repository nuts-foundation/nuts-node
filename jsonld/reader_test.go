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
	"encoding/json"
	"testing"

	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
)

func TestDocumentReader_FromStruct(t *testing.T) {
	reader := Reader{
		DocumentLoader: &ld.DefaultDocumentLoader{},
	}

	t.Run("ok", func(t *testing.T) {
		object := make(map[string]interface{})
		_ = json.Unmarshal([]byte(jsonLDExample), &object)
		document, err := reader.Read(object)
		values := document.ValueAt(NewPath())

		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, document)
		assert.Len(t, values, 1)
		assert.Equal(t, "123456782", values[0].String())
	})
}

func TestDocumentReader_FromBytes(t *testing.T) {
	reader := Reader{
		DocumentLoader: &ld.DefaultDocumentLoader{},
	}

	t.Run("ok", func(t *testing.T) {
		document, err := reader.ReadBytes([]byte(jsonLDExample))
		values := document.ValueAt(NewPath())

		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, document)
		assert.Len(t, values, 1)
		assert.Equal(t, "123456782", values[0].String())
	})

	t.Run("error - wrong syntax", func(t *testing.T) {
		_, err := reader.ReadBytes([]byte("{"))

		assert.Error(t, err)
	})

	t.Run("error - invalid JSON-LD", func(t *testing.T) {
		_, err := reader.ReadBytes([]byte(invalidJSONLD))

		assert.Error(t, err)
	})
}
