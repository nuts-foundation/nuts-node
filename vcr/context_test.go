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

package vcr

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/jsonld"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

// TestNutsV2Context tests if some example jsonld is correctly expanded/compacted with the current default context
func TestNutsV2Context(t *testing.T) {
	vcJSON, _ := os.ReadFile("test/auth_vc.jsonld")
	jsonldManager := jsonld.NewJSONLDInstance()
	jsonldManager.(core.Configurable).Configure(*core.NewServerConfig())
	reader := jsonld.Reader{DocumentLoader: jsonldManager.DocumentLoader()}
	documents, err := reader.ReadBytes(vcJSON)
	if err != nil {
		panic(err)
	}

	t.Run("expand and compact", func(t *testing.T) {
		options := ld.NewJsonLdOptions("")
		options.DocumentLoader = jsonldManager.DocumentLoader()
		processor := ld.NewJsonLdProcessor()

		compacted, err := processor.Compact(documents[0], nil, options)
		if !assert.NoError(t, err) {
			return
		}
		expanded, err := processor.Expand(compacted, options)

		assert.Equal(t, documents[0], expanded[0])
		assert.NoError(t, err)
	})
}
