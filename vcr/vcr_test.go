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
 *
 */

package vcr

import (
	"os"
	"path"
	"testing"

	"github.com/nuts-foundation/go-leia"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/stretchr/testify/assert"
)

func TestVCR_Configure(t *testing.T) {

	t.Run("error - creating db", func(t *testing.T) {
		instance := NewVCRInstance(nil, nil, nil).(*vcr)

		err := instance.Configure(core.ServerConfig{Datadir: "test"})
		assert.Error(t, err)
	})

	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		instance := NewVCRInstance(nil, nil, nil).(*vcr)

		err := instance.Configure(core.ServerConfig{Datadir: testDir})
		if !assert.NoError(t, err) {
			return
		}

		t.Run("loads default templates", func(t *testing.T) {
			cTemplates := instance.registry.ConceptTemplates()

			if ! assert.Len(t, cTemplates, 1) {
				return
			}

			orgTemplate := cTemplates["organization"]

			assert.NotNil(t, orgTemplate)
		})

		t.Run("initializes DB", func(t *testing.T) {
			fsPath := path.Join(testDir, "vcr", "credentials.db")
			_, err = os.Stat(fsPath)
			assert.NoError(t, err)
		})
	})
}

func TestVCR_Search(t *testing.T) {
	testDir := io.TestDirectory(t)
	instance := NewTestVCRInstance(testDir)

	ct, err := concept.ParseTemplate(concept.ExampleTemplate)
	if !assert.NoError(t, err) {
		return
	}
	// init template
	err = instance.registry.Add(ct)
	if !assert.NoError(t, err) {
		return
	}

	// reindex
	err = instance.initIndices()
	if !assert.NoError(t, err) {
		return
	}

	// add document
	doc := leia.Document(concept.TestCredential)
	err = instance.store.Collection(concept.ExampleType).Add([]leia.Document{doc})
	if !assert.NoError(t, err) {
		return
	}

	// query
	q, err := instance.Registry().QueryFor(concept.ExampleConcept)
	if !assert.NoError(t, err) {
		return
	}
	q.AddClause(concept.Eq("company.name", "Because we care BV"))

	creds, err := instance.Search(q)
	if !assert.NoError(t, err) {
		return
	}

	assert.Len(t, creds, 1)

	cs := creds[0].CredentialSubject[0]
	m := cs.(map[string]interface{})
	c := m["company"].(map[string]interface{})

	assert.Equal(t, "Because we care BV", c["name"])
}
