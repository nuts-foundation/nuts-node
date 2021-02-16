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

package credential

import (
	"errors"
	"os"
	"path"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/go-leia"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/credential/concept"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

func TestCredential_Configure(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		instance := NewCredentialInstance().(*credential)

		err := instance.Configure(core.ServerConfig{Datadir: testDir})
		if !assert.NoError(t, err) {
			return
		}

		fsPath := path.Join(testDir, "credentials", "credentials.db")
		_, err = os.Stat(fsPath)
		assert.NoError(t, err)
	})

	t.Run("error - creating db", func(t *testing.T) {
		instance := NewCredentialInstance().(*credential)

		err := instance.Configure(core.ServerConfig{Datadir: "test"})
		assert.Error(t, err)
	})

	t.Run("error - loading templates", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		registry := concept.NewMockRegistry(ctrl)
		instance := credential{
			registry: registry,
		}

		registry.EXPECT().LoadTemplates().Return(errors.New("b00m!"))

		err := instance.Configure(core.ServerConfig{Datadir: testDir})
		assert.Error(t, err)
	})
}

func TestCredential_Search(t *testing.T) {
	testDir := io.TestDirectory(t)
	instance := NewTestCredentialInstance(testDir)

	// init template
	err := instance.registry.AddFromString(concept.ExampleTemplate)
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
	q.AddCriteria(concept.Eq("company.name", "Because we care BV"))

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
