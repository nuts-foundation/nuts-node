/*
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

package verifier

import (
	"path"
	"testing"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/nuts-foundation/nuts-node/vcr/credential"
	"github.com/stretchr/testify/assert"
)

func TestNewLeiaVerifierStore(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		verifierStorePath := path.Join(testDir, "vcr", "verifier-store.db")
		sut, err := NewLeiaVerifierStore(verifierStorePath)

		assert.NoError(t, err)
		assert.IsType(t, &leiaVerifierStore{}, sut)
	})

	t.Run("error", func(t *testing.T) {
		sut, err := NewLeiaVerifierStore("/")

		assert.Contains(t, err.Error(), "failed to create leiaVerifierStore:")
		assert.Nil(t, sut)
	})
}

func TestLeiaStore_Close(t *testing.T) {
	testDir := io.TestDirectory(t)
	verifierStorePath := path.Join(testDir, "vcr", "verifier-store.db")
	sut, _ := NewLeiaVerifierStore(verifierStorePath)
	err := sut.Close()
	assert.NoError(t, err)
}

func Test_leiaVerifierStore_StoreRevocation(t *testing.T) {
	testDir := io.TestDirectory(t)
	verifierStorePath := path.Join(testDir, "vcr", "verifier-store.db")
	sut, _ := NewLeiaVerifierStore(verifierStorePath)

	t.Run("it stores a revocation and can find it back", func(t *testing.T) {
		subjectID := ssi.MustParseURI("did:nuts:123#ab-c")
		revocation := &credential.Revocation{Subject: subjectID}
		err := sut.StoreRevocation(*revocation)
		assert.NoError(t, err)
		result, err := sut.GetRevocations(subjectID)
		assert.NoError(t, err)
		assert.Equal(t, []*credential.Revocation{revocation}, result)
	})
}

func Test_leiaVerifierStore_GetRevocation(t *testing.T) {
	testDir := io.TestDirectory(t)
	verifierStorePath := path.Join(testDir, "vcr", "verifier-store.db")
	sut, _ := NewLeiaVerifierStore(verifierStorePath)
	subjectID := ssi.MustParseURI("did:nuts:123#ab-c")
	revocation := &credential.Revocation{Subject: subjectID}
	assert.NoError(t, sut.StoreRevocation(*revocation))

	t.Run("it can find a revocation", func(t *testing.T) {
		result, err := sut.GetRevocations(subjectID)
		assert.NoError(t, err)
		assert.Equal(t, []*credential.Revocation{revocation}, result)
	})

	t.Run("it returns a ErrNotFound when revocation could not be found", func(t *testing.T) {
		unknownSubjectID := ssi.MustParseURI("did:nuts:456#ab-cde")
		result, err := sut.GetRevocations(unknownSubjectID)
		assert.EqualError(t, err, "not found")
		assert.Nil(t, result)
	})
}
