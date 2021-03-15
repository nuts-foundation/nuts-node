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
	"path"
	"testing"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
)

const nutsTestCredential = "NutsOrganizationCredential"

func TestTrustConfig_Save(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		tc := trustConfig{
			filename:      path.Join(testDir, "test.yaml"),
			issuesPerType: map[string][]string{},
		}

		tc.issuesPerType[nutsTestCredential] = []string{"did:nuts:1"}

		err := tc.Save()
		if !assert.NoError(t, err) {
			return
		}

		tc2 := trustConfig{
			filename:      path.Join(testDir, "test.yaml"),
			issuesPerType: map[string][]string{},
		}

		err = tc2.Load()
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, []string{"did:nuts:1"}, tc2.issuesPerType[nutsTestCredential])
	})
}

func TestTrustConfig_Load(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		tc := trustConfig{
			filename:      "test/issuers.yaml",
			issuesPerType: map[string][]string{},
		}

		err := tc.Load()
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, []string{"did:nuts:t1DVVAs5fmNba8fdKoTSQNtiGcH49vicrkjZW2KRqpv"}, tc.issuesPerType[nutsTestCredential])
	})
}

func TestTrustConfig_IsTrusted(t *testing.T) {
	tc := trustConfig{
		filename:      "test/issuers.yaml",
		issuesPerType: map[string][]string{},
	}

	err := tc.Load()
	if !assert.NoError(t, err) {
		return
	}

	c, _ := did.ParseURI(nutsTestCredential)

	t.Run("true", func(t *testing.T) {
		d, _ := did.ParseURI("did:nuts:t1DVVAs5fmNba8fdKoTSQNtiGcH49vicrkjZW2KRqpv")

		assert.True(t, tc.IsTrusted(*c, *d))
	})

	t.Run("false", func(t *testing.T) {
		d, _ := did.ParseURI("did:nuts:1")

		assert.False(t, tc.IsTrusted(*c, *d))
	})
}
