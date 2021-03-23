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

package trust

import (
	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"path"
	"testing"
)

const nutsTestCredential = "NutsOrganizationCredential"

func TestTrustConfig_save(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		tc := NewConfig(path.Join(testDir, "test.yaml"))

		tc.issuersPerType[nutsTestCredential] = []string{"did:nuts:1"}

		err := tc.save()
		if !assert.NoError(t, err) {
			return
		}

		tc2 := Config{
			filename:       path.Join(testDir, "test.yaml"),
			issuersPerType: map[string][]string{},
		}

		err = tc2.Load()
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, []string{"did:nuts:1"}, tc2.issuersPerType[nutsTestCredential])
	})

	t.Run("error - no filename", func(t *testing.T) {
		err := NewConfig("").save()

		assert.Error(t, err)
	})
}

func TestTrustConfig_Load(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		tc := NewConfig("../test/issuers.yaml")

		err := tc.Load()
		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, []string{"did:nuts:t1DVVAs5fmNba8fdKoTSQNtiGcH49vicrkjZW2KRqpv"}, tc.issuersPerType[nutsTestCredential])
	})

	t.Run("error - no filename", func(t *testing.T) {
		err := NewConfig("").Load()

		assert.Error(t, err)
	})
}

func TestTrustConfig_IsTrusted(t *testing.T) {
	tc := NewConfig("../test/issuers.yaml")

	err := tc.Load()
	if !assert.NoError(t, err) {
		return
	}

	c, _ := ssi.ParseURI(nutsTestCredential)

	t.Run("true", func(t *testing.T) {
		d, _ := ssi.ParseURI("did:nuts:t1DVVAs5fmNba8fdKoTSQNtiGcH49vicrkjZW2KRqpv")

		assert.True(t, tc.IsTrusted(*c, *d))
	})

	t.Run("false", func(t *testing.T) {
		d, _ := ssi.ParseURI("did:nuts:1")

		assert.False(t, tc.IsTrusted(*c, *d))
	})
}

func TestConfig_AddTrust(t *testing.T) {
	testDir := io.TestDirectory(t)
	tc := NewConfig(path.Join(testDir, "test.yaml"))
	issuer, _ := ssi.ParseURI("did:nuts:1")

	t.Run("ok - already present", func(t *testing.T) {
		err := tc.AddTrust(vc.VerifiableCredentialTypeV1URI(), *issuer)

		assert.NoError(t, err)

		err = tc.AddTrust(vc.VerifiableCredentialTypeV1URI(), *issuer)

		assert.NoError(t, err)
	})
}

func TestConfig_RemoveTrust(t *testing.T) {
	testDir := io.TestDirectory(t)
	tc := NewConfig(path.Join(testDir, "test.yaml"))
	issuer, _ := ssi.ParseURI("did:nuts:1")

	t.Run("ok - not present", func(t *testing.T) {
		isTrusted := tc.IsTrusted(vc.VerifiableCredentialTypeV1URI(), *issuer)

		assert.False(t, isTrusted)
		err := tc.RemoveTrust(vc.VerifiableCredentialTypeV1URI(), *issuer)

		assert.NoError(t, err)
		assert.False(t, isTrusted)
	})

	t.Run("ok", func(t *testing.T) {
		err := tc.AddTrust(vc.VerifiableCredentialTypeV1URI(), *issuer)
		if !assert.NoError(t, err) {
			return
		}

		assert.True(t, tc.IsTrusted(vc.VerifiableCredentialTypeV1URI(), *issuer))
		err = tc.RemoveTrust(vc.VerifiableCredentialTypeV1URI(), *issuer)

		if !assert.NoError(t, err) {
			return
		}
		assert.False(t, tc.IsTrusted(vc.VerifiableCredentialTypeV1URI(), *issuer))
	})

	t.Run("ok - with multiple entries", func(t *testing.T) {
		testDir := io.TestDirectory(t)
		tc := NewConfig(path.Join(testDir, "test.yaml"))

		issuer2, _ := ssi.ParseURI("did:nuts:2")
		issuer3, _ := ssi.ParseURI("did:nuts:3")

		tc.AddTrust(vc.VerifiableCredentialTypeV1URI(), *issuer)
		tc.AddTrust(vc.VerifiableCredentialTypeV1URI(), *issuer2)
		tc.AddTrust(vc.VerifiableCredentialTypeV1URI(), *issuer3)

		err := tc.RemoveTrust(vc.VerifiableCredentialTypeV1URI(), *issuer)

		if !assert.NoError(t, err) {
			return
		}
		assert.True(t, tc.IsTrusted(vc.VerifiableCredentialTypeV1URI(), *issuer3))
	})
}
