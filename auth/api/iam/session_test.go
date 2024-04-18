/*
 * Copyright (C) 2024 Nuts community
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

package iam

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/pe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUserWallet_Key(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		keyAsJWK, err := jwk.FromRaw(pk)
		require.NoError(t, err)
		jwkAsJSON, _ := json.Marshal(keyAsJWK)
		wallet := UserWallet{
			JWK: jwkAsJSON,
		}
		key, err := wallet.Key()
		require.NoError(t, err)
		assert.Equal(t, keyAsJWK, key)
	})
}

func TestOpenID4VPVerifier_next(t *testing.T) {
	userPresentationDefinition := PresentationDefinition{
		Id: "user",
	}
	orgPresentationDefinition := PresentationDefinition{
		Id: "organization",
	}
	t.Run("owner is next", func(t *testing.T) {
		v := PEXState{
			RequiredPresentationDefinitions: map[pe.WalletOwnerType]pe.PresentationDefinition{
				pe.WalletOwnerOrganization: orgPresentationDefinition,
				pe.WalletOwnerUser:         userPresentationDefinition,
			},
			Submissions: map[string]PresentationSubmission{},
		}
		ownerType, definition := v.next()
		assert.Equal(t, pe.WalletOwnerOrganization, *ownerType)
		assert.Equal(t, orgPresentationDefinition, *definition)

	})
	t.Run("user is next", func(t *testing.T) {
		v := PEXState{
			RequiredPresentationDefinitions: map[pe.WalletOwnerType]pe.PresentationDefinition{
				pe.WalletOwnerOrganization: orgPresentationDefinition,
				pe.WalletOwnerUser:         userPresentationDefinition,
			},
			Submissions: map[string]PresentationSubmission{
				orgPresentationDefinition.Id: {},
			},
		}
		ownerType, definition := v.next()
		assert.Equal(t, pe.WalletOwnerUser, *ownerType)
		assert.Equal(t, userPresentationDefinition, *definition)
	})
	t.Run("no next", func(t *testing.T) {
		v := PEXState{
			RequiredPresentationDefinitions: map[pe.WalletOwnerType]pe.PresentationDefinition{
				pe.WalletOwnerOrganization: orgPresentationDefinition,
				pe.WalletOwnerUser:         userPresentationDefinition,
			},
			Submissions: map[string]PresentationSubmission{
				orgPresentationDefinition.Id:  {},
				userPresentationDefinition.Id: {},
			},
		}
		ownerType, definition := v.next()
		assert.Nil(t, ownerType)
		assert.Nil(t, definition)
	})
}

func TestOpenID4VPVerifier_fulfill(t *testing.T) {
	userPresentationDefinition := PresentationDefinition{
		Id: "user",
	}
	orgPresentationDefinition := PresentationDefinition{
		Id: "organization",
	}
	t.Run("ok", func(t *testing.T) {
		v := PEXState{
			Submissions: map[string]pe.PresentationSubmission{},
			RequiredPresentationDefinitions: map[pe.WalletOwnerType]pe.PresentationDefinition{
				pe.WalletOwnerOrganization: orgPresentationDefinition,
			},
		}
		err := v.fulfill(orgPresentationDefinition.Id, PresentationSubmission{}, []VerifiablePresentation{}, map[string]VerifiableCredential{})
		require.NoError(t, err)
	})
	t.Run("not required", func(t *testing.T) {
		v := PEXState{
			Submissions: map[string]pe.PresentationSubmission{},
			Credentials: map[string]vc.VerifiableCredential{},
			RequiredPresentationDefinitions: map[pe.WalletOwnerType]pe.PresentationDefinition{
				pe.WalletOwnerUser: userPresentationDefinition,
			},
		}
		err := v.fulfill(orgPresentationDefinition.Id, PresentationSubmission{}, []VerifiablePresentation{}, map[string]VerifiableCredential{})
		assert.Error(t, err)
	})
	t.Run("already fulfilled", func(t *testing.T) {
		v := PEXState{
			RequiredPresentationDefinitions: map[pe.WalletOwnerType]pe.PresentationDefinition{
				pe.WalletOwnerOrganization: orgPresentationDefinition,
			},
			Credentials: map[string]vc.VerifiableCredential{},
			Submissions: map[string]PresentationSubmission{
				orgPresentationDefinition.Id: {},
			},
		}
		err := v.fulfill(orgPresentationDefinition.Id, PresentationSubmission{}, []VerifiablePresentation{}, map[string]VerifiableCredential{})
		assert.Error(t, err)
	})
}
