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

package doc

import (
	"crypto"
	nutsCrypto "github.com/nuts-foundation/nuts-node/crypto"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
)

type StaticKeyResolver struct {
	Key crypto.PublicKey
}

func (s StaticKeyResolver) ResolvePublicKey(_ string, _ *time.Time) (crypto.PublicKey, error) {
	return s.Key, nil
}

func (s StaticKeyResolver) ResolveSigningKeyID(_ did.DID, _ *time.Time) (string, error) {
	panic("implement me")
}

func (s StaticKeyResolver) ResolveSigningKey(_ string, _ *time.Time) (crypto.PublicKey, error) {
	panic("implement me")
}

func (s StaticKeyResolver) ResolveAssertionKeyID(_ did.DID) (ssi.URI, error) {
	panic("implement me")
}

const kid = "did:nuts:3gU9z3j7j4VCboc3qq3Vc5mVVGDNGjfg32xokeX8c8Zn#J9O6wvqtYOVwjc8JtZ4aodRdbPv_IKAjLkEq9uHlDdE"

// mockKeyCreator can create new keys based on a predefined key
type mockKeyCreator struct {
	kid string
}

func newMockKeyCreator() *mockKeyCreator {
	return &mockKeyCreator{kid: kid}
}

// New uses a predefined ECDSA key and calls the namingFunc to get the kid
func (m *mockKeyCreator) New(namingFunc nutsCrypto.KIDNamingFunc) (nutsCrypto.Key, error) {
	return nutsCrypto.NewTestKey(m.kid), nil
}