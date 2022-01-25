/*
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

package vdr

import (
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	"github.com/nuts-foundation/nuts-node/vdr/store"
)

// Two TestDIDs which can be used during testing:
// TestDIDA is a testDID
var TestDIDA, _ = did.ParseDID("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")

// TestDIDB is a testDID
var TestDIDB, _ = did.ParseDID("did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY")

// TestMethodDIDA is a test method DID for the TestDIDA
var TestMethodDIDA, _ = did.ParseDIDURL(TestDIDA.String() + "#abc-method-1")

// TestMethodDIDB is a test method DID for the TestDIDB
var TestMethodDIDB, _ = did.ParseDIDURL(TestDIDB.String() + "#abc-method-2")

func NewTestVDRInstance(testDirectory string) *VDR {
	config := TestVDRConfig()
	didStore := store.NewMemoryStore()
	return NewVDR(config, crypto.NewTestCryptoInstance(), network.NewTestNetworkInstance(testDirectory), didStore)
}

func TestVDRConfig() Config {
	config := DefaultConfig()
	return config
}
