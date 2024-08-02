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
	"github.com/nuts-foundation/nuts-node/crypto/util"
)

// Two TestDIDs which can be used during testing:

// TestDIDA is a testDID
var TestDIDA = did.MustParseDID("did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW")

// TestDIDB is a testDID
var TestDIDB = did.MustParseDID("did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY")

// TestMethodDIDA is a test method DID for the TestDIDA
var TestMethodDIDA = did.MustParseDIDURL(TestDIDA.String() + "#abc-method-1")

// TestMethodDIDAPrivateKey returns the key for TestMethodDIDA
func TestMethodDIDAPrivateKey() crypto.TestKey {
	key, _ := util.PemToPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmvipTdytRXwTTY/6
wJl5Cwj0YQ4+QdJK+fEC8DzL9/OhRANCAATxa8o5Htmk5J83FPbRCKDwO5VjtADD
HpB7g016NM3emlGGaFytd23nTAx77KxrJMYoQ7liF4BgXUH0748kJQgx
-----END PRIVATE KEY-----`))
	return crypto.TestKey{PrivateKey: key, KID: TestMethodDIDA.String(), PublicKey: key.Public()}
}

// TestMethodDIDB is a test method DID for the TestDIDB
var TestMethodDIDB, _ = did.ParseDIDURL(TestDIDB.String() + "#abc-method-2")

// TestMethodDIDBPrivateKey returns the key for TestMethodDIDB
func TestMethodDIDBPrivateKey() crypto.TestKey {
	key, _ := util.PemToPrivateKey([]byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg3dY0NAGN7koRq+BH
XxhMnrGAyJ4c6DWkQyjAfhgzMJChRANCAARyqdBob46wU2n+qqQHwnxRa/KprcVr
rYrfaOuqO34hTemBL1DkecuWBTPYT5HKiuKPn7LnDRupFXuCLF4tp+BR
-----END PRIVATE KEY-----`))
	return crypto.TestKey{PrivateKey: key, KID: TestMethodDIDB.String(), PublicKey: key.Public()}
}
