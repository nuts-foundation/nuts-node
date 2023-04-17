/*
 * Nuts node
 * Copyright (C) 2023 Nuts community
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
 */

package selfsigned

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	vcr2 "github.com/nuts-foundation/nuts-node/vcr"
	"github.com/nuts-foundation/nuts-node/vdr/didstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var vpValidTime, _ = time.Parse(time.RFC3339, "2023-04-14T14:00:00.000000+02:00")
var docTXTime, _ = time.Parse(time.RFC3339, "2023-04-14T12:00:00.000000+02:00")

func TestSessionStore_VerifyVP(t *testing.T) {

	vp := vc.VerifiablePresentation{}
	vpData, _ := os.ReadFile("./test/vp.json")
	_ = json.Unmarshal(vpData, &vp)
	testCredential := vc.VerifiableCredential{}
	vcData, _ := os.ReadFile("./test/vc.json")
	_ = json.Unmarshal(vcData, &testCredential)

	t.Run("always returns invalid VerificationResult", func(t *testing.T) {
		ss := NewService(nil)

		result, err := ss.VerifyVP(vc.VerifiablePresentation{}, nil)

		require.NoError(t, err)
		assert.Equal(t, contract.Invalid, result.Validity())
	})

	t.Run("ok using mocks", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewSessionStore(mockContext.vcr).(sessionStore)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, nil).Return([]vc.VerifiableCredential{testCredential}, nil)

		result, err := ss.VerifyVP(vp, nil)

		require.NoError(t, err)
		assert.Empty(t, result.Reason())
		assert.Equal(t, contract.Valid, result.Validity())
	})

	t.Run("error on verify", func(t *testing.T) {
		mockContext := newMockContext(t)
		ss := NewSessionStore(mockContext.vcr).(sessionStore)
		mockContext.verifier.EXPECT().VerifyVP(vp, true, nil).Return(nil, errors.New("error"))

		_, err := ss.VerifyVP(vp, nil)

		assert.Error(t, err)
	})

	t.Run("ok using in-memory DBs", func(t *testing.T) {
		vcrContext := vcr2.NewTestVCRContext(t)
		ss := NewSessionStore(vcrContext.VCR)
		didDocument := did.Document{}
		ddBytes, _ := os.ReadFile("./test/diddocument.json")
		_ = json.Unmarshal(ddBytes, &didDocument)
		// test transaction for DIDStore ordering
		tx := didstore.TestTransaction(didDocument)
		tx.SigningTime = docTXTime
		err := vcrContext.DIDStore.Add(didDocument, tx)
		require.NoError(t, err)
		// Trust issuer, only needed for test
		vcrContext.VCR.Trust(ssi.MustParseURI(credentialType), didDocument.ID.URI())

		result, err := ss.VerifyVP(vp, &vpValidTime)

		require.NoError(t, err)
		assert.Empty(t, result.Reason())
		assert.Equal(t, contract.Valid, result.Validity())
	})
}
