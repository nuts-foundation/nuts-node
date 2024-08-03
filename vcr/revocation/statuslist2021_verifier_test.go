/*
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
 *
 */

package revocation

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/test"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatusList2021_Verify(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)
		cred := test.ValidNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		assert.NoError(t, cs.Verify(cred))
	})
	t.Run("ok - multiple credentialStatus", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)
		cred := test.ValidNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry, entry}
		assert.NoError(t, cs.Verify(cred))
	})
	t.Run("ok - no credentialStatus", func(t *testing.T) {
		cs, _, _ := testSetup(t, false)
		cred := test.ValidNutsOrganizationCredential(t)
		cred.CredentialStatus = nil
		assert.NoError(t, cs.Verify(cred))
	})
	t.Run("ok - unknown credentialStatus.type is ignored", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)
		entry.Type = "SomethingElse"
		cred := test.ValidNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		assert.NoError(t, cs.Verify(cred))
	})
	t.Run("ok - revoked", func(t *testing.T) {
		cs, entry, _ := testSetup(t, true) // true
		cred := test.ValidNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		err := cs.Verify(cred)
		assert.ErrorIs(t, err, types.ErrRevoked)
	})
	t.Run("ok - credentialStatus.statusPurpose != 'revocation' is ignored", func(t *testing.T) {
		cs, entry, _ := testSetup(t, true) // true
		entry.StatusPurpose = "suspension"
		cred := test.ValidNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		assert.NoError(t, cs.Verify(cred))
	})
	t.Run("error - cannot get statusList", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)
		cs.client = http.DefaultClient
		cred := test.ValidNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		assert.ErrorContains(t, cs.Verify(cred), "tls: failed to verify certificate: x509: certificate signed by unknown authority")
	})
	t.Run("error - statusPurpose mismatch", func(t *testing.T) {
		// credentialStatus
		cs, entry, ts := testSetup(t, false)

		// server that return StatusList2021Credential with statusPurpose == suspension
		statusList2021Credential := test.ValidStatusList2021Credential(t)
		statusList2021Credential.CredentialSubject[0].(map[string]any)["statusPurpose"] = "suspension"
		statusList2021Credential.CredentialSubject[0].(map[string]any)["id"] = ts.URL
		credBytes, err := json.Marshal(statusList2021Credential)
		require.NoError(t, err)
		ts.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if _, err = writer.Write(credBytes); err != nil {
				t.Fatal(err)
			}
		})

		// test credential
		entry.StatusListCredential = ts.URL
		cred := test.ValidNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}

		err = cs.Verify(cred)

		assert.EqualError(t, err, "StatusList2021Credential.credentialSubject.statusPuspose='suspension' does not match vc.credentialStatus.statusPurpose='revocation'")
	})
	t.Run("error - credentialStatus.statusListIndex out of bounds", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)
		entry.StatusListIndex = "500000" // max is ±130k
		cred := test.ValidNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		assert.EqualError(t, cs.Verify(cred), "index not in status list")

	})
}

func TestStatusList2021_statusList(t *testing.T) {
	makeRecords := func(subjectID string) (credentialRecord, credentialIssuerRecord) {
		cir := credentialIssuerRecord{
			SubjectID: subjectID,
			Issuer:    aliceDID.String(),
			Page:      1,
			Revocations: []revocationRecord{{
				StatusListCredential: subjectID,
				StatusListIndex:      1,
			}},
		}
		_, cr, err := (&StatusList2021{Sign: noopSign}).updateCredential(nil, &cir, "")
		require.NoError(t, err)
		return *cr, cir
	}
	t.Run("ok - known credential", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)
		cs.client = nil // panics if attempts to update
		expectedCR, _ := makeRecords(entry.StatusListCredential)
		require.NoError(t, cs.db.Create(&expectedCR).Error)

		require.NotPanics(t, func() {
			actualCR, err := cs.statusList(entry.StatusListCredential)
			require.NoError(t, err)
			assert.Equal(t, expectedCR, *actualCR)
		})
	})
	t.Run("ok - new credential", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)

		actualCR, err := cs.statusList(entry.StatusListCredential)
		require.NoError(t, err)
		assert.NotEmpty(t, actualCR)
	})
	t.Run("ok - managed and expired", func(t *testing.T) {
		cs, _, _ := testSetup(t, false)
		cs.client = nil // panics if attempts to update
		cr, cir := makeRecords("a")
		require.NoError(t, cs.db.Create(&cr).Error)
		require.NoError(t, cs.db.Create(&cir).Error)

		assert.NotPanics(t, func() {
			actualCR, err := cs.statusList(cir.SubjectID)

			require.NoError(t, err)
			assert.Equal(t, cr, *actualCR)
		})
	})
	t.Run("ok - expired", func(t *testing.T) {
		cs, _, ts := testSetup(t, false)
		cr, cir := makeRecords(ts.URL)
		expires := time.Now().Add(-time.Second).Unix()
		cr.Expires = &expires
		require.NoError(t, cs.db.Create(&cr).Error)

		actualCR, err := cs.statusList(cir.SubjectID)

		assert.NoError(t, err)
		require.NotEmpty(t, actualCR)
		assert.NotEqual(t, cr, *actualCR)
	})
	t.Run("ok - exceeded max age", func(t *testing.T) {
		cs, _, ts := testSetup(t, false)
		cr, cir := makeRecords(ts.URL)
		cr.CreatedAt = time.Now().Add(-2 * maxAgeExternal).Unix()
		require.NoError(t, cs.db.Create(&cr).Error)

		actualCR, err := cs.statusList(cir.SubjectID)

		assert.NoError(t, err)
		require.NotEmpty(t, actualCR)
		assert.NotEqual(t, cr, *actualCR)
	})
	t.Run("ok - use expired", func(t *testing.T) {
		cs, _, ts := testSetup(t, false)
		ts.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if _, err := writer.Write([]byte{'{'}); err != nil {
				t.Fatal(err)
			}
		})
		cr, cir := makeRecords(ts.URL)
		expires := time.Now().Add(-time.Second).Unix()
		cr.Expires = &expires
		require.NoError(t, cs.db.Create(&cr).Error)

		actualCR, err := cs.statusList(cir.SubjectID)

		require.NoError(t, err)
		assert.Equal(t, cr, *actualCR)
	})
	t.Run("error - unknown and failed to download", func(t *testing.T) {
		cs, entry, ts := testSetup(t, false)
		ts.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if _, err := writer.Write([]byte{'{'}); err != nil {
				t.Fatal(err)
			}
		})

		actualCR, err := cs.statusList(entry.StatusListCredential)

		assert.EqualError(t, err, "unexpected end of JSON input")
		assert.Nil(t, actualCR)
	})

}

func TestStatusList2021_update(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cs, entry, ts := testSetup(t, false)

		sl, err := cs.update(ts.URL)

		assert.NoError(t, err)
		require.NotNil(t, sl)
		assert.NotNil(t, sl.Raw)
		assert.Equal(t, ts.URL, sl.SubjectID)
		assert.Equal(t, "revocation", sl.StatusPurpose)
		assert.NotEmpty(t, sl.Expanded)
		assert.InDelta(t, sl.CreatedAt, time.Now().Unix(), 2) // allow 2 sec difference on slow CI
		assert.NotNil(t, sl.Expires)
		slDB, err := cs.loadCredential(entry.StatusListCredential)
		require.NoError(t, err)
		assert.Equal(t, *sl, *slDB)
	})
	t.Run("ok - ExpirationDate", func(t *testing.T) {
		cs, _, ts := testSetup(t, false)
		// change handler
		statusList2021Credential := test.ValidStatusList2021Credential(t)
		expectedExpires := time.Now().Truncate(time.Second)
		statusList2021Credential.ExpirationDate = &expectedExpires
		statusList2021Credential.CredentialSubject[0].(map[string]any)["id"] = ts.URL
		credBytes, err := json.Marshal(statusList2021Credential)
		require.NoError(t, err)
		ts.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if _, err = writer.Write(credBytes); err != nil {
				t.Fatal(err)
			}
		})

		sl, err := cs.update(ts.URL)

		require.NoError(t, err)
		assert.Equal(t, expectedExpires.Unix(), *sl.Expires)
	})
	t.Run("error - download", func(t *testing.T) {
		cs, _, _ := testSetup(t, false)

		sl, err := cs.update("%%")

		assert.EqualError(t, err, "parse \"%%\": invalid URL escape \"%%\"")
		assert.Nil(t, sl)
	})
	t.Run("error - verify", func(t *testing.T) {
		cs, _, ts := testSetup(t, false)
		cs.VerifySignature = func(_ vc.VerifiableCredential, _ *time.Time) error { return errors.New("custom error") }

		sl, err := cs.update(ts.URL)

		assert.EqualError(t, err, "custom error")
		assert.Nil(t, sl)
	})
	t.Run("error - wrong StatusList2021Credential", func(t *testing.T) {
		cs, _, ts := testSetup(t, false)
		// change handler
		credBytes, err := json.Marshal(test.ValidStatusList2021Credential(t))
		require.NoError(t, err)
		ts.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if _, err = writer.Write(credBytes); err != nil {
				t.Fatal(err)
			}
		})

		sl, err := cs.update(ts.URL)

		assert.ErrorContains(t, err, "status list: wrong credential: expected")
		assert.Nil(t, sl)
	})
}

func TestStatusList2021_download(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t) // has bit 1 set
		expected, err := json.Marshal(cred)
		require.NoError(t, err)
		ts := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if _, err = writer.Write(expected); err != nil {
				t.Fatal(err)
			}
		}))
		defer ts.Close()

		cs := StatusList2021{client: ts.Client()}
		received, err := cs.download(ts.URL)

		assert.NoError(t, err)
		actual, err := json.Marshal(received)
		assert.NoError(t, err)
		assert.JSONEq(t, string(expected), string(actual))
	})
	t.Run("error - StatusListCredential not a URL", func(t *testing.T) {
		cs := StatusList2021{client: http.DefaultClient}
		received, err := cs.download("%%")
		assert.EqualError(t, err, "parse \"%%\": invalid URL escape \"%%\"")
		assert.Nil(t, received)
	})
	t.Run("error - response StatusCode => 300", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(400)
		}))
		defer ts.Close()

		cs := StatusList2021{client: ts.Client()}
		received, err := cs.download(ts.URL)

		assert.ErrorContains(t, err, "fetching StatusList2021Credential from")
		assert.Nil(t, received)
	})
	t.Run("error - body is not a VC", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if _, err := writer.Write([]byte("{")); err != nil {
				t.Fatal(err)
			}
		}))
		defer ts.Close()

		cs := &StatusList2021{client: ts.Client()}

		received, err := cs.download(ts.URL)
		assert.EqualError(t, err, "unexpected end of JSON input")
		assert.Nil(t, received)
	})
}

func TestStatusList2021_verify(t *testing.T) {
	credentialStatusNoSignCheck := &StatusList2021{
		client: nil,
		VerifySignature: func(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error {
			return nil
		},
	}
	t.Run("ok", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		expectedBs, err := json.Marshal(cred.CredentialSubject[0])
		require.NoError(t, err)
		credSubj, err := credentialStatusNoSignCheck.verify(cred)
		assert.NoError(t, err)
		require.NotNil(t, credSubj)
		credSubjBs, err := json.Marshal(credSubj)
		assert.NoError(t, err)
		assert.JSONEq(t, string(expectedBs), string(credSubjBs))
	})
	t.Run("error - credential validation failed", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(map[string]any)["type"] = "wrong type"
		credSubj, err := credentialStatusNoSignCheck.verify(cred)
		assert.EqualError(t, err, "credentialSubject.type 'StatusList2021' is required")
		assert.Nil(t, credSubj)
	})
	t.Run("error - invalid credentialSubject.encodedList", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(map[string]any)["encodedList"] = "@"
		credSubj, err := credentialStatusNoSignCheck.verify(cred)

		assert.EqualError(t, err, "credentialSubject.encodedList is invalid: illegal base64 data at input byte 0")
		assert.Nil(t, credSubj)
	})
	t.Run("error -invalid signature", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cs := StatusList2021{VerifySignature: func(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error {
			return errors.New("invalid signature")
		}}
		credSubj, err := cs.verify(cred)
		assert.EqualError(t, err, "invalid signature")
		assert.Nil(t, credSubj)
	})
}

func TestStatusList2021_validate(t *testing.T) {
	cs := StatusList2021{
		VerifySignature: func(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error { return nil },
	}

	// Credential checks
	t.Run("ok", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		_, err := cs.validate(cred)
		assert.NoError(t, err)
	})
	t.Run("error - missing credential/v1 context", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.Context = []ssi.URI{statusList2021CredentialTypeURI}
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "default context is required")
	})
	t.Run("error - missing status list context", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.Context = []ssi.URI{vc.VCContextV1URI()}
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "context 'https://w3id.org/vc/status-list/2021/v1' is required")
	})
	t.Run("error - missing VerifiableCredential type", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.Type = []ssi.URI{statusList2021CredentialTypeURI}
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "type 'VerifiableCredential' is required")
	})
	t.Run("error - missing StatusList2021Credential type", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.Type = []ssi.URI{vc.VerifiableCredentialTypeV1URI()}
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "type 'StatusList2021Credential' is required")
	})
	t.Run("error - too many credential types", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.Type = append(cred.Type, ssi.MustParseURI("OneTooMany"))
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "StatusList2021Credential contains other types")
	})
	t.Run("error - missing ID", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.ID = nil
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "'ID' is required")
	})
	t.Run("issuance date", func(t *testing.T) {
		t.Run("ok - issuance date", func(t *testing.T) {
			cred := test.ValidStatusList2021Credential(t)
			_, err := cs.validate(cred)
			assert.NoError(t, err)
		})
		t.Run("error - missing", func(t *testing.T) {
			cred := test.ValidStatusList2021Credential(t)
			cred.IssuanceDate = time.Time{}
			_, err := cs.validate(cred)
			assert.EqualError(t, err, "issuanceDate is required")
		})
	})
	t.Run("error - jsonld without proof", func(t *testing.T) {
		// Marshal and Unmarshal so the vc.format field is set.
		credJSON, _ := json.Marshal(test.ValidStatusList2021Credential(t))
		var cred vc.VerifiableCredential
		_ = json.Unmarshal(credJSON, &cred)
		cred.Proof = nil
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "'proof' is required for JSON-LD credentials")
	})
	t.Run("error - contains CredentialStatus", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.CredentialStatus = []any{}
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "StatusList2021Credential with a CredentialStatus is not supported")
	})

	// CredentialSubject checks
	t.Run("error - invalid credential subject", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.CredentialSubject = []any{"{"}
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "json: cannot unmarshal string into Go value of type revocation.StatusList2021CredentialSubject")
	})
	t.Run("error - wrong credential subject", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.CredentialSubject = []any{struct{}{}}
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "credentialSubject.type 'StatusList2021' is required")
	})
	t.Run("error - multiple credentialSubject", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.CredentialSubject = []any{StatusList2021CredentialSubject{}, StatusList2021CredentialSubject{}}
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "single credentialSubject expected")
	})
	t.Run("error - missing credentialSubject.type", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(map[string]any)["type"] = ""
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "credentialSubject.type 'StatusList2021' is required")
	})
	t.Run("error - missing statusPurpose", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(map[string]any)["statusPurpose"] = ""
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "credentialSubject.statusPurpose is required")
	})
	t.Run("error - missing encodedList", func(t *testing.T) {
		cred := test.ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(map[string]any)["encodedList"] = ""
		_, err := cs.validate(cred)
		assert.EqualError(t, err, "credentialSubject.encodedList is required")
	})
}

// testSetup returns
//   - credentialStatus that does NOT Verify signatures, and a client configured for the test server
//   - a StatusList2021Entry pointing to the test server, optionally provide a statusListIndex matching statusList2021Credential.encodedList to simulate revocation
//   - the test server
func testSetup(t testing.TB, entryIsRevoked bool) (*StatusList2021, StatusList2021Entry, *httptest.Server) {
	// make test server
	ts := httptest.NewTLSServer(nil)
	t.Cleanup(func() { ts.Close() })

	// credential
	statusList2021Credential := test.ValidStatusList2021Credential(t)             // has bit 1 set
	statusList2021Credential.CredentialSubject[0].(map[string]any)["id"] = ts.URL // point to the test server
	credBytes, err := json.Marshal(statusList2021Credential)
	require.NoError(t, err)

	// set test server handler
	ts.Config.Handler = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, err = writer.Write(credBytes); err != nil {
			t.Fatal(err)
		}
	})

	// make credentialStatus
	credentialStatusNoSignCheck := newTestStatusList2021(t, aliceDID, bobDID)
	credentialStatusNoSignCheck.client = ts.Client()

	// make StatusList2021Entry
	slEntry := StatusList2021Entry{
		Type:                 StatusList2021EntryType,
		StatusPurpose:        StatusPurposeRevocation,
		StatusListIndex:      "76248",
		StatusListCredential: ts.URL,
	}
	if entryIsRevoked {
		slEntry.StatusListIndex = "1" // matches revoked value set in statusList2021Credential
	}

	return credentialStatusNoSignCheck, slEntry, ts
}
