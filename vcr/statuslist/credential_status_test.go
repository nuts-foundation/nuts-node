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

package statuslist

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/nuts-foundation/nuts-node/vcr/assets"
	"github.com/nuts-foundation/nuts-node/vcr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// copy of vcr/validNutsOrganizationCredential to prevent circular deps.
func validNutsOrganizationCredential(t *testing.T) vc.VerifiableCredential {
	inputVC := vc.VerifiableCredential{}
	vcJSON, err := assets.TestAssets.ReadFile("test_assets/vc.json")
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(vcJSON, &inputVC)
	if err != nil {
		t.Fatal(err)
	}
	return inputVC
}

func TestCredentialStatus_verify(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)
		cred := validNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		assert.NoError(t, cs.Verify(cred))
	})
	t.Run("ok - multiple credentialStatus", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)
		cred := validNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry, entry}
		assert.NoError(t, cs.Verify(cred))
	})
	t.Run("ok - no credentialStatus", func(t *testing.T) {
		cs, _, _ := testSetup(t, false)
		cred := validNutsOrganizationCredential(t)
		cred.CredentialStatus = nil
		assert.NoError(t, cs.Verify(cred))
	})
	t.Run("ok - unknown credentialStatus.type is ignored", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)
		entry.Type = "SomethingElse"
		cred := validNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		assert.NoError(t, cs.Verify(cred))
	})
	t.Run("ok - revoked", func(t *testing.T) {
		cs, entry, _ := testSetup(t, true) // true
		cred := validNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		err := cs.Verify(cred)
		assert.ErrorIs(t, err, types.ErrRevoked)
	})
	t.Run("ok - credentialStatus.statusPurpose != 'revocation' is ignored", func(t *testing.T) {
		cs, entry, _ := testSetup(t, true) // true
		entry.StatusPurpose = "suspension"
		cred := validNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		assert.NoError(t, cs.Verify(cred))
	})
	t.Run("error - cannot get statusList", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)
		cs.client = http.DefaultClient
		cred := validNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		assert.ErrorContains(t, cs.Verify(cred), "tls: failed to verify certificate: x509: certificate signed by unknown authority")
	})
	t.Run("error - statusPurpose mismatch", func(t *testing.T) {
		// server that return StatusList2021Credential with statusPurpose == suspension
		statusList2021Credential := ValidStatusList2021Credential(t)
		statusList2021Credential.CredentialSubject[0].(*StatusList2021CredentialSubject).StatusPurpose = "suspension"
		credBytes, err := json.Marshal(statusList2021Credential)
		require.NoError(t, err)
		ts := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if _, err = writer.Write(credBytes); err != nil {
				t.Fatal(err)
			}
		}))
		defer ts.Close()

		// credentialStatus
		cs, entry, _ := testSetup(t, false)
		cs.client = ts.Client()

		// test credential
		entry.StatusListCredential = ts.URL
		cred := validNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}

		err = cs.Verify(cred)

		assert.EqualError(t, err, "StatusList2021Credential.credentialSubject.statusPuspose='suspension' does not match vc.credentialStatus.statusPurpose='revocation'")
	})
	t.Run("error - credentialStatus.statusListIndex out of bounds", func(t *testing.T) {
		cs, entry, _ := testSetup(t, false)
		entry.StatusListIndex = "500000" // max is ±130k
		cred := validNutsOrganizationCredential(t)
		cred.CredentialStatus = []any{entry}
		assert.EqualError(t, cs.Verify(cred), "index not in status list")

	})
}

func TestCredentialStatus_update(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cs, _, ts := testSetup(t, false)

		sl, err := cs.update(ts.URL)

		assert.NoError(t, err)
		require.NotNil(t, sl)
		assert.NotNil(t, sl.credential)
		assert.Equal(t, ts.URL, sl.statusListCredential)
		assert.Equal(t, "revocation", sl.statusPurpose)
		assert.NotEmpty(t, sl.expanded)
		assert.WithinRange(t, sl.lastUpdated, time.Now().Add(-time.Second), time.Now())
		// TODO: check that statusList is cached
	})
	t.Run("error - download", func(t *testing.T) {
		cs, _, _ := testSetup(t, false)

		sl, err := cs.update("%%")

		assert.EqualError(t, err, "parse \"%%\": invalid URL escape \"%%\"")
		assert.Nil(t, sl)
	})
	t.Run("error - verifyStatusList2021Credential", func(t *testing.T) {
		cs, _, ts := testSetup(t, false)
		cs.verifySignature = func(_ vc.VerifiableCredential, _ *time.Time) error { return errors.New("custom error") }

		sl, err := cs.update(ts.URL)

		assert.EqualError(t, err, "custom error")
		assert.Nil(t, sl)
	})
}

func TestCredentialStatus_download(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t) // has bit 1 set
		expected, err := json.Marshal(cred)
		require.NoError(t, err)
		ts := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if _, err = writer.Write(expected); err != nil {
				t.Fatal(err)
			}
		}))
		defer ts.Close()

		cs := CredentialStatus{client: ts.Client()}
		received, err := cs.download(ts.URL)

		assert.NoError(t, err)
		actual, err := json.Marshal(received)
		assert.NoError(t, err)
		assert.JSONEq(t, string(expected), string(actual))
	})
	t.Run("error - statusListCredential not a URL", func(t *testing.T) {
		cs := CredentialStatus{client: http.DefaultClient}
		received, err := cs.download("%%")
		assert.EqualError(t, err, "parse \"%%\": invalid URL escape \"%%\"")
		assert.Nil(t, received)
	})
	t.Run("error - response StatusCode => 300", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(400)
		}))
		defer ts.Close()

		cs := CredentialStatus{client: ts.Client()}
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

		cs := &CredentialStatus{client: ts.Client()}

		received, err := cs.download(ts.URL)
		assert.EqualError(t, err, "unexpected end of JSON input")
		assert.Nil(t, received)
	})
}

func TestCredentialStatus_verifyStatusList2021Credential(t *testing.T) {
	credentialStatusNoSignCheck := &CredentialStatus{
		client: nil,
		verifySignature: func(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error {
			return nil
		},
	}
	t.Run("ok", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		expected := cred.CredentialSubject[0].(*StatusList2021CredentialSubject)
		credSubj, err := credentialStatusNoSignCheck.verifyStatusList2021Credential(cred)
		assert.NoError(t, err)
		require.NotNil(t, credSubj)
		assert.Equal(t, *expected, *credSubj)
	})
	t.Run("error - incorrect credential type", func(t *testing.T) {
		cred := validNutsOrganizationCredential(t)
		credSubj, err := credentialStatusNoSignCheck.verifyStatusList2021Credential(cred)
		assert.EqualError(t, err, "incorrect credential types")
		assert.Nil(t, credSubj)
	})
	t.Run("error - too many credential types", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.Type = append(cred.Type, ssi.MustParseURI("OneTooMany"))
		credSubj, err := credentialStatusNoSignCheck.verifyStatusList2021Credential(cred)
		assert.EqualError(t, err, "incorrect credential types")
		assert.Nil(t, credSubj)
	})
	t.Run("error - credential validation failed", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(*StatusList2021CredentialSubject).Type = "wrong type"
		credSubj, err := credentialStatusNoSignCheck.verifyStatusList2021Credential(cred)
		assert.EqualError(t, err, "credentialSubject.type 'StatusList2021' is required")
		assert.Nil(t, credSubj)
	})
	t.Run("error - contains CredentialStatus", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialStatus = []any{}
		credSubj, err := credentialStatusNoSignCheck.verifyStatusList2021Credential(cred)
		assert.EqualError(t, err, "StatusList2021Credential with a CredentialStatus is not supported")
		assert.Nil(t, credSubj)
	})
	t.Run("error - invalid credentialSubject.encodedList", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cred.CredentialSubject[0].(*StatusList2021CredentialSubject).EncodedList = "@"
		credSubj, err := credentialStatusNoSignCheck.verifyStatusList2021Credential(cred)

		assert.EqualError(t, err, "credentialSubject.encodedList is invalid: illegal base64 data at input byte 0")
		assert.Nil(t, credSubj)
	})
	t.Run("error -invalid signature", func(t *testing.T) {
		cred := ValidStatusList2021Credential(t)
		cs := CredentialStatus{verifySignature: func(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error {
			return errors.New("invalid signature")
		}}
		credSubj, err := cs.verifyStatusList2021Credential(cred)
		assert.EqualError(t, err, "invalid signature")
		assert.Nil(t, credSubj)
	})
}

// testSetup returns
//   - credentialStatus that does NOT Verify signatures, and a client configured for the test server
//   - a StatusList2021Entry pointing to the test server, optionally provide a statusListIndex matching statusList2021Credential.encodedList to simulate revocation
//   - the test server
func testSetup(t testing.TB, entryIsRevoked bool) (*CredentialStatus, StatusList2021Entry, *httptest.Server) {
	// make test server
	statusList2021Credential := ValidStatusList2021Credential(t) // has bit 1 set
	credBytes, err := json.Marshal(statusList2021Credential)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, err = writer.Write(credBytes); err != nil {
			t.Fatal(err)
		}
	}))
	t.Cleanup(func() { ts.Close() })

	// make credentialStatus
	credentialStatusNoSignCheck := &CredentialStatus{
		client: ts.Client(),
		verifySignature: func(credentialToVerify vc.VerifiableCredential, validateAt *time.Time) error {
			return nil
		},
	}

	// make StatusList2021Entry
	slEntry := StatusList2021Entry{
		Type:                 StatusList2021EntryType,
		StatusPurpose:        "revocation",
		StatusListIndex:      "76248",
		StatusListCredential: ts.URL,
	}
	if entryIsRevoked {
		slEntry.StatusListIndex = "1" // matches revoked value set in statusList2021Credential
	}

	return credentialStatusNoSignCheck, slEntry, ts
}
