/*
 * Nuts node
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

package echo

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/nuts-foundation/nuts-node/test/node"
	logTest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"

	"github.com/stretchr/testify/assert"
)

// TestStatusCodes tests if the returned errors from the API implementations are correctly translated to status codes
func TestStatusCodes(t *testing.T) {
	hook := logTest.NewGlobal()
	baseUrl, _ := node.StartServer(t)

	type operation struct {
		module    string
		operation string
		url       string
		body      interface{}
	}
	t.Run("404s", func(t *testing.T) {
		testCases := []operation{
			{module: "Auth", operation: "GetSignSessionStatus", url: "/internal/auth/v1/signature/session/1"},
			{module: "Auth", operation: "GetContractByType", url: "/public/auth/v1/contract/1"},
			{module: "Didman", operation: "GetCompoundServices", url: "/internal/didman/v1/did/did:nuts:1/compoundservice"},
			{module: "Didman", operation: "GetCompoundServiceEndpoint", url: "/internal/didman/v1/did/did:nuts:1/compoundservice/1/endpoint/2"},
			{module: "Network", operation: "GetTransaction", url: "/internal/network/v1/transaction/0000000000000000000000000000000000000000000000000000000000000000"},
			{module: "Network", operation: "GetTransactionPayload", url: "/internal/network/v1/transaction/0000000000000000000000000000000000000000000000000000000000000000/payload"},
			{module: "VCR", operation: "ResolveVC", url: "/internal/vcr/v2/vc/1"},
			{module: "VDR", operation: "GetDID", url: "/internal/vdr/v1/did/did:nuts:1"},
		}

		for _, testCase := range testCases {
			resp, err := http.Get(fmt.Sprintf("%s%s", baseUrl, testCase.url))

			require.NoError(t, err)
			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			assert.Equal(t, testCase.module, hook.LastEntry().Data["module"].(string))
			assert.Equal(t, testCase.operation, hook.LastEntry().Data["operation"].(string))
		}
	})
	t.Run("400s", func(t *testing.T) {
		testCases := []operation{
			{module: "Crypto", operation: "SignJwt", url: "/internal/crypto/v1/sign_jwt", body: map[string]interface{}{"kid": "fpp", "claims": map[string]interface{}{"foo": "bar"}}},
			{module: "Network", operation: "GetTransaction", url: "/internal/network/v1/transaction/invalidhash"},
			{module: "Network", operation: "GetTransactionPayload", url: "/internal/network/v1/transaction/invalidhash/payload"},
		}

		for _, testCase := range testCases {
			var resp *http.Response
			var err error
			if testCase.body != nil {
				body, _ := json.Marshal(testCase.body)
				resp, err = http.Post(fmt.Sprintf("%s%s", baseUrl, testCase.url), "application/json", bytes.NewReader(body))
			} else {
				resp, err = http.Get(fmt.Sprintf("%s%s", baseUrl, testCase.url))
			}

			require.NoError(t, err)
			assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
			assert.Equal(t, testCase.module, hook.LastEntry().Data["module"].(string))
			assert.Equal(t, testCase.operation, hook.LastEntry().Data["operation"].(string))
		}
	})
}
