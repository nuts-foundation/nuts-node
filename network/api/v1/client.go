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

package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/nuts-foundation/nuts-node/network/p2p"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/crypto/hash"
	"github.com/nuts-foundation/nuts-node/network/dag"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	ServerAddress string
	Timeout       time.Duration
}

// GetTransactionPayload retrieves the transaction payload for the given transaction. If the transaction or payload is not found
// nil is returned.
func (hb HTTPClient) GetTransactionPayload(transactionRef hash.SHA256Hash) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()
	res, err := hb.client().GetTransactionPayload(ctx, transactionRef.String())
	if err != nil {
		return nil, err
	}
	if res.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err := core.TestResponseCode(http.StatusOK, res); err != nil {
		return nil, err
	}
	return io.ReadAll(res.Body)
}

// GetTransaction retrieves the transaction for the given reference. If the transaction is not known, an error is returned.
func (hb HTTPClient) GetTransaction(transactionRef hash.SHA256Hash) (dag.Transaction, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()
	res, err := hb.client().GetTransaction(ctx, transactionRef.String())
	if err != nil {
		return nil, err
	}
	return testAndParseTransactionResponse(res)
}

// ListTransactions returns all transactions known to this network instance.
func (hb HTTPClient) ListTransactions() ([]dag.Transaction, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()
	res, err := hb.client().ListTransactions(ctx)
	if err != nil {
		return nil, err
	}
	if err := core.TestResponseCode(http.StatusOK, res); err != nil {
		return nil, err
	}
	responseData, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	unparsedTransactions := make([]string, 0)
	if err = json.Unmarshal(responseData, &unparsedTransactions); err != nil {
		return nil, err
	}
	transactions := make([]dag.Transaction, 0)
	for _, unparsedTransaction := range unparsedTransactions {
		transaction, err := dag.ParseTransaction([]byte(unparsedTransaction))
		if err != nil {
			return nil, err
		}
		transactions = append(transactions, transaction)
	}

	return transactions, nil
}

// GetPeerDiagnostics retrieves diagnostic information on the node's peers.
func (hb HTTPClient) GetPeerDiagnostics() (map[p2p.PeerID]PeerDiagnostics, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()
	response, err := hb.client().GetPeerDiagnostics(ctx)
	if err != nil {
		return nil, err
	}
	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	result := make(map[p2p.PeerID]PeerDiagnostics, 0)
	err = json.Unmarshal(responseData, &result)
	return result, err
}

func (hb HTTPClient) client() ClientInterface {
	url := hb.ServerAddress
	if !strings.Contains(url, "http") {
		url = fmt.Sprintf("http://%v", hb.ServerAddress)
	}

	response, err := NewClientWithResponses(url)
	if err != nil {
		panic(err)
	}
	return response
}

func testAndParseTransactionResponse(response *http.Response) (dag.Transaction, error) {
	if response.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if err := core.TestResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	responseData, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return dag.ParseTransaction(responseData)
}
