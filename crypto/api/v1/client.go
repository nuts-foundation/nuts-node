/*
 * Nuts node
 * Copyright (C) 2021. Nuts community
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
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

// HTTPClient holds the server address and other basic settings for the http client
type HTTPClient struct {
	ServerAddress string
	Timeout       time.Duration
}

func (hb HTTPClient) clientWithRequestEditor(fn RequestEditorFn) ClientInterface {
	url := hb.ServerAddress
	if !strings.Contains(url, "http") {
		url = fmt.Sprintf("http://%v", hb.ServerAddress)
	}

	response, err := NewClientWithResponses(url, WithRequestEditorFn(fn))
	if err != nil {
		panic(err)
	}
	return response
}

func (hb HTTPClient) client() ClientInterface {
	return hb.clientWithRequestEditor(nil)
}

// GetPublicKey returns a PublicKey from the server given a kid
func (hb HTTPClient) GetPublicKey(kid string, validAt *string) (jwk.Key, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hb.Timeout)
	defer cancel()

	httpClient := hb.clientWithRequestEditor(func(ctx context.Context, req *http.Request) error {
		req.Header.Add(echo.HeaderAccept, "application/json")
		return nil
	})

	params := &PublicKeyParams{
		At: validAt,
	}

	response, err := httpClient.PublicKey(ctx, kid, params)

	if err != nil {
		return nil, err
	}
	if err := testResponseCode(http.StatusOK, response); err != nil {
		return nil, err
	}
	jwkSet, err := jwk.ParseReader(response.Body)
	if err != nil {
		return nil, err
	}
	key, _ := jwkSet.Get(0)
	return key, nil
}

func testResponseCode(expectedStatusCode int, response *http.Response) error {
	if response.StatusCode != expectedStatusCode {
		responseData, _ := ioutil.ReadAll(response.Body)
		return fmt.Errorf("server returned HTTP %d (expected: %d), response: %s",
			response.StatusCode, expectedStatusCode, string(responseData))
	}
	return nil
}
