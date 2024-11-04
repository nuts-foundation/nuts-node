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

package didx509

import (
	"context"
	"errors"
	"github.com/lestrrat-go/jwx/v2/jws"
)

// ErrorInvalidNumberOfSignatures indicates that the number of signatures present in the JWT is invalid.
var (
	ErrorInvalidNumberOfSignatures = errors.New("invalid number of signatures")
)

// ExtractProtectedHeaders extracts the protected headers from a JWT string.
// The function takes a JWT string as input and returns a map of the protected headers.
// Note that:
//   - This method ignores any parsing errors and returns an empty map instead of an error.
func ExtractProtectedHeaders(jwt string) (map[string]interface{}, error) {
	headers := make(map[string]interface{})
	if jwt != "" {
		message, _ := jws.ParseString(jwt)
		if message != nil {
			if len(message.Signatures()) != 1 {
				return nil, ErrorInvalidNumberOfSignatures
			}
			var err error
			headers, err = message.Signatures()[0].ProtectedHeaders().AsMap(context.Background())
			if err != nil {
				return nil, err
			}
		}
	}
	return headers, nil
}
