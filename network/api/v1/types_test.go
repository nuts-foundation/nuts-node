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
	"github.com/nuts-foundation/nuts-node/json"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestPeerDiagnostics_MarshalJSON(t *testing.T) {
	t.Run("assert uptime is marshaled in seconds", func(t *testing.T) {
		expected := PeerDiagnostics{Uptime: 1 * time.Hour}

		data, _ := json.Marshal(expected)

		actualAsMap := make(map[string]interface{}, 0)
		json.Unmarshal(data, &actualAsMap)
		assert.Equal(t, 3600, int(actualAsMap["uptime"].(float64)))

		actual := PeerDiagnostics{}
		err := json.Unmarshal(data, &actual)
		assert.NoError(t, err)
		assert.Equal(t, expected.Uptime, actual.Uptime)
	})
}
