/*
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

package storage

import (
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
	"testing"
	"time"
)

func TestMarshallingDuration_UnmarshalText(t *testing.T) {
	type Container struct {
		Value MarshallingDuration
	}

	expected := Container{Value: MarshallingDuration(time.Hour * 3)}

	t.Run("roundtrip", func(t *testing.T) {
		// Marshal
		data, _ := yaml.Marshal(expected)
		assert.Equal(t, string(data), "value: 3h0m0s\n")

		// Unmarshal
		var actual Container
		err := yaml.Unmarshal(data, &actual)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("minimal", func(t *testing.T) {
		var actual Container
		err := yaml.Unmarshal([]byte("value: 3h"), &actual)
		assert.NoError(t, err)
		assert.Equal(t, expected, actual)
	})
	t.Run("empty", func(t *testing.T) {
		var actual Container
		err := yaml.Unmarshal([]byte("value: "), &actual)
		assert.NoError(t, err)
		assert.Equal(t, time.Duration(0), time.Duration(actual.Value))
	})
}
