/*
 * Nuts node
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

package concept

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEq(t *testing.T) {
	q := eq{
		key:   "key",
		value: "value",
	}

	t.Run("ok - key", func(t *testing.T) {
		assert.Equal(t, "key", q.Key())
	})

	t.Run("ok - match", func(t *testing.T) {
		assert.Equal(t, "value", q.Match())
	})

	t.Run("ok - seek", func(t *testing.T) {
		assert.Equal(t, "value", q.Seek())
	})

}

func TestQuery(t *testing.T) {
	q := query{
		concept: "concept",
	}
	tp := template{
		raw: ExampleTemplate,
	}
	err := tp.parse()
	if !assert.NoError(t, err) {
		return
	}

	q.AddTemplate(&tp)

	t.Run("Concept", func(t *testing.T) {
		assert.Equal(t, "concept", q.Concept())
	})

	t.Run("AddTemplate - adds template to query", func(t *testing.T) {
		assert.Len(t, q.Parts(), 1)
	})

	t.Run("AddTemplate - adds hardcoded values to query criteria", func(t *testing.T) {
		tq := q.parts[0]

		if !assert.Len(t, tq.Criteria, 1) {
			return
		}

		crit := tq.Criteria[0]
		assert.Equal(t, TypeField, crit.Key())
		assert.Equal(t, ExampleType, crit.Seek())
		assert.Equal(t, ExampleType, crit.Match())
	})

	t.Run("AddCriteria", func(t *testing.T) {
		tq := q.parts[0]

		q.AddCriteria(eq{key: "key", value: "value"})

		if !assert.Len(t, tq.Criteria, 2) {
			return
		}

		crit := tq.Criteria[1]
		assert.Equal(t, "key", crit.Key())
		assert.Equal(t, "value", crit.Seek())
	})

	t.Run("VCType", func(t *testing.T) {
		tq := q.parts[0]

		assert.Equal(t, ExampleType, tq.VCType())
	})

}
