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

	ssi "github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-did/vc"
	"github.com/stretchr/testify/assert"
)

func TestRegistry_AddFromString(t *testing.T) {
	tp, err := ParseTemplate(ExampleTemplate)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("when template is added", func(t *testing.T) {
		r := NewRegistry().(*registry)

		err := r.Add(tp)
		if !assert.NoError(t, err) {
			return
		}

		t.Run("hasConcept() is true", func(t *testing.T) {
			assert.True(t, r.hasConcept(ExampleConcept))
		})

		t.Run("template is added to conceptTemplates", func(t *testing.T) {
			ts, ok := r.conceptTemplates[ExampleConcept]

			if !assert.True(t, ok) {
				return
			}

			assert.Len(t, ts, 1)
		})

		t.Run("ConceptTemplates() returns templates", func(t *testing.T) {
			ts, ok := r.ConceptTemplates()[ExampleConcept]

			if !assert.True(t, ok) {
				return
			}

			assert.Len(t, ts, 1)
		})

		t.Run("template is added to typedTemplates", func(t *testing.T) {
			_, ok := r.typedTemplates[ExampleType]

			assert.True(t, ok)
		})
	})

	t.Run("error - no type error", func(t *testing.T) {
		r := NewRegistry().(*registry)
		tp, err := ParseTemplate("{}")
		if !assert.NoError(t, err) {
			return
		}

		err = r.Add(tp)

		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, ErrNoType, err)
	})
}

func TestRegistry_Transform(t *testing.T) {
	r := NewRegistry().(*registry)
	tp, err := ParseTemplate(ExampleTemplate)
	if !assert.NoError(t, err) {
		return
	}

	err = r.Add(tp)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("VC is transformed", func(t *testing.T) {
		c, err := r.Transform(ExampleConcept, TestVC())

		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, c)
		assert.Equal(t, "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY#123", c[IDField])
		assert.Equal(t, ExampleType, c[TypeField])
		assert.Equal(t, "did:nuts:B8PUHs2AUHbFF1xLLK4eZjgErEcMXHxs68FteY7NDtCY", c[IssuerField])
		assert.Equal(t, "did:nuts:GvkzxsezHvEc8nGhgz6Xo3jbqkHwswLmWw3CYtCm7hAW", c[SubjectField])

		cs, ok := c[ExampleConcept]
		if !assert.True(t, ok) {
			return
		}

		cm, ok := cs.(Concept)
		if !assert.True(t, ok) {
			return
		}

		assert.Equal(t, "fair", cm["hairColour"])
		assert.Equal(t, "blue/grey", cm["eyeColour"])
	})

	t.Run("error - unknown type", func(t *testing.T) {
		vcType, _ := ssi.ParseURI("unknownType")
		vc := vc.VerifiableCredential{
			Type: []ssi.URI{*vcType},
		}

		_, err = r.Transform("human", vc)

		if !assert.Error(t, err) {
			return
		}

		assert.Equal(t, ErrNoType, err)
	})

	t.Run("error - unknown concept", func(t *testing.T) {
		_, err = r.Transform("unknown", vc.VerifiableCredential{})

		if !assert.Error(t, err) {
			return
		}

		assert.Equal(t, ErrUnknownConcept, err)
	})
}

func TestRegistry_QueryFor(t *testing.T) {
	r := NewRegistry().(*registry)
	tp, err := ParseTemplate(ExampleTemplate)
	if !assert.NoError(t, err) {
		return
	}
	err = r.Add(tp)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("error - unknown concept", func(t *testing.T) {
		_, err := r.QueryFor("unknown")

		if !assert.Error(t, err) {
			return
		}

		assert.Equal(t, ErrUnknownConcept, err)
	})
}
