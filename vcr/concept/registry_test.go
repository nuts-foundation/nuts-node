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

func TestRegistry_Add(t *testing.T) {
	t.Run("when template is added", func(t *testing.T) {
		r := NewRegistry().(*registry)

		err := r.Add(ExampleConfig)
		if !assert.NoError(t, err) {
			return
		}

		t.Run("hasConcept() is true", func(t *testing.T) {
			assert.True(t, r.hasConcept(ExampleConcept))
		})

		t.Run("template is added", func(t *testing.T) {
			assert.Len(t, r.configs, 1)
		})
	})

	t.Run("error - no type error", func(t *testing.T) {
		r := NewRegistry().(*registry)

		err := r.Add(Config{})

		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, ErrNoType, err)
	})
}

func TestRegistry_Transform(t *testing.T) {
	r := NewRegistry().(*registry)

	err := r.Add(ExampleConfig)
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

		cm, ok := cs.(map[string]interface{})
		if !assert.True(t, ok) {
			return
		}

		assert.Equal(t, "fair", cm["hairColour"])
		assert.Equal(t, "blue/grey", cm["eyeColour"])
	})

	t.Run("error - unknown type", func(t *testing.T) {
		vcType := ssi.MustParseURI("unknownType")
		vc := vc.VerifiableCredential{
			Type: []ssi.URI{vcType},
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

func TestRegistry_Concepts(t *testing.T) {
	r := NewRegistry().(*registry)

	err := r.Add(ExampleConfig)
	if !assert.NoError(t, err) {
		return
	}

	cs := r.Concepts()

	if !assert.Len(t, cs, 1) {
		return
	}
	assert.Equal(t, "human", cs[0].Concept)
}

func TestRegistry_FindByType(t *testing.T) {
	r := NewRegistry().(*registry)

	err := r.Add(ExampleConfig)
	if !assert.NoError(t, err) {
		return
	}

	t.Run("true", func(t *testing.T) {
		assert.NotNil(t, r.FindByType(ExampleType))
	})

	t.Run("false", func(t *testing.T) {
		assert.Nil(t, r.FindByType("other"))
	})
}

func TestRegistry_QueryFor(t *testing.T) {
	r := NewRegistry().(*registry)

	err := r.Add(ExampleConfig)
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

	t.Run("ok", func(t *testing.T) {
		q, err := r.QueryFor("human")

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, "human", q.Concept())
		if !assert.Len(t, q.Parts(), 1) {
			return
		}
		assert.Equal(t, "HumanCredential", q.Parts()[0].CredentialType())
		assert.Equal(t, q.Concept(), q.Parts()[0].config.Concept)
		assert.Len(t, q.Parts()[0].Clauses, 0)
	})
}
