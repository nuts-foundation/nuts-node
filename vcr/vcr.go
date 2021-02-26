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

package vcr

import (
	"encoding/json"
	"fmt"
	"path"
	"time"

	"github.com/nuts-foundation/go-did"
	"github.com/nuts-foundation/go-leia"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/vcr/concept"
	"github.com/pkg/errors"
)

// NewVCRInstance creates a new vcr instance with default config and empty concept registry
func NewVCRInstance() VCR {
	return &vcr{
		config:   DefaultConfig(),
		registry: concept.NewRegistry(),
	}
}

type vcr struct {
	registry concept.Registry
	config   Config
	store    leia.Store
}

func (c *vcr) Registry() concept.Registry {
	return c.registry
}

func (c *vcr) Configure(config core.ServerConfig) error {
	var err error
	fsPath := path.Join(config.Datadir, "vcr", "credentials.db")

	if c.store, err = leia.NewStore(fsPath); err != nil {
		return err
	}

	// init indices
	if err = c.initIndices(); err != nil {
		return err
	}

	return nil
}

func (c *vcr) initIndices() error {
	for _, templates := range c.registry.ConceptTemplates() {
		for _, t := range templates {
			collection := c.store.Collection(t.VCType())
			for i, index := range t.Indices() {
				var leiaParts []leia.IndexPart

				for _, iParts := range index {
					name := iParts
					jsonPath := t.ToVCPath(iParts)
					leiaParts = append(leiaParts, leia.NewJSONIndexPart(name, jsonPath))
				}

				if err := collection.AddIndex(leia.NewIndex(fmt.Sprintf("index_%d", i), leiaParts...)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (c *vcr) Name() string {
	return moduleName
}

func (c *vcr) ConfigKey() string {
	return configKey
}

func (c *vcr) Config() interface{} {
	return &c.config
}

func (c *vcr) Search(query concept.Query) ([]did.VerifiableCredential, error) {
	//transform query to leia query, for each template a query is returned
	queries := c.convert(query)

	var VCs = make([]did.VerifiableCredential, 0)
	for vcType, q := range queries {
		docs, err := c.store.Collection(vcType).Find(q)
		if err != nil {
			return nil, err
		}
		for _, doc := range docs {
			vc := did.VerifiableCredential{}
			err = json.Unmarshal(doc, &vc)
			if err != nil {
				return nil, errors.Wrap(err, "unable to parse vcr from db")
			}
			VCs = append(VCs, vc)
		}
	}

	return VCs, nil
}

func (c *vcr) Resolve(ID string) (did.VerifiableCredential, error) {
	panic("implement me")
}

func (c *vcr) Verify(vc did.VerifiableCredential, credentialSubject interface{}, at time.Time) (bool, error) {
	panic("implement me")
}

// convert returns a map of vcr type to query
// vcr type is then used as collection input
func (c *vcr) convert(query concept.Query) map[string]leia.Query {
	var qs = make(map[string]leia.Query, 0)

	for _, tq := range query.Parts() {
		var q leia.Query
		for _, criteria := range tq.Criteria {
			// todo this should map better
			qp := leia.Range(criteria.Key(), criteria.Seek(), criteria.Match())
			if q == nil {
				q = leia.New(qp)
			} else {
				q = q.And(qp)
			}
		}
		qs[tq.VCType()] = q
	}

	return qs
}
