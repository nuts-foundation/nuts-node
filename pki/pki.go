/*
 * Copyright (C) 2023 Nuts community
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

package pki

import (
	"context"
	"github.com/nuts-foundation/nuts-node/core"
)

const moduleName = "PKI"

var _ Validator = (*PKI)(nil)

type PKI struct {
	*validator
	ctx      context.Context
	shutdown context.CancelFunc
	config   Config
}

func New() *PKI {
	return &PKI{config: DefaultConfig()}
}

func (p *PKI) Name() string {
	return moduleName
}

func (p *PKI) Config() any {
	return &p.config
}

func (p *PKI) Configure(_ core.ServerConfig) error {
	var err error
	p.validator, err = newValidator(p.config)
	if err != nil {
		return err
	}
	return nil
}

func (p *PKI) Start() error {
	p.ctx, p.shutdown = context.WithCancel(context.Background())
	p.validator.start(p.ctx)
	return nil
}

func (p *PKI) Shutdown() error {
	p.shutdown()
	return nil
}
