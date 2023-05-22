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
