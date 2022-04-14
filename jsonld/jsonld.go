package jsonld

import "github.com/nuts-foundation/nuts-node/core"

type jsonld struct {
	config         Config
	contextManager ContextManager
}

func NewJSONLDInstance() JSONLD {
	return &jsonld{
		config:         DefaultConfig(),
		contextManager: NewManager(),
	}
}

func (j *jsonld) Configure(core.ServerConfig) error {
	if err := j.contextManager.Configure(j.config); err != nil {
		return err
	}
	return nil
}

func (j jsonld) ContextManager() ContextManager {
	return j.contextManager
}

func (j jsonld) Name() string {
	return moduleName
}

func (j *jsonld) Config() interface{} {
	return &j.config
}
