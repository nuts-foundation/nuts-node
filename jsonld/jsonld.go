package jsonld

import "github.com/nuts-foundation/nuts-node/core"

type jsonld struct {
	config         Config
	contextManager ContextManager
}

// NewJSONLDInstance creates a new instance of the jsonld struct which implements the JSONLD interface
func NewJSONLDInstance() JSONLD {
	return &jsonld{
		config:         DefaultConfig(),
		contextManager: NewManager(),
	}
}

func (j *jsonld) Configure(serverConfig core.ServerConfig) error {
	j.config.strictMode = serverConfig.Strictmode
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
