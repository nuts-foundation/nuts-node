package jsonld

import (
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/piprate/json-gold/ld"
)

type jsonld struct {
	config         Config
	documentLoader ld.DocumentLoader
}

// NewJSONLDInstance creates a new instance of the jsonld struct which implements the JSONLD interface
func NewJSONLDInstance() JSONLD {
	return &jsonld{
		config: DefaultConfig(),
	}
}

func (j *jsonld) DocumentLoader() ld.DocumentLoader {
	return j.documentLoader
}

func (j *jsonld) Configure(serverConfig core.ServerConfig) error {
	j.config.strictMode = serverConfig.Strictmode

	loader, err := NewContextLoader(!j.config.strictMode, j.config.Contexts)
	if err != nil {
		return err
	}
	j.documentLoader = loader
	return nil
}

func (j jsonld) Name() string {
	return moduleName
}

func (j *jsonld) Config() interface{} {
	return &j.config
}
