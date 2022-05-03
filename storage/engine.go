package storage

import "github.com/nuts-foundation/nuts-node/core"

// New creates a new instance of the storage engine.
func New() core.Engine {
	return &engine{}
}

type engine struct {
}

// Name returns the name of the storage engine.
func (e engine) Name() string {
	return "Storage"
}
