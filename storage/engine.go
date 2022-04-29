package storage

import "github.com/nuts-foundation/nuts-node/core"

func New() core.Engine {
	return &engine{}
}

type engine struct {

}

func (e engine) Name() string {
	return "Storage"
}
