package tenant

import (
	"github.com/google/uuid"
	"time"
)

// ModuleName is the name of the module
const ModuleName = "Tenant"

type Tenant struct {
	ID      string
	DIDs    []string
	Created time.Time
}

func New() *Module {
	return &Module{}
}

type Module struct {
}

func (m Module) create() (*Tenant, error) {
	uuid.NewString()
}
