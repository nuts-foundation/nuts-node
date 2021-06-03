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

package core

import (
	"fmt"
	"net/url"
	"os"

	"github.com/labstack/echo/v4"
	"github.com/spf13/cobra"
)

// Routable enables connecting a REST API to the echo server. The API wrappers should implement this interface
type Routable interface {
	// Routes configures the HTTP routes on the given router
	Routes(router EchoRouter)
}

// NewSystem creates a new, empty System.
func NewSystem() *System {
	result := &System{
		engines: []Engine{},
		Config:  NewServerConfig(),
		Routers: []Routable{},
	}
	result.EchoCreator = func(cfg HTTPConfig, strictmode bool) (EchoServer, error) {
		return createEchoServer(cfg, strictmode, result.Routers)
	}
	return result
}

// System is the control structure where engines are registered.
type System struct {
	// engines is the slice of all registered engines
	engines []Engine
	// Config holds the global and raw config
	Config *ServerConfig
	// Routers is used to connect API handlers to the echo server
	Routers []Routable
	// EchoCreator is the function that's used to create the echo server/
	EchoCreator func(cfg HTTPConfig, strictmode bool) (EchoServer, error)
}

// Load loads the config and injects config values into engines
func (system *System) Load(cmd *cobra.Command) error {
	if err := system.Config.Load(cmd); err != nil {
		return err
	}

	return system.injectConfig()
}

func (system *System) injectConfig() error {
	var err error
	return system.VisitEnginesE(func(engine Engine) error {
		if m, ok := engine.(Injectable); ok {
			err = system.Config.InjectIntoEngine(m)
		}
		return err
	})
}

// Diagnostics returns the compound diagnostics for all engines.
func (system *System) Diagnostics() []DiagnosticResult {
	result := make([]DiagnosticResult, 0)
	system.VisitEngines(func(engine Engine) {
		if m, ok := engine.(Diagnosable); ok {
			result = append(result, m.Diagnostics()...)
		}
	})
	return result
}

// Start starts all engines in the system.
func (system *System) Start() error {
	var err error
	return system.VisitEnginesE(func(engine Engine) error {
		if m, ok := engine.(Runnable); ok {
			err = m.Start()
		}
		return err
	})
}

// Shutdown shuts down all engines in the system.
func (system *System) Shutdown() error {
	var err error
	return system.VisitEnginesE(func(engine Engine) error {
		if m, ok := engine.(Runnable); ok {
			err = m.Shutdown()
		}
		return err
	})
}

// Configure configures all engines in the system.
func (system *System) Configure() error {
	var err error
	if err = os.MkdirAll(system.Config.Datadir, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create datadir (dir=%s): %w", system.Config.Datadir, err)
	}
	return system.VisitEnginesE(func(engine Engine) error {
		// only if Engine is dynamically configurable
		if m, ok := engine.(Configurable); ok {
			err = m.Configure(*system.Config)
		}
		return err
	})
}

// VisitEngines applies the given function on all engines in the system.
func (system *System) VisitEngines(visitor func(engine Engine)) {
	_ = system.VisitEnginesE(func(engine Engine) error {
		visitor(engine)
		return nil
	})
}

// VisitEnginesE applies the given function on all engines in the system, stopping when an error is returned. The error
// is passed through.
func (system *System) VisitEnginesE(visitor func(engine Engine) error) error {
	for _, e := range system.engines {
		if err := visitor(e); err != nil {
			return err
		}
	}
	return nil
}

// RegisterEngine is a helper func to add an engine to the list of engines from a different lib/pkg
func (system *System) RegisterEngine(engine Engine) {
	system.engines = append(system.engines, engine)
}

// RegisterRoutes is a helper func to register API routers so they can be linked to the echo server
func (system *System) RegisterRoutes(router Routable) {
	system.Routers = append(system.Routers, router)
}

// Runnable is the interface that groups the Start and Shutdown methods.
// When an engine implements these they will be called on startup and shutdown.
// Start and Shutdown should not be called more than once
type Runnable interface {
	Start() error
	Shutdown() error
}

// Configurable is the interface that contains the Configure method.
// When an engine implements the Configurable interface, it will be called before startup.
// Configure should only be called once per engine instance
type Configurable interface {
	Configure(config ServerConfig) error
}

// ViewableDiagnostics is used for engines that display diagnostics in an interface
type ViewableDiagnostics interface {
	Named
	Diagnosable
}

// Diagnosable allows the implementer, mostly engines, to return diagnostics.
type Diagnosable interface {
	Diagnostics() []DiagnosticResult
}

// Engine is the base interface for a modular design
type Engine interface{}

// Named is the interface for all engines that have a name
type Named interface {
	// Name returns the name of the engine
	Name() string
}

// Injectable marks a engine capable of Config injection
type Injectable interface {
	Named
	// ConfigKey returns the logical Config key used in the Config file for this engine.
	ConfigKey() string
	// Config returns a pointer to the struct that holds the Config.
	Config() interface{}
}

// DecodeURIPath is a echo middleware that decodes path parameters
func DecodeURIPath(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// FIXME: This is a hack because of https://github.com/labstack/echo/issues/1258
		newValues := make([]string, len(c.ParamValues()))
		for i, value := range c.ParamValues() {
			path, err := url.PathUnescape(value)
			if err != nil {
				path = value
			}
			newValues[i] = path
		}
		c.SetParamNames(c.ParamNames()...)
		c.SetParamValues(newValues...)
		return next(c)
	}
}
