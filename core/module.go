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
	"github.com/spf13/pflag"
)

// NewSystem creates a new, empty System.
func NewSystem() *System {
	return &System{
		modules: []Module{},
		Config:  NewNutsConfig(),
	}
}

// System is the control structure where modules are registered.
type System struct {
	// modules is the slice of all registered modules
	modules []Module
	// Config holds the global and raw config
	Config *NutsConfig
}

// Load loads the config and injects config values into modules
func (system *System) Load(cmd *cobra.Command) error {
	if err := system.Config.Load(cmd); err != nil {
		return err
	}

	return system.injectConfig()
}

func (system *System) injectConfig() error {
	var err error
	return system.VisitModuleE(func(module Module) error {
		if m, ok := module.(Injectable); ok {
			err = system.Config.InjectIntoEngine(m)
		}
		return err
	})
}

// Diagnostics returns the compound diagnostics for all modules.
func (system *System) Diagnostics() []DiagnosticResult {
	result := make([]DiagnosticResult, 0)
	system.VisitModules(func(module Module) {
		if m, ok := module.(Diagnosable); ok {
			result = append(result, m.Diagnostics()...)
		}
	})
	return result
}

// Start starts all modules in the system.
func (system *System) Start() error {
	var err error
	return system.VisitModuleE(func(module Module) error {
		if m, ok := module.(Runnable); ok {
			err = m.Start()
		}
		return err
	})
}

// Shutdown shuts down all modules in the system.
func (system *System) Shutdown() error {
	var err error
	return system.VisitModuleE(func(module Module) error {
		if m, ok := module.(Runnable); ok {
			err = m.Shutdown()
		}
		return err
	})
}

// Configure configures all modules in the system.
func (system *System) Configure() error {
	var err error
	if err = os.MkdirAll(system.Config.Datadir, os.ModePerm); err != nil {
		return fmt.Errorf("unable to create datadir (dir=%s): %w", system.Config.Datadir, err)
	}
	return system.VisitModuleE(func(module Module) error {
		// only if Engine is dynamically configurable
		if m, ok := module.(Configurable); ok {
			err = m.Configure(*system.Config)
		}
		return err
	})
}

// VisitModules applies the given function on all modules in the system.
func (system *System) VisitModules(visitor func(module Module)) {
	_ = system.VisitModuleE(func(module Module) error {
		visitor(module)
		return nil
	})
}

// VisitModuleE applies the given function on all modules in the system, stopping when an error is returned. The error
// is passed through.
func (system *System) VisitModuleE(visitor func(module Module) error) error {
	for _, e := range system.modules {
		if err := visitor(e); err != nil {
			return err
		}
	}
	return nil
}

// RegisterModule is a helper func to add an engine to the list of modules from a different lib/pkg
func (system *System) RegisterModule(module Module) {
	system.modules = append(system.modules, module)
}

// EchoServer implements both the EchoRouter interface and Start function to aid testing.
type EchoServer interface {
	EchoRouter
	Start(address string) error
}

// EchoRouter is the interface the generated server API's will require as the Routes func argument
type EchoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
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
	Configure(config NutsConfig) error
}

// ViewableDiagnostics is used for modules that display diagnostics in an interface
type ViewableDiagnostics interface {
	Named
	Diagnosable
}

// Diagnosable allows the implementer, mostly modules, to return diagnostics.
type Diagnosable interface {
	Diagnostics() []DiagnosticResult
}

// Routable enables connecting a REST API to the implementer.
type Routable interface {
	// Routes configures the HTTP routes on the given router
	Routes(router EchoRouter)
}

// Module is the base interface for a modular design
type Module interface{}

// Named is the interface for all modules that have a name
type Named interface {
	// Name returns the name of the module
	Name() string
}

// Executable enables CLI commands on the implementer
type Executable interface {
	// Cmd that can be called from the CLI
	Cmd() *cobra.Command
}

// Injectable marks a module capable of Config injection
type Injectable interface {
	Named
	// ConfigKey returns the logical Config key used in the Config file for this module.
	ConfigKey() string
	// Config returns a pointer to the struct that holds the Config.
	Config() interface{}
	// FlagSet containing commandline flags
	FlagSet() *pflag.FlagSet
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
