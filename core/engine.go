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
		engines: []*Engine{},
		Config:  NewNutsConfig(),
	}
}

// System is the control structure where engines are registered.
type System struct {
	// engines is the slice of all registered engines
	engines []*Engine
	// Config holds the global and raw config
	Config *NutsConfig
}

// Load loads the config and injects config values into engines
func (system *System) Load(cmd *cobra.Command) error {
	if err := system.Config.Load(cmd); err != nil {
		return err
	}

	return system.injectConfig()
}

func (system *System) injectConfig() error {
	return system.VisitEnginesE(func(engine *Engine) error {
		return system.Config.InjectIntoEngine(engine)
	})
}

// Diagnostics returns the compound diagnostics for all engines.
func (system *System) Diagnostics() []DiagnosticResult {
	result := make([]DiagnosticResult, 0)
	system.VisitEngines(func(engine *Engine) {
		if engine.Diagnosable != nil {
			result = append(result, engine.Diagnostics()...)
		}
	})
	return result
}

// Start starts all engines in the system.
func (system *System) Start() error {
	var err error
	return system.VisitEnginesE(func(engine *Engine) error {
		if engine.Runnable != nil {
			err = engine.Start()
		}
		return err
	})
}

// Shutdown shuts down all engines in the system.
func (system *System) Shutdown() error {
	var err error
	return system.VisitEnginesE(func(engine *Engine) error {
		if engine.Runnable != nil {
			err = engine.Shutdown()
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
	return system.VisitEnginesE(func(engine *Engine) error {
		// only if Engine is dynamically configurable
		if engine.Configurable != nil {
			err = engine.Configure(*system.Config)
		}
		return err
	})
}

// VisitEngines applies the given function on all engines in the system.
func (system *System) VisitEngines(visitor func(engine *Engine)) {
	_ = system.VisitEnginesE(func(engine *Engine) error {
		visitor(engine)
		return nil
	})
}

// VisitEnginesE applies the given function on all engines in the system, stopping when an error is returned. The error
// is passed through.
func (system *System) VisitEnginesE(visitor func(engine *Engine) error) error {
	for _, e := range system.engines {
		if err := visitor(e); err != nil {
			return err
		}
	}
	return nil
}

// RegisterEngine is a helper func to add an engine to the list of engines from a different lib/pkg
func (system *System) RegisterEngine(engine *Engine) {
	system.engines = append(system.engines, engine)
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

// START_DOC_ENGINE_1

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

// Diagnosable allows the implementer, mostly engines, to return diagnostics.
type Diagnosable interface {
	Diagnostics() []DiagnosticResult
}

// Engine contains all the configuration options and callbacks needed by the executable to configure, start, monitor and shutdown the engines
type Engine struct {
	// Name holds the human readable name of the engine
	Name string

	// Cmd is the optional sub-command for the engine. An engine can only add one sub-command (but multiple sub-sub-commands for the sub-command)
	Cmd *cobra.Command

	// ConfigKey is the root yaml key in the config file or ENV sub-key for all keys used to configure an engine
	// 	status:
	//	  key:
	// and
	// 	NUTS_STATUS_KEY=
	// and
	//	--status-key
	ConfigKey string

	// Config is the pointer to a config struct. The config will be unmarshalled using the ConfigKey.
	Config interface{}

	Diagnosable
	Runnable
	Configurable

	// FlasSet contains all engine-local configuration possibilities so they can be displayed through the help command
	FlagSet *pflag.FlagSet

	// Routes passes the Echo router to the specific engine for it to register their routes.
	Routes func(router EchoRouter)
}

// END_DOC_ENGINE_1

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
