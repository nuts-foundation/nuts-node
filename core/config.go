/*
 * Nuts go
 * Copyright (C) 2019 Nuts community
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
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const defaultPrefix = "NUTS"
const defaultSeparator = "."
const defaultConfigFile = "nuts.yaml"
const configFileFlag = "configfile"
const loggerLevelFlag = "verbosity"
const addressFlag = "address"
const defaultLogLevel = "info"
const defaultAddress = "localhost:1323"
const strictModeFlag = "strictmode"
const modeFlag = "mode"
const identityFlag = "identity"

var defaultIgnoredPrefixes = []string{"root"}

// Make sure NutsGlobalConfig implements NutConfigValues interface
var _ NutsConfigValues = (*NutsGlobalConfig)(nil)

// NutsGlobalConfig has the settings which influence all other settings.
type NutsGlobalConfig struct {
	// The default config file the configuration looks for (Default nuts.yaml)
	DefaultConfigFile string

	// Prefix sets the global config environment variable prefix (Default: NUTS)
	Prefix string

	// Delimiter sets the nested config separator string (Default: '.')
	Delimiter string

	// IgnoredPrefixes is a slice of prefixes which will not be used to prepend config variables, eg: --logging.verbosity will just be --verbosity
	IgnoredPrefixes []string

	v *viper.Viper
}

// NutsConfigValues exposes global configuration values
type NutsConfigValues interface {
	ServerAddress() string
	InStrictMode() bool
	Mode() string
	GetEngineMode(engineMode string) string
}

const (
	// ServerEngineMode is used for starting a node's engine in server mode
	ServerEngineMode string = "server"
	// ClientEngineMode is used for starting a node's engine in client mode
	ClientEngineMode string = "client"
)

const (
	// GlobalServerMode is used for starting the application in server mode, running as Nuts node.
	GlobalServerMode string = "server"
	// GlobalCLIMode is used for starting the application in CLI mode, meaning it's used as CLI client administering
	// for a remote Nuts node. Engines will start in client mode when this mode is specified.
	GlobalCLIMode string = "cli"
)

// NewNutsGlobalConfig creates a NutsGlobalConfig with the following defaults
// * Prefix: NUTS
// * Delimiter: '.'
// * IgnoredPrefixes: ["root","logging"]
func NewNutsGlobalConfig() *NutsGlobalConfig {
	return &NutsGlobalConfig{
		DefaultConfigFile: defaultConfigFile,
		Prefix:            defaultPrefix,
		Delimiter:         defaultSeparator,
		IgnoredPrefixes:   defaultIgnoredPrefixes,
		v:                 viper.New(),
	}
}

var configOnce sync.Once
var configInstance *NutsGlobalConfig

// NutsGlobalConfig returns a singleton global config
func NutsConfig() *NutsGlobalConfig {
	configOnce.Do(func() {
		configInstance = NewNutsGlobalConfig()
	})
	return configInstance
}

// ServerAddress is the address which is used to either listen on (in server mode) or connect to (in client mode).
func (ngc NutsGlobalConfig) ServerAddress() string {
	return ngc.v.GetString(addressFlag)
}

// InStrictMode helps to safeguard settings which are handy and default in development but not safe for production.
func (ngc NutsGlobalConfig) InStrictMode() bool {
	return ngc.v.GetBool(strictModeFlag)
}

// Mode returns the configured mode (client/server).
func (ngc NutsGlobalConfig) Mode() string {
	return ngc.v.GetString(modeFlag)
}


// GetEngineMode configures an engine mode if not already configured. If the application is started in 'cli' mode,
// its engines are configured to run in 'client' mode. This function returns the proper mode for the engine in and should be used as follows:
// engineConfig.Mode = GetEngineMode(engineConfig.Mode)
func (ngc NutsGlobalConfig) GetEngineMode(engineMode string) string {
	if engineMode == "" {
		switch ngc.Mode() {
		case GlobalCLIMode:
			return ClientEngineMode
		default:
			return ServerEngineMode
		}
	}
	return engineMode
}

// Load sets some initial config in order to be able for commands to load the right parameters and to add the configFile Flag.
// This is mainly spf13/viper related stuff
func (ngc *NutsGlobalConfig) Load(cmd *cobra.Command) error {
	ngc.v.SetEnvPrefix(ngc.Prefix)
	ngc.v.AutomaticEnv()
	ngc.v.SetEnvKeyReplacer(strings.NewReplacer(ngc.Delimiter, "_"))
	flagSet := pflag.NewFlagSet("config", pflag.ContinueOnError)
	flagSet.String(configFileFlag, ngc.DefaultConfigFile, "Nuts config file")
	flagSet.String(loggerLevelFlag, defaultLogLevel, "Log level (trace, debug, info, warn, error)")
	flagSet.String(addressFlag, defaultAddress, "Address and port the server will be listening to")
	flagSet.Bool(strictModeFlag, false, "When set, insecure settings are forbidden.")
	flagSet.String(modeFlag, "server", "Mode the application will run in. When 'cli' it can be used to administer a remote Nuts node. When 'server' it will start a Nuts node. Defaults to 'server'.")
	flagSet.String(identityFlag, "", "Vendor identity for the node, mandatory when running in server mode. Must be in the format: urn:oid:"+NutsVendorOID+":<number>")
	cmd.PersistentFlags().AddFlagSet(flagSet)

	// Bind config flag
	// Bind log level flag
	ngc.bindFlag(flagSet, configFileFlag)
	ngc.bindFlag(flagSet, loggerLevelFlag)
	ngc.bindFlag(flagSet, addressFlag)
	ngc.bindFlag(flagSet, strictModeFlag)
	ngc.bindFlag(flagSet, modeFlag)
	ngc.bindFlag(flagSet, identityFlag)

	// load flags into viper
	pfs := cmd.PersistentFlags()
	pfs.ParseErrorsWhitelist.UnknownFlags = true
	if err := pfs.Parse(os.Args[1:]); err != nil {
		if err != pflag.ErrHelp {
			return err
		}
	}

	// load configFile into viper
	if err := ngc.loadConfigFile(); err != nil {
		return err
	}

	// initialize logger, verbosity flag needs to be available
	level, err := log.ParseLevel(ngc.v.GetString(loggerLevelFlag))
	if err != nil {
		return err
	}
	log.SetLevel(level)

	if ngc.Mode() != GlobalCLIMode && ngc.Mode() != GlobalServerMode {
		return fmt.Errorf("unsupported global mode: %s, supported modes: %s", ngc.Mode(), strings.Join([]string{GlobalCLIMode, GlobalServerMode}, ", "))
	}

	return nil
}

func (ngc *NutsGlobalConfig) bindFlag(fs *pflag.FlagSet, name string) error {
	s := fs.Lookup(name)
	if err := ngc.v.BindPFlag(s.Name, s); err != nil {
		return err
	}
	if err := ngc.v.BindEnv(s.Name); err != nil {
		return err
	}
	return nil
}

// PrintConfig outputs the current config to the logger on info level
func (ngc *NutsGlobalConfig) PrintConfig(logger log.FieldLogger) {
	title := "Config"
	var longestKey = 10
	var longestValue int
	for _, e := range EngineCtl.Engines {
		if e.FlagSet != nil {
			e.FlagSet.VisitAll(func(flag *pflag.Flag) {
				s := fmt.Sprintf("%v", ngc.v.Get(strings.ToLower(flag.Name)))
				if len(s) > longestValue {
					longestValue = len(s)
				}
				if len(flag.Name) > longestKey {
					longestKey = len(flag.Name)
				}
			})
		}
	}

	totalLength := 7 + longestKey + longestValue
	stars := strings.Repeat("*", totalLength)
	sideStarsLeft := int(math.Floor((float64(totalLength)-float64(len(title)))/2.0)) - 1
	sideStarsRight := int(math.Ceil((float64(totalLength)-float64(len(title)))/2.0)) - 1

	logger.Infoln(stars)
	logger.Infof("%s %s %s", strings.Repeat("*", sideStarsLeft), title, strings.Repeat("*", sideStarsRight))

	f := fmt.Sprintf("%%-%ds%%v", 7+longestKey)

	logger.Infof(f, addressFlag, ngc.ServerAddress())
	logger.Infof(f, configFileFlag, ngc.v.Get(configFileFlag))
	logger.Infof(f, loggerLevelFlag, ngc.v.Get(loggerLevelFlag))
	logger.Infof(f, strictModeFlag, ngc.InStrictMode())
	logger.Infof(f, modeFlag, ngc.Mode())
	for _, e := range EngineCtl.Engines {
		if e.FlagSet != nil {
			e.FlagSet.VisitAll(func(flag *pflag.Flag) {
				logger.Infof(f, flag.Name, ngc.v.Get(strings.ToLower(flag.Name)))
			})
		}
	}

	logger.Infoln(stars)
}

// LoadConfigFile load the config from the given config file or from the default config file. If the file does not exist it'll continue with default values.
func (ngc *NutsGlobalConfig) loadConfigFile() error {
	configFile := ngc.v.GetString(configFileFlag)

	// default path, relative paths and absolute paths should work
	ngc.v.AddConfigPath(".")
	ngc.v.SetConfigFile(configFile)

	// if file can not be found, print to stderr and continue
	err := ngc.v.ReadInConfig()
	if err != nil {
		var pathError *os.PathError
		// error on opening file
		if errors.As(err, &pathError) && pathError.Op == "open" {
			fmt.Fprintf(os.Stderr, "Config file %s not found, using defaults!\n", configFile)
			return nil
		}
	}
	return err
}

// InjectIntoEngine loop over all flags from an engine and injects any value into the given Config struct for the Engine.
// If the Engine does not have a config struct, it does nothing.
// Any config not registered as global flag will be ignored.
// It expects all config var names to be prepended or nested with the Engine ConfigKey,
// this will be ignored if the ConfigKey is "" or if the key is in the set of ignored prefixes.
func (ngc *NutsGlobalConfig) InjectIntoEngine(e *Engine) error {
	var err error

	// ignore if no target for injection
	if e.Config != nil {
		// ignore if no registered flags
		if e.FlagSet != nil {
			fs := e.FlagSet
			log.Tracef("Injecting values for engine %s\n", e.Name)

			fs.VisitAll(func(f *pflag.Flag) {
				// config name as used by viper
				configName := ngc.configName(e, f)

				// field in struct
				var field *reflect.Value
				field, err = ngc.findField(e, ngc.fieldName(e, f.Name))

				if err != nil {
					err = fmt.Errorf("problem injecting [%v] for %s: %w", configName, e.Name, err)
					return
				}

				// test if is set, this can not be done with IsSet, because it doesn't take ENV variables into account.
				var val interface{}
				val = ngc.v.Get(configName)
				if val == nil {
					err = fmt.Errorf("nil value for %v, forgot to add flag binding", configName)
					return
				}

				isStringSlice := false

				// get real value with correct type
				switch field.Kind() {
				case reflect.Int:
					val = ngc.v.GetInt(configName)
				case reflect.Int32:
					val = ngc.v.GetInt32(configName)
				case reflect.Int64:
					val = ngc.v.GetInt64(configName)
				case reflect.String:
					val = ngc.v.GetString(configName)
				case reflect.Bool:
					val = ngc.v.GetBool(configName)
				case reflect.Slice:
					val = ngc.v.Get(configName)
					valI := val.([]interface{})
					if _, ok := valI[0].(string); ok {
						isStringSlice = true
					}
				default:
					val = ngc.v.Get(configName)
				}

				if val == nil {
					err = fmt.Errorf("nil value for %v, forgot to add flag binding", configName)
					return
				}

				// inject value
				if isStringSlice {
					valI := val.([]interface{})
					va := make([]string, len(valI))
					for i, v := range valI {
						va[i] = v.(string)
					}
					field.Set(reflect.ValueOf(va))
				} else {
					field.Set(reflect.ValueOf(val))
				}
				log.Tracef("[%s] %s=%v\n", e.Name, f.Name, val)
			})
		}
	}

	return err
}

func (ngc *NutsGlobalConfig) injectIntoStruct(s interface{}) error {
	var err error

	for _, configName := range ngc.v.AllKeys() {
		// ignore global flags
		if configName == configFileFlag || configName == loggerLevelFlag || configName == addressFlag || configName == strictModeFlag || configName == modeFlag {
			continue
		}

		sv := reflect.ValueOf(s)
		var field *reflect.Value
		field, err = ngc.findFieldInStruct(&sv, configName)

		if err != nil {
			return fmt.Errorf("problem injecting [%v]: %w", configName, err)
		}

		// inject value
		field.Set(reflect.ValueOf(ngc.v.Get(configName)))
	}
	return err
}

// RegisterFlags adds the flagSet of an engine to the commandline, flag names are prefixed if needed
// The passed command must be the root command not the engine.Cmd (unless they are the same)
func (ngc *NutsGlobalConfig) RegisterFlags(cmd *cobra.Command, e *Engine) {
	if e.FlagSet != nil {
		fs := e.FlagSet

		fs.VisitAll(func(f *pflag.Flag) {
			// prepend with engine.configKey
			if e.ConfigKey != "" && !ngc.isIgnoredPrefix(e.ConfigKey) {
				f.Name = fmt.Sprintf("%s%s%s", e.ConfigKey, ngc.Delimiter, f.Name)
			}

			// add commandline flag
			pf := cmd.PersistentFlags().Lookup(f.Name)
			if pf == nil {
				cmd.PersistentFlags().AddFlag(f)
				pf = f
			}

			// some magic for stuff to get combined
			ngc.v.BindPFlag(f.Name, pf)

			// bind environment variable
			ngc.v.BindEnv(f.Name)
		})
	}
}

func (ngc *NutsGlobalConfig) isIgnoredPrefix(prefix string) bool {
	for _, ip := range ngc.IgnoredPrefixes {
		if ip == prefix {
			return true
		}
	}
	return false
}

// Unmarshal loads config from Env, commandLine and configFile into given struct.
// This call is intended to be used outside of the engine structure of Nuts-go.
// It can be used by the individual repo's, for testing the repo as standalone command.
func (ngc *NutsGlobalConfig) LoadAndUnmarshal(cmd *cobra.Command, targetCfg interface{}) error {
	if err := ngc.Load(cmd); err != nil {
		return err
	}

	return ngc.injectIntoStruct(targetCfg)
}

// configName returns the fully qualified config name including prefixes and delimiter
func (ngc *NutsGlobalConfig) configName(e *Engine, f *pflag.Flag) string {
	if e.ConfigKey == "" {
		return f.Name
	}
	for _, i := range ngc.IgnoredPrefixes {
		if i == e.ConfigKey {
			return f.Name
		}
	}

	// check if flag name already starts with prefix
	if strings.Index(f.Name, e.ConfigKey) == 0 {
		return f.Name
	}

	// add prefix
	return fmt.Sprintf("%s%s%s", e.ConfigKey, ngc.Delimiter, f.Name)
}

func (ngc *NutsGlobalConfig) fieldName(e *Engine, s string) string {
	if e.ConfigKey != "" && !ngc.isIgnoredPrefix(e.ConfigKey) {
		if strings.Index(s, e.ConfigKey) == 0 {
			return s[len(e.ConfigKey)+1:]
		}
	}

	return s
}

// findField returns the Value of the field to inject value into
// it also checks if the Field can be set
// it uses findFieldRecursive to find deeper nested struct fields
func (ngc *NutsGlobalConfig) findField(e *Engine, fieldName string) (*reflect.Value, error) {
	cfgP := reflect.ValueOf(e.Config)

	return ngc.findFieldInStruct(&cfgP, fieldName)
}

// ErrInvalidConfigTarget is an error used for invalid config target pointers
var ErrInvalidConfigTarget = errors.New("only struct pointers are supported to be a config target")

// ErrUnMutableConfigTarget is an error used when a struct member is accessible
var ErrUnMutableConfigTarget = errors.New("given Engine.Config can not be altered")

func (ngc *NutsGlobalConfig) findFieldInStruct(cfgP *reflect.Value, configName string) (*reflect.Value, error) {
	if cfgP.Kind() != reflect.Ptr {
		return nil, ErrInvalidConfigTarget
	}

	s := cfgP.Elem()
	if !s.CanSet() {
		return nil, ErrUnMutableConfigTarget
	}

	spl := strings.Split(configName, ngc.Delimiter)

	return ngc.findFieldRecursive(&s, spl)
}

func (ngc *NutsGlobalConfig) findFieldRecursive(s *reflect.Value, names []string) (*reflect.Value, error) {
	head := names[0]
	tail := names[1:]

	t := strings.Title(head)
	field := s.FieldByName(t)
	switch field.Kind() {
	case reflect.Invalid:
		return nil, fmt.Errorf("inaccessible or invalid field [%v] in %v", t, s.Type())
	case reflect.Struct:
		if len(tail) == 0 {
			return nil, fmt.Errorf("incompatible source/target, trying to set value to struct target: %v to %v", strings.Title(head), field.Type())
		}
		return ngc.findFieldRecursive(&field, tail)
	case reflect.Map:
		return nil, fmt.Errorf("map values not supported in %v", field.Type())
	default:
		if len(tail) > 0 {
			n := fmt.Sprintf("%s.%s", head, strings.Join(tail, "."))
			return nil, fmt.Errorf("incompatible source/target, deeper nested key than target %s", n)
		}
	}

	if !field.CanSet() {
		return nil, fmt.Errorf("field %v can not be Set", t)
	}

	return &field, nil
}
