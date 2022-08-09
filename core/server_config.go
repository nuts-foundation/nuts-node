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
	"crypto/tls"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
)

const defaultConfigFile = "nuts.yaml"
const configFileFlag = "configfile"

const defaultPrefix = "NUTS_"
const defaultDelimiter = "."
const configValueListSeparator = ","

// ServerConfig has global server settings.
type ServerConfig struct {
	Verbosity           string           `koanf:"verbosity"`
	LoggerFormat        string           `koanf:"loggerformat"`
	CPUProfile          string           `koanf:"cpuprofile"`
	Strictmode          bool             `koanf:"strictmode"`
	InternalRateLimiter bool             `koanf:"internalratelimiter"`
	Datadir             string           `koanf:"datadir"`
	HTTP                GlobalHTTPConfig `koanf:"http"`
	TLS                 TLSConfig        `koanf:"tls"`
	LegacyTLS           NetworkTLSConfig `koanf:"network"`
	configMap           *koanf.Koanf
}

// TLSConfig specifies how TLS should be configured for connections.
// For v5, network.enabletls, network.truststorefile, network.certfile and network.certkeyfile must be moved to this struct.
type TLSConfig struct {
	// Offload specifies the TLS offloading mode for incoming/outgoing traffic.
	Offload TLSOffloadingMode `koanf:"offload"`
	// ClientCertHeaderName specifies the name of the HTTP header in which the TLS offloader puts the client certificate in.
	// It is required when TLS offloading for incoming traffic is enabled. The client certificate must be in PEM format.
	ClientCertHeaderName string `koanf:"certheader"`
	CertFile             string `koanf:"certfile"`
	CertKeyFile          string `koanf:"certkeyfile"`
	TrustStoreFile       string `koanf:"truststorefile"`
}

func (t TLSConfig) Enabled() bool {
	return (len(t.CertFile) > 0 || len(t.CertKeyFile) > 0) && t.Offload == NoOffloading
}

// Load creates tls.Config from the given configuration. If TLS is disabled or offloaded it returns nil.
func (t TLSConfig) Load() (*tls.Config, error) {
	if !t.Enabled() {
		return nil, nil
	}

	if len(t.CertFile) == 0 || len(t.CertKeyFile) == 0 || len(t.TrustStoreFile) == 0 {
		return nil, errors.New("tls.certfile, tls.certkeyfile and tls.truststorefile must be configured when TLS is enabled")
	}
	certificate, err := tls.LoadX509KeyPair(t.CertFile, t.CertKeyFile)
	if err != nil {
		return nil, err
	}
	trustStore, err := LoadTrustStore(t.TrustStoreFile)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		MinVersion:   MinTLSVersion,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      trustStore.CertPool,
		ClientCAs:    trustStore.CertPool,
	}
	return config, nil
}

// NetworkTLSConfig is temporarily here to support having the network engine's TLS config available to both the network and auth engine.
// This was introduced by https://github.com/nuts-foundation/nuts-node/pull/375 but leads to issues when unmarshalling non-flattened child structs.
// This works for ServerConfig, because Koanf's FlatPaths decoding option is `false` there,
// but for engine config the PR above requires it to be `true`, which leads to different behavior when unmarshalling engine config (v.s. server config).
// It was a bad idea then, and will be fixed by https://github.com/nuts-foundation/nuts-node/pull/1334 because it moves TLS config to the ServerConfig,
// so it can be used by any module requiring TLS. But since we don't want to break backwards compatibility within 1 release,
// this needs to stay here for v5 and be removed in v6.
type NetworkTLSConfig struct {
	Enabled        bool   `koanf:"enabletls"`
	CertFile       string `koanf:"certfile"`
	CertKeyFile    string `koanf:"certkeyfile"`
	TrustStoreFile string `koanf:"truststorefile"`
	// MaxCRLValidityDays defines the number of days a CRL can be outdated, after that it will hard-fail
	MaxCRLValidityDays int `koanf:"maxcrlvaliditydays"`
}

// TLSOffloadingMode defines configurable modes for TLS offloading.
type TLSOffloadingMode string

const (
	// NoOffloading specifies that TLS is not offloaded,
	// meaning incoming and outgoing TLS traffic is terminated at the local node, and not by a proxy inbetween.
	NoOffloading TLSOffloadingMode = ""
	// OffloadIncomingTLS specifies that incoming TLS traffic should be offloaded.
	// It will assume there is a reverse proxy at which TLS is terminated,
	// and which puts the client certificate in PEM format in a configured header.
	OffloadIncomingTLS = "incoming"
)

// GlobalHTTPConfig is the top-level config struct for HTTP interfaces.
type GlobalHTTPConfig struct {
	// HTTPConfig contains the config for the default HTTP interface.
	HTTPConfig `koanf:"default"`
	// AltBinds contains binds for alternative HTTP interfaces. The key of the map is the first part of the path
	// of the URL (e.g. `/internal/some-api` -> `internal`), the value is the HTTP interface it must be bound to.
	AltBinds map[string]HTTPConfig `koanf:"alt"`
}

// HTTPConfig contains configuration for an HTTP interface, e.g. address.
// It will probably contain security related properties in the future (TLS configuration, user/pwd requirements).
type HTTPConfig struct {
	// Address holds the interface address the HTTP service must be bound to, in the format of `interface:port` (e.g. localhost:5555).
	Address string `koanf:"address"`
	// CORS holds the configuration for Cross Origin Resource Sharing.
	CORS HTTPCORSConfig `koanf:"cors"`
	// TLSMode specifies whether TLS is enabled for this interface, and which flavor.
	TLSMode HTTPTLSMode `koanf:"tls"`
}

// HTTPTLSMode defines the values for TLS modes
type HTTPTLSMode string

const (
	DisabledHTTPTLSMode HTTPTLSMode = "disabled"
	ServerCertTLSMode               = "server-cert"
	MutualTLSMode                   = "server-and-client-cert"
)

// HTTPCORSConfig contains configuration for Cross Origin Resource Sharing.
type HTTPCORSConfig struct {
	// Origin specifies the AllowOrigin option. If no origins are given CORS is considered to be disabled.
	Origin []string `koanf:"origin"`
}

// Enabled returns whether CORS is enabled according to this configuration.
func (cors HTTPCORSConfig) Enabled() bool {
	return len(cors.Origin) > 0
}

// NewServerConfig creates an initialized empty server config
func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		configMap: koanf.New(defaultDelimiter),
		HTTP: GlobalHTTPConfig{
			HTTPConfig: HTTPConfig{},
			AltBinds:   map[string]HTTPConfig{},
		},
	}
}

// loadConfigMap populates the configMap with values from the config file, environment and pFlags
func (ngc *ServerConfig) loadConfigMap(flags *pflag.FlagSet) error {
	if err := loadDefaultsFromFlagset(ngc.configMap, flags); err != nil {
		return err
	}

	if err := loadFromFile(ngc.configMap, resolveConfigFilePath(flags)); err != nil {
		return err
	}

	if err := loadFromEnv(ngc.configMap); err != nil {
		return err
	}

	if err := loadFromFlagSet(ngc.configMap, flags); err != nil {
		return err
	}

	return nil
}

// Load loads the server config  follows the load order of configfile, env vars and then commandline param
func (ngc *ServerConfig) Load(flags *pflag.FlagSet) (err error) {
	if err := ngc.loadConfigMap(flags); err != nil {
		return err
	}

	if err := ngc.configMap.UnmarshalWithConf("", ngc, koanf.UnmarshalConf{
		FlatPaths: false,
	}); err != nil {
		return err
	}

	// Configure logging.
	// TODO: see #40
	lvl, err := logrus.ParseLevel(ngc.Verbosity)
	if err != nil {
		return err
	}
	logrus.SetLevel(lvl)

	switch ngc.LoggerFormat {
	case "text":
		logrus.SetFormatter(&logrus.TextFormatter{})
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{})
	default:
		return fmt.Errorf("invalid formatter: '%s'", ngc.LoggerFormat)
	}

	return nil
}

// resolveConfigFilePath resolves the path of the config file using the following sources:
// 1. commandline params (using the given flags)
// 2. environment vars,
// 3. default location.
func resolveConfigFilePath(flags *pflag.FlagSet) string {
	k := koanf.New(defaultDelimiter)

	// load env flags
	e := env.Provider(defaultPrefix, defaultDelimiter, func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, defaultPrefix)), "_", defaultDelimiter, -1)
	})
	// can't return error
	_ = k.Load(e, nil)

	// load cmd flags, without a parser, no error can be returned
	// this also loads the default flag value of nuts.yaml. So we need a way to know if it's overiden.
	_ = k.Load(posflag.Provider(flags, defaultDelimiter, k), nil)

	return k.String(configFileFlag)
}

// FlagSet returns the default server flags
func FlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("server", pflag.ContinueOnError)
	flagSet.String(configFileFlag, defaultConfigFile, "Nuts config file")
	flagSet.String("cpuprofile", "", "When set, a CPU profile is written to the given path. Ignored when strictmode is set.")
	flagSet.String("verbosity", "info", "Log level (trace, debug, info, warn, error)")
	flagSet.String("loggerformat", "text", "Log format (text, json)")
	flagSet.String("http.default.address", ":1323", "Address and port the server will be listening to")
	flagSet.String("http.default.tls", string(DisabledHTTPTLSMode), fmt.Sprintf("Whether to enable TLS for the default interface (options are `%s`, `%s`, `%s`).", DisabledHTTPTLSMode, ServerCertTLSMode, MutualTLSMode))
	flagSet.Bool("strictmode", false, "When set, insecure settings are forbidden.")
	flagSet.Bool("internalratelimiter", true, "When set, expensive internal calls are rate-limited to protect the network. Always enabled in strict mode.")
	flagSet.String("datadir", "./data", "Directory where the node stores its files.")
	flagSet.StringSlice("http.default.cors.origin", nil, "When set, enables CORS from the specified origins for the on default HTTP interface.")
	flagSet.String("tls.certfile", "", "PEM file containing the certificate for the server (also used as client certificate). Required when `network.enabletls` is `true`.")
	flagSet.String("tls.certkeyfile", "", "PEM file containing the private key of the server certificate. Required when `tls.enable` is `true`.")
	flagSet.String("tls.truststorefile", "truststore.pem", "PEM file containing the trusted CA certificates for authenticating remote servers.")
	flagSet.String("tls.offload", "", "Whether to enable TLS offloading for incoming connections. If enabled `tls.certheader` must be configured as well.")
	flagSet.String("tls.certheader", "", "Name of the HTTP header that will contain the client certificate when TLS is offloaded.")
	// Legacy TLS settings, to be removed in v6:
	flagSet.Bool("network.enabletls", true, "Whether to enable TLS for gRPC connections, which can be disabled for demo/development purposes. It is NOT meant for TLS offloading (see `tls.offload`). Disabling TLS is not allowed in strict-mode.")
	flagSet.String("network.certfile", "", "Deprecated: use `tls.certfile`. PEM file containing the server certificate for the gRPC server. "+
		"Required when `network.enabletls` is `true`.")
	flagSet.String("network.certkeyfile", "", "Deprecated: use `tls.certkeyfile`. PEM file containing the private key of the server certificate. "+
		"Required when `network.enabletls` is `true`.")
	flagSet.String("network.truststorefile", "", "Deprecated: use `tls.truststorefile`. PEM file containing the trusted CA certificates for authenticating remote gRPC servers.")

	return flagSet
}

// PrintConfig return the current config in string form
func (ngc *ServerConfig) PrintConfig() string {
	return ngc.configMap.Sprint()
}

// InjectIntoEngine takes the loaded config and sets the engine's config struct
func (ngc *ServerConfig) InjectIntoEngine(e Injectable) error {
	return unmarshalRecursive([]string{strings.ToLower(e.Name())}, e.Config(), ngc.configMap)
}

func elemType(ty reflect.Type) (reflect.Type, bool) {
	isPtr := ty.Kind() == reflect.Ptr

	if isPtr {
		return ty.Elem(), true
	}

	return ty, false
}

func unmarshalRecursive(path []string, config interface{}, configMap *koanf.Koanf) error {
	decoderConfig := koanf.UnmarshalConf{
		FlatPaths: false,
	}
	if err := configMap.UnmarshalWithConf(strings.Join(path, "."), config, decoderConfig); err != nil {
		return err
	}

	configType, isPtr := elemType(reflect.TypeOf(config))

	// If `config` is a struct or a pointer to a struct we're iterating its fields to find structs
	if configType.Kind() == reflect.Struct {
		valueOfConfig := reflect.ValueOf(config)

		if isPtr {
			valueOfConfig = valueOfConfig.Elem()
		}

		for i := 0; i < configType.NumField(); i++ {
			field := configType.Field(i)
			fieldType, _ := elemType(field.Type)
			tagValue := field.Tag.Get("koanf")

			// Unmarshal this field if it's a struct, and it has a `koanf` tag
			if (fieldType.Kind() == reflect.Struct || fieldType.Kind() == reflect.Map) &&
				tagValue != "" {
				fieldAddr := valueOfConfig.Field(i).Addr()

				if err := unmarshalRecursive(append(path, tagValue), fieldAddr.Interface(), configMap); err != nil {
					return err
				}
			}
		}
	}

	return nil
}
