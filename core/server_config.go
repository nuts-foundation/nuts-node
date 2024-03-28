/*
 * Nuts node
 * Copyright (C) 2023 Nuts community
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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"net/url"
	"reflect"
	"strings"
	"time"
)

const defaultConfigFile = "./config/nuts.yaml"
const configFileFlag = "configfile"

const defaultEnvPrefix = "NUTS_"
const defaultEnvDelimiter = "_"
const defaultDelimiter = "."
const configValueListSeparator = ","

// redactedConfigKeys contains the configuration keys that are masked when logged, to avoid leaking secrets.
var redactedConfigKeys = []string{
	"crypto.vault.token",
	"storage.redis.password",
	"storage.redis.sentinel.password",
	"storage.sql.connection",
}

// ServerConfig has global server settings.
type ServerConfig struct {
	// URL contains the base URL for public-facing HTTP services.
	URL                 string           `koanf:"url"`
	Verbosity           string           `koanf:"verbosity"`
	LoggerFormat        string           `koanf:"loggerformat"`
	CPUProfile          string           `koanf:"cpuprofile"`
	Strictmode          bool             `koanf:"strictmode"`
	InternalRateLimiter bool             `koanf:"internalratelimiter"`
	Datadir             string           `koanf:"datadir"`
	HTTPClient          HTTPClientConfig `koanf:"httpclient"`
	TLS                 TLSConfig        `koanf:"tls"`
	// LegacyTLS exists to detect usage of deprecated network.{truststorefile,certkeyfile,certfile} parameters.
	// This can be removed in v6.1+ (can't skip minors in migration). See https://github.com/nuts-foundation/nuts-node/issues/2909
	LegacyTLS TLSConfig `koanf:"network"`
	configMap *koanf.Koanf
}

// HTTPClientConfig contains settings for HTTP clients.
type HTTPClientConfig struct {
	// Timeout specifies the timeout for HTTP requests.
	Timeout time.Duration `koanf:"timeout"`
}

// TLSConfig specifies how TLS should be configured for connections.
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

// Enabled returns whether TLS should be enabled, according to the global config.
func (t TLSConfig) Enabled() bool {
	return len(t.CertFile) > 0 || len(t.CertKeyFile) > 0
}

// LoadCertificate loads the TLS certificate from the configured location.
func (t TLSConfig) LoadCertificate() (tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(t.CertFile, t.CertKeyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("unable to load node TLS certificate (certfile=%s,certkeyfile=%s): %w", t.CertFile, t.CertKeyFile, err)
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	return certificate, nil
}

// LoadTrustStore loads the TLS trust store from the configured location.
func (t TLSConfig) LoadTrustStore() (*TrustStore, error) {
	return LoadTrustStore(t.TrustStoreFile)
}

// Load creates tls.Config from the given configuration. If TLS is disabled it returns nil.
func (t TLSConfig) Load() (*tls.Config, *TrustStore, error) {
	if !t.Enabled() {
		return nil, nil, nil
	}

	certificate, err := t.LoadCertificate()
	if err != nil {
		return nil, nil, err
	}
	trustStore, err := t.LoadTrustStore()
	if err != nil {
		return nil, nil, err
	}
	config := &tls.Config{
		MinVersion:   MinTLSVersion,
		Certificates: []tls.Certificate{certificate},
		RootCAs:      trustStore.CertPool,
		ClientCAs:    trustStore.CertPool,
	}
	return config, trustStore, nil
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

// NewServerConfig creates an initialized empty server config
func NewServerConfig() *ServerConfig {
	return &ServerConfig{
		configMap:           koanf.New(defaultDelimiter),
		LoggerFormat:        "text",
		Verbosity:           "info",
		Strictmode:          true,
		InternalRateLimiter: true,
		Datadir:             "./data",
		TLS: TLSConfig{
			TrustStoreFile: "./config/ssl/truststore.pem",
			Offload:        NoOffloading,
		},
		HTTPClient: HTTPClientConfig{
			Timeout: 30 * time.Second,
		},
	}
}

// loadConfigMap populates the configMap with values from the defaults < config file < environment < cli
func (ngc *ServerConfig) loadConfigMap(flags *pflag.FlagSet) error {
	if err := loadFromFile(ngc.configMap, resolveConfigFilePath(flags)); err != nil {
		return err
	}

	if err := loadFromEnv(ngc.configMap); err != nil {
		return err
	}

	// Besides CLI, also sets default values for flags not yet set in the configMap.
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

	if err := loadConfigIntoStruct(ngc, ngc.configMap); err != nil {
		return err
	}

	if ngc.LegacyTLS.TrustStoreFile != "" || ngc.LegacyTLS.CertKeyFile != "" || ngc.LegacyTLS.CertFile != "" {
		return errors.New("invalid config parameter(s): network.{truststorefile,certkeyfile,certfile} have moved to tls.{...}")
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
	e := env.Provider(defaultEnvPrefix, defaultDelimiter, func(s string) string {
		return strings.Replace(strings.ToLower(
			strings.TrimPrefix(s, defaultEnvPrefix)), defaultEnvDelimiter, defaultDelimiter, -1)
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
	defaultCfg := NewServerConfig()

	flagSet.String(configFileFlag, defaultConfigFile, "Nuts config file")
	flagSet.String("cpuprofile", "", "When set, a CPU profile is written to the given path. Ignored when strictmode is set.")
	flagSet.String("verbosity", defaultCfg.Verbosity, "Log level (trace, debug, info, warn, error)")
	flagSet.String("loggerformat", defaultCfg.LoggerFormat, "Log format (text, json)")
	flagSet.Bool("strictmode", defaultCfg.Strictmode, "When set, insecure settings are forbidden.")
	flagSet.Bool("internalratelimiter", defaultCfg.InternalRateLimiter, "When set, expensive internal calls are rate-limited to protect the network. Always enabled in strict mode.")
	flagSet.String("datadir", defaultCfg.Datadir, "Directory where the node stores its files.")
	flagSet.String("url", defaultCfg.URL, "Public facing URL of the server (required). Must be HTTPS when strictmode is set.")
	flagSet.Duration("httpclient.timeout", defaultCfg.HTTPClient.Timeout, "Request time-out for HTTP clients, such as '10s'. Refer to Golang's 'time.Duration' syntax for a more elaborate description of the syntax.")
	flagSet.String("tls.certfile", defaultCfg.TLS.CertFile, "PEM file containing the certificate for the gRPC server (also used as client certificate). Required in strict mode.")
	flagSet.String("tls.certkeyfile", defaultCfg.TLS.CertKeyFile, "PEM file containing the private key of the gRPC server certificate. Required in strict mode.")
	flagSet.String("tls.truststorefile", defaultCfg.TLS.TrustStoreFile, "PEM file containing the trusted CA certificates for authenticating remote gRPC servers. Required in strict mode.")
	flagSet.String("tls.offload", string(defaultCfg.TLS.Offload), fmt.Sprintf("Whether to enable TLS offloading for incoming gRPC connections. "+
		"Enable by setting it to '%s'. If enabled 'tls.certheader' must be configured as well.", OffloadIncomingTLS))
	flagSet.String("tls.certheader", defaultCfg.TLS.ClientCertHeaderName, "Name of the HTTP header that will contain the client certificate when TLS is offloaded for gRPC.")

	return flagSet
}

// PrintConfig return the current config in string form
func (ngc *ServerConfig) PrintConfig() string {
	redacted := func(k string) bool {
		for _, key := range redactedConfigKeys {
			if key == k {
				return true
			}
		}
		return false
	}
	buf := bytes.Buffer{}
	for _, key := range ngc.configMap.Keys() {
		value := ngc.configMap.Get(key)
		if redacted(key) {
			value = "(redacted)"
		}
		// Copied from Koanf.ConfigMap.Sprint()
		buf.Write([]byte(fmt.Sprintf("%s -> %v\n", key, value)))
	}
	return buf.String()
}

// InjectIntoEngine takes the loaded config and sets the engine's config struct
func (ngc *ServerConfig) InjectIntoEngine(e Injectable) error {
	return unmarshalRecursive([]string{strings.ToLower(e.Name())}, e.Config(), ngc.configMap)
}

// ServerURL returns the parsed URL of the server
func (ngc *ServerConfig) ServerURL() (*url.URL, error) {
	// Validate server URL
	if ngc.URL == "" {
		return nil, errors.New("'url' must be configured")
	}
	result, err := ParsePublicURL(ngc.URL, ngc.Strictmode)
	if err != nil {
		return nil, fmt.Errorf("invalid 'url': %w", err)
	}
	return result, nil
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
