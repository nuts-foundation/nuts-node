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
	"fmt"
	"github.com/knadh/koanf"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/posflag"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"reflect"
	"strings"

	pkiconfig "github.com/nuts-foundation/nuts-node/pki/config"
)

const defaultConfigFile = "nuts.yaml"
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
}

// ServerConfig has global server settings.
type ServerConfig struct {
	Verbosity           string             `koanf:"verbosity"`
	LoggerFormat        string             `koanf:"loggerformat"`
	CPUProfile          string             `koanf:"cpuprofile"`
	Strictmode          bool               `koanf:"strictmode"`
	InternalRateLimiter bool               `koanf:"internalratelimiter"`
	Datadir             string             `koanf:"datadir"`
	PKI                 pkiconfig.Config   `koanf:"pki"`
	TLS                 TLSConfig          `koanf:"tls"`
	LegacyTLS           *NetworkTLSConfig  `koanf:"network"`
	Auth                AuthEndpointConfig `koanf:"auth"`
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
	legacyTLS            *NetworkTLSConfig
}

// Enabled returns whether TLS should be enabled, according to the global config.
func (t TLSConfig) Enabled() bool {
	return len(t.CertFile) > 0 || len(t.CertKeyFile) > 0 ||
		len(t.legacyTLS.CertFile) > 0 || len(t.legacyTLS.CertKeyFile) > 0
}

// LoadCertificate loads the TLS certificate from the configured location.
func (t TLSConfig) LoadCertificate() (tls.Certificate, error) {
	var certFile, certKeyFile string
	if len(t.legacyTLS.CertFile) > 0 {
		logrus.Warn("Deprecated: use `tls.certfile` instead of `network.certfile`")
		certFile = t.legacyTLS.CertFile
	} else {
		certFile = t.CertFile
	}
	if len(t.legacyTLS.CertKeyFile) > 0 {
		logrus.Warn("Deprecated: use `tls.certkeyfile` instead of `network.certkeyfile`")
		certKeyFile = t.legacyTLS.CertKeyFile
	} else {
		certKeyFile = t.CertKeyFile
	}
	certificate, err := tls.LoadX509KeyPair(certFile, certKeyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("unable to load node TLS certificate (certfile=%s,certkeyfile=%s): %w", certFile, certKeyFile, err)
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	return certificate, nil
}

// LoadTrustStore loads the TLS trust store from the configured location.
func (t TLSConfig) LoadTrustStore() (*TrustStore, error) {
	var trustStoreFile string
	if len(t.legacyTLS.TrustStoreFile) > 0 {
		logrus.Warn("Deprecated: use `tls.truststorefile` instead of `network.truststorefile`")
		trustStoreFile = t.legacyTLS.TrustStoreFile
	} else {
		trustStoreFile = t.TrustStoreFile
	}
	return LoadTrustStore(trustStoreFile)
}

// Load creates tls.Config from the given configuration. If TLS is disabled it returns nil.
func (t TLSConfig) Load() (*tls.Config, error) {
	if !t.Enabled() {
		return nil, nil
	}

	certificate, err := t.LoadCertificate()
	if err != nil {
		return nil, err
	}
	trustStore, err := t.LoadTrustStore()
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
}

// AuthEndpointConfig is temporarily here so VCR's OIDC4VCI can use the configured auth.publicurl as Wallet/Issuer identifier.
// This should probably be moved to VCR config, but we need to decide whether the protocol should really be part of VCR.
type AuthEndpointConfig struct {
	PublicURL string `koanf:"publicurl"`
}

func (c AuthEndpointConfig) PublicURLWithTrailingSlash() string {
	return strings.TrimSuffix(c.PublicURL, "/") + "/"
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
	legacyTLS := &NetworkTLSConfig{}
	return &ServerConfig{
		configMap: koanf.New(defaultDelimiter),
		LegacyTLS: legacyTLS,
		TLS: TLSConfig{
			legacyTLS: legacyTLS,
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
	flagSet.String(configFileFlag, defaultConfigFile, "Nuts config file")
	flagSet.String("cpuprofile", "", "When set, a CPU profile is written to the given path. Ignored when strictmode is set.")
	flagSet.String("verbosity", "info", "Log level (trace, debug, info, warn, error)")
	flagSet.String("loggerformat", "text", "Log format (text, json)")
	flagSet.Bool("strictmode", true, "When set, insecure settings are forbidden.")
	flagSet.Bool("internalratelimiter", true, "When set, expensive internal calls are rate-limited to protect the network. Always enabled in strict mode.")
	flagSet.String("datadir", "./data", "Directory where the node stores its files.")
	flagSet.String("tls.certfile", "", "PEM file containing the certificate for the server (also used as client certificate).")
	flagSet.String("tls.certkeyfile", "", "PEM file containing the private key of the server certificate.")
	flagSet.String("tls.truststorefile", "truststore.pem", "PEM file containing the trusted CA certificates for authenticating remote servers.")
	flagSet.String("tls.offload", string(NoOffloading), fmt.Sprintf("Whether to enable TLS offloading for incoming connections. "+
		"Enable by setting it to '%s'. If enabled 'tls.certheader' must be configured as well.", OffloadIncomingTLS))
	flagSet.String("tls.certheader", "", "Name of the HTTP header that will contain the client certificate when TLS is offloaded.")

	// Maxvaliditydays has been deprecated in v5.x
	flagSet.Int("tls.crl.maxvaliditydays", 0, "The number of days a CRL can be outdated, after that it will hard-fail.")
	// Legacy TLS settings, to be removed in v6:
	flagSet.Bool("network.enabletls", true, "Whether to enable TLS for gRPC connections, which can be disabled for demo/development purposes. It is NOT meant for TLS offloading (see 'tls.offload'). Disabling TLS is not allowed in strict-mode.")
	flagSet.String("network.certfile", "", "Deprecated: use 'tls.certfile'. PEM file containing the server certificate for the gRPC server. "+
		"Required when 'network.enabletls' is 'true'.")
	flagSet.String("network.certkeyfile", "", "Deprecated: use 'tls.certkeyfile'. PEM file containing the private key of the server certificate. "+
		"Required when 'network.enabletls' is 'true'.")
	flagSet.String("network.truststorefile", "", "Deprecated: use 'tls.truststorefile'. PEM file containing the trusted CA certificates for authenticating remote gRPC servers.")
	flagSet.Int("network.maxcrlvaliditydays", 0, "Deprecated: use 'tls.crl.maxvaliditydays'. The number of days a CRL can be outdated, after that it will hard-fail.")

	// Flags for denylist features
	flagSet.Int("pki.maxupdatefailhours", 4, "maximum number of hours that a denylist update can fail")
	// TODO: Choose a default trusted signer key
	flagSet.String("pki.denylist.trustedsigner", "", "Ed25519 public key (in PEM format) of the trusted signer for denylists")
	// TODO: Choose a default denylist URL
	flagSet.String("pki.denylist.url", "", "URL of PKI denylist (set to empty string to disable)")

	// Changing these config values is not recommended, and they are expected to almost always be the same value, so
	// do not show them in the config dump
	flagSet.MarkHidden("pki.denylist.trustedsigner")
	flagSet.MarkHidden("pki.denylist.url")

	flagSet.MarkDeprecated("tls.crl.maxvaliditydays", "CRLs can no longer be accepted after the time in NextUpdate has past")
	flagSet.MarkDeprecated("network.certfile", "use 'tls.certfile' instead")
	flagSet.MarkDeprecated("network.certkeyfile", "use 'tls.certkeyfile' instead")
	flagSet.MarkDeprecated("network.truststorefile", "use 'tls.truststorefile' instead")
	flagSet.MarkDeprecated("network.maxcrlvaliditydays", "use 'tls.crl.maxvaliditydays' instead")

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
