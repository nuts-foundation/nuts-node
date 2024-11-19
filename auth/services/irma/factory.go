/*
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

package irma

import (
	"fmt"
	"github.com/nuts-foundation/nuts-node/auth/contract"
	"os"
	"path/filepath"

	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/sirupsen/logrus"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
)

// IrmaMountPath contains location the irma webserver will mount
const IrmaMountPath = "/public/auth/irmaclient"

// Config holds the configuration for the irma server.
type Config struct {
	// PublicURL is used for discovery for the IRMA app.
	PublicURL string
	// Where to find the IrmaConfig files including the schemas
	IrmaConfigPath string
	// Which scheme manager to use
	IrmaSchemeManager string
	// Auto update the schemas every x minutes or not?
	AutoUpdateIrmaSchemas bool
	// Use the IRMA server in production mode. Without this the IRMA app needs to be in "developer mode"
	// https://irma.app/docs/irma-app/#developer-mode
	Production bool
	// CORS configuration
	CORSOrigin []string
}

// NewSignerAndVerifier creates a new IRMA signer and verifier.
func NewSignerAndVerifier(cfg Config) (*Signer, *Verifier, error) {
	irmaConfig, err := getIrmaConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	irmaServer, err := getIrmaServer(cfg, irmaConfig)
	if err != nil {
		return nil, nil, err
	}

	return &Signer{
			sessionHandler: irmaServer,
			schemeManager:  cfg.IrmaSchemeManager,
			cors:           cfg.CORSOrigin,
		}, &Verifier{
			IrmaConfig: irmaConfig,
			Templates:  contract.StandardContractTemplates,
		}, nil
}

// getIrmaConfig creates and returns an IRMA config.
// The config sets the given irma path or a temporary folder. Then it downloads the schemas.
func getIrmaConfig(cfg Config) (irmaConfig *irma.Configuration, err error) {
	if err = os.MkdirAll(cfg.IrmaConfigPath, 0700); err != nil {
		err = fmt.Errorf("could not create IRMA config directory: %w", err)
		return
	}

	options := irma.ConfigurationOptions{}
	irmaConfig, err = irma.NewConfiguration(cfg.IrmaConfigPath, options)
	if err != nil {
		return
	}

	// This fixes an IRMA bug https://github.com/privacybydesign/irmago/issues/139
	// It removes any temporary "tempscheme123" directories, leftover from a previous unfinished schema update.
	dirs, err := filepath.Glob(filepath.Join(cfg.IrmaConfigPath, "tempscheme*"))
	if err != nil {
		return nil, err
	}
	for _, dir := range dirs {
		log.Logger().Infof("Removing leftover temporary IRMA scheme dir: %s", dir)
		// ignore any errors, it will fail below
		_ = os.RemoveAll(dir)
	}

	log.Logger().Debug("Loading IRMA schemas...")
	if err = irmaConfig.ParseFolder(); err != nil {
		log.Logger().WithError(err).Error("Could not parse the IRMA schemas, try emptying the IRMA directory and restart the node.")
		return nil, err
	}
	return
}

// getIrmaServer creates and starts the irma server instance.
// The server can be used by a IRMA client like the app to handle IRMA sessions
func getIrmaServer(cfg Config, irmaConfig *irma.Configuration) (*irmaserver.Server, error) {
	// Customize logger to have it clearly log "IRMA" in module field.
	// We need a decorator because IRMA config takes a logrus.Logger instead of logrus.Entry
	logger := *logrus.StandardLogger()
	formatter := logger.Formatter
	logger.Formatter = &decoratingFormatter{
		formatter: formatter,
		decorator: func(entry *logrus.Entry) *logrus.Entry {
			entry.Data["module"] = "Auth/IRMA"
			return entry
		},
	}

	config := &server.Configuration{
		IrmaConfiguration:    irmaConfig,
		URL:                  cfg.PublicURL + IrmaMountPath,
		Logger:               &logger,
		Verbose:              irmaLogLevel(&logger),
		SchemesPath:          cfg.IrmaConfigPath,
		DisableSchemesUpdate: !cfg.AutoUpdateIrmaSchemas,
		Production:           cfg.Production,
	}

	log.Logger().Debugf("Initializing IRMA library (baseURL=%s)...", config.URL)

	return irmaserver.New(config)
}

// irmaLogLevel returns the IRMA log level. 0 is normal, 1 includes DEBUG level, 2 includes TRACE level
func irmaLogLevel(logger *logrus.Logger) int {
	switch logger.Level {
	case logrus.DebugLevel:
		return 1
	case logrus.TraceLevel:
		return 2
	default:
		return 0
	}
}

type decoratingFormatter struct {
	formatter logrus.Formatter
	decorator func(entry *logrus.Entry) *logrus.Entry
}

func (f decoratingFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	return f.formatter.Format(f.decorator(entry))
}
