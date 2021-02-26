package irma

import (
	"fmt"
	"os"
	"sync"

	"github.com/nuts-foundation/nuts-node/auth/logging"

	"github.com/pkg/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
)

// IrmaMountPath contains location the irma webserver will mount
const IrmaMountPath = "/auth/irmaclient"

// create a singleton irma config
var _irmaConfig *irma.Configuration
var configOnce = new(sync.Once)

// create a singleton irma server
var _irmaServer *irmaserver.Server
var serverOnce = new(sync.Once)

// GetIrmaConfig creates and returns an IRMA config.
// The config sets the given irma path or a temporary folder. Then it downloads the schemas.
func GetIrmaConfig(validatorConfig ValidatorConfig) (irmaConfig *irma.Configuration, err error) {
	irmaConfig = _irmaConfig

	configOnce.Do(func() {
		if err = os.MkdirAll(validatorConfig.IrmaConfigPath, 0700); err != nil {
			err = errors.Wrap(err, "could not create IRMA config directory")
			return
		}

		options := irma.ConfigurationOptions{}
		irmaConfig, err = irma.NewConfiguration(validatorConfig.IrmaConfigPath, options)
		if err != nil {
			return
		}

		logging.Log().Info("Loading IRMA schemas...")
		err = irmaConfig.ParseFolder()
		_irmaConfig = irmaConfig
	})
	return
}

// GetIrmaServer creates and starts the irma server instance.
// The server can be used by a IRMA client like the app to handle IRMA sessions
func GetIrmaServer(validatorConfig ValidatorConfig) (irmaServer *irmaserver.Server, err error) {
	irmaServer = _irmaServer

	serverOnce.Do(func() {
		irmaConfig, err := GetIrmaConfig(validatorConfig)
		if err != nil {
			return
		}
		config := &server.Configuration{
			IrmaConfiguration:    irmaConfig,
			URL:                  fmt.Sprintf("%s"+IrmaMountPath, validatorConfig.PublicURL),
			Logger:               logging.Log().Logger,
			SchemesPath:          validatorConfig.IrmaConfigPath,
			DisableSchemesUpdate: !validatorConfig.AutoUpdateIrmaSchemas,
		}

		logging.Log().Infof("Initializing IRMA library (baseURL=%s)...", config.URL)

		irmaServer, err = irmaserver.New(config)
		_irmaServer = irmaServer
	})

	return
}
