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
func GetIrmaConfig(config ValidatorConfig) (irmaConfig *irma.Configuration, err error) {
	irmaConfig = _irmaConfig

	configOnce.Do(func() {
		var configDir string
		configDir, err = irmaConfigDir(config)
		if err != nil {
			return
		}

		options := irma.ConfigurationOptions{}
		irmaConfig, err = irma.NewConfiguration(configDir, options)
		if err != nil {
			return
		}

		logging.Log().Info("Loading IRMA schemas...")
		if err = irmaConfig.ParseFolder(); err != nil {
			return
		}
		_irmaConfig = irmaConfig
	})
	return
}

// GetIrmaServer creates and starts the irma server instance.
// The server can be used by a IRMA client like the app to handle IRMA sessions
func GetIrmaServer(config ValidatorConfig) (irmaServer *irmaserver.Server, err error) {
	irmaServer = _irmaServer

	serverOnce.Do(func() {
		baseURL := config.PublicURL

		var configDir string
		configDir, err = irmaConfigDir(config)
		if err != nil {
			return
		}

		irmaConfig, err := GetIrmaConfig(config)
		if err != nil {
			return
		}
		config := &server.Configuration{
			IrmaConfiguration:    irmaConfig,
			URL:                  fmt.Sprintf("%s"+IrmaMountPath, baseURL),
			Logger:               logging.Log().Logger,
			SchemesPath:          configDir,
			DisableSchemesUpdate: !config.AutoUpdateIrmaSchemas,
		}

		logging.Log().Infof("Initializing IRMA library (baseURL=%s)...", config.URL)

		irmaServer, err = irmaserver.New(config)
		if err != nil {
			return
		}
		_irmaServer = irmaServer
	})

	return
}

func irmaConfigDir(config ValidatorConfig) (string, error) {
	path := config.IrmaConfigPath
	if err := ensureDirectoryExists(path); err != nil {
		return "", errors.Wrap(err, "could not create irma config directory")
	}
	return path, nil
}

// PathExists checks if the specified path exists.
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func ensureDirectoryExists(path string) error {
	exists, err := pathExists(path)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return os.MkdirAll(path, 0700)
}
