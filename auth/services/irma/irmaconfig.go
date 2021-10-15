package irma

import (
	"os"

	"github.com/nuts-foundation/nuts-node/auth/log"
	"github.com/sirupsen/logrus"

	"github.com/pkg/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
)

// IrmaMountPath contains location the irma webserver will mount
const IrmaMountPath = "/public/auth/irmaclient"

// GetIrmaConfig creates and returns an IRMA config.
// The config sets the given irma path or a temporary folder. Then it downloads the schemas.
func GetIrmaConfig(validatorConfig ValidatorConfig) (irmaConfig *irma.Configuration, err error) {
	if err = os.MkdirAll(validatorConfig.IrmaConfigPath, 0700); err != nil {
		err = errors.Wrap(err, "could not create IRMA config directory")
		return
	}

	options := irma.ConfigurationOptions{}
	irmaConfig, err = irma.NewConfiguration(validatorConfig.IrmaConfigPath, options)
	if err != nil {
		return
	}

	log.Logger().Debug("Loading IRMA schemas...")
	return irmaConfig, irmaConfig.ParseFolder()
}

// GetIrmaServer creates and starts the irma server instance.
// The server can be used by a IRMA client like the app to handle IRMA sessions
func GetIrmaServer(validatorConfig ValidatorConfig, irmaConfig *irma.Configuration) (*irmaserver.Server, error) {
	logger := log.Logger().Logger
	config := &server.Configuration{
		IrmaConfiguration:    irmaConfig,
		URL:                  validatorConfig.PublicURL + IrmaMountPath,
		Logger:               logger,
		Verbose:              irmaLogLevel(logger),
		SchemesPath:          validatorConfig.IrmaConfigPath,
		DisableSchemesUpdate: !validatorConfig.AutoUpdateIrmaSchemas,
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
