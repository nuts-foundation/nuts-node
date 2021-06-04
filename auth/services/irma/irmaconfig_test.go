package irma

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetIrmaServer(t *testing.T) {
	validatorConfig := ValidatorConfig{
		IrmaConfigPath:        "../../../development/irma",
		IrmaSchemeManager:     "empty",
		AutoUpdateIrmaSchemas: false,
	}

	t.Run("when the config in initialized, the server can be fetched", func(t *testing.T) {
		irmaConfig, err := GetIrmaConfig(validatorConfig)
		if !assert.NoError(t, err) {
			return
		}
		irmaServer, err := GetIrmaServer(validatorConfig, irmaConfig)
		if !assert.NoError(t, err) {
			return
		}
		assert.NotNil(t, irmaServer, "expected an IRMA server instance")
	})
}

func TestIrmaLogLevel(t *testing.T) {
	assert.Equal(t, 0, irmaLogLevel(&logrus.Logger{Level: logrus.InfoLevel}))
	assert.Equal(t, 1, irmaLogLevel(&logrus.Logger{Level: logrus.DebugLevel}))
	assert.Equal(t, 2, irmaLogLevel(&logrus.Logger{Level: logrus.TraceLevel}))
}
