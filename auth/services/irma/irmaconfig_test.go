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
	"github.com/stretchr/testify/require"
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
		require.NoError(t, err)
		irmaServer, err := GetIrmaServer(validatorConfig, irmaConfig)
		require.NoError(t, err)
		assert.NotNil(t, irmaServer, "expected an IRMA server instance")
	})
}

func TestIrmaLogLevel(t *testing.T) {
	assert.Equal(t, 0, irmaLogLevel(&logrus.Logger{Level: logrus.InfoLevel}))
	assert.Equal(t, 1, irmaLogLevel(&logrus.Logger{Level: logrus.DebugLevel}))
	assert.Equal(t, 2, irmaLogLevel(&logrus.Logger{Level: logrus.TraceLevel}))
}
