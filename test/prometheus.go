package test

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"testing"
)

func PrometheusStats(t *testing.T) string {
	fileName := path.Join(t.TempDir(), "prometheus.txt")
	err := prometheus.WriteToTextfile(fileName, prometheus.Gatherers{prometheus.DefaultGatherer})
	require.NoError(t, err)
	data, err := os.ReadFile(fileName)
	require.NoError(t, err)
	return string(data)
}
