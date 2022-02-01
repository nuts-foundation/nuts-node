package test

import (
	"fmt"
	"path"
)

func GetIntegrationTestConfig(testDirectory string) map[string]string {
	httpAddress := fmt.Sprintf("localhost:%d", FreeTCPPort())
	return map[string]string{
		"configfile":              path.Join(testDirectory, "nuts.yaml"), // does not exist, but that's okay: default config
		"datadir":                 testDirectory,
		"network.enabletls":       "false",
		"network.grpcaddr":        fmt.Sprintf("localhost:%d", FreeTCPPort()),
		"auth.contractvalidators": "dummy", // disables IRMA
		"http.default.address":    httpAddress,
		"events.nats.port":        fmt.Sprintf("%d", FreeTCPPort()),
	}
}
