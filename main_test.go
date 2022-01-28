package main

import (
	"context"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-node/test"
	"github.com/nuts-foundation/nuts-node/test/io"
	"go.uber.org/atomic"
	"io/ioutil"
	"net/http"
	"os"
	"syscall"
	"testing"
	"time"
)

// Test_ServerLifecycle tests the lifecycle of the Nuts node:
// - It starts the Nuts node
// - Waits for the /status endpoint to return HTTP 200, indicating it started properly
// - Sends SIGINT signal
// - Waits for the main function to return
func Test_ServerLifecycle(t *testing.T) {
	testDirectory := io.TestDirectory(t)

	// Collect options
	httpAddress := fmt.Sprintf("localhost:%d", test.FreeTCPPort())
	opts := map[string]string{
		"datadir":                 testDirectory,
		"network.enabletls":       "false",
		"network.grpcaddr":        fmt.Sprintf("localhost:%d", test.FreeTCPPort()),
		"auth.contractvalidators": "dummy", // disables IRMA
		"http.default.address":    httpAddress,
		"events.nats.port":        fmt.Sprintf("%d", test.FreeTCPPort()),
	}
	var optsSlice []string
	for key, value := range opts {
		optsSlice = append(optsSlice, "--"+key+"="+fmt.Sprintf("%s", value))
	}

	os.Args = append([]string{"nuts", "server"}, optsSlice...)
	timeout := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	wasRunning := &atomic.Bool{}

	go func() {
		// Wait for the Nuts node to start, until the given timeout. Check every 100ms
		interval := 100 * time.Millisecond
		attempts := int(timeout / interval)
		address := fmt.Sprintf("http://%s/status", httpAddress)
		for i := 0; i < attempts; i++ {
			if isRunning(address) {
				println("Nuts node running, sending SIGINT signal")
				wasRunning.Store(true)
				syscall.Kill(syscall.Getpid(), syscall.SIGINT)
				break
			}
			time.Sleep(interval)
		}
	}()

	go func() {
		main()
		cancel()
	}()

	// Wait for the main func to exit
	<-ctx.Done()
	if errors.Is(ctx.Err(), context.Canceled) {
		if wasRunning.Load() {
			// Program exited OK
			t.Log("Process successfully started and shut down.")
		} else {
			t.Fatal("Process didn't start properly")
		}
	} else {
		t.Fatalf("Process didn't start and shut down before the time-out expired: %v", ctx.Err())
	}
}

func isRunning(address string) bool {
	response, err := http.Get(address)
	if err != nil {
		println(err.Error())
		return false
	}
	_, _ = ioutil.ReadAll(response.Body)
	return response.StatusCode == http.StatusOK
}
