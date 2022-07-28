package cmd

import (
	"bytes"
	"fmt"
	"github.com/google/uuid"
	"github.com/nuts-foundation/nuts-node/core"
	crypto2 "github.com/nuts-foundation/nuts-node/crypto"
	"github.com/nuts-foundation/nuts-node/network"
	storageCmd "github.com/nuts-foundation/nuts-node/storage/cmd"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestCmd_AnalyzeSigners(t *testing.T) {
	os.Setenv("NUTS_DATADIR", io.TestDirectory(t))
	defer os.Unsetenv("NUTS_DATADIR")
	os.Setenv("NUTS_NETWORK_ENABLETLS", "false")
	defer os.Unsetenv("NUTS_NETWORK_ENABLETLS")

	system := core.NewSystem()
	networkInstance, err := registerModule(system)
	if !assert.NoError(t, err) {
		return
	}

	// Load config
	cmd := ServerCmds().Commands()[0]
	cmd.Flags().AddFlagSet(core.FlagSet())
	cmd.Flags().AddFlagSet(storageCmd.FlagSet())
	cmd.Flags().AddFlagSet(FlagSet())
	err = system.Load(cmd.Flags())
	if !assert.NoError(t, err) {
		return
	}

	// Configure and start
	err = system.Configure()
	if !assert.NoError(t, err) {
		return
	}
	err = system.Start()
	if !assert.NoError(t, err) {
		return
	}

	defer system.Shutdown()

	// 4 txs; 1 with attached JWK (unknown signer), 2 from the same signer, and 1 other
	signer1 := crypto2.NewTestKey(fmt.Sprintf("did:nuts:%d#%s", 1, uuid.NewString()))
	signer2 := crypto2.NewTestKey(fmt.Sprintf("did:nuts:%d#%s", 2, uuid.NewString()))
	signer3 := crypto2.NewTestKey(fmt.Sprintf("did:nuts:%d#%s", 3, uuid.NewString()))
	networkInstance.CreateTransaction(network.TransactionTemplate("zfoo/bar", []byte("1"), signer1).WithAttachKey())
	networkInstance.CreateTransaction(network.TransactionTemplate("zfoo/bar", []byte("2"), signer2).WithAttachKey())
	networkInstance.CreateTransaction(network.TransactionTemplate("zfoo/bar", []byte("3"), signer2))
	networkInstance.CreateTransaction(network.TransactionTemplate("zfoo/bar", []byte("4"), signer3).WithAttachKey())
	system.Shutdown()

	t.Run("ok", func(t *testing.T) {
		outBuf := new(bytes.Buffer)
		cmd := ServerCmds()
		cmd.SetOut(outBuf)
		cmd.SetArgs([]string{"analyze", "signers"})

		err := cmd.Execute()
		assert.NoError(t, err)
		out := outBuf.String()
		assert.Contains(t, out, "did:nuts:2 : 2")
		assert.Contains(t, out, "(unknown signer: embedded JWT) : 1")
		assert.Contains(t, out, "did:nuts:3 : 1")
	})
}
