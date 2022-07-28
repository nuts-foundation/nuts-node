package cmd

import (
	"bytes"
	"context"
	"github.com/nuts-foundation/nuts-node/core"
	"github.com/nuts-foundation/nuts-node/network/dag"
	"github.com/nuts-foundation/nuts-node/test/io"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestCmd_Analyze(t *testing.T) {
	// 4 txs; 1 with attached JWK (unknown signer), 2 from the same signer, and 1 other
	t1 := dag.CreateSignedTestTransaction(1, time.Now().Add(time.Duration(0)*time.Second), nil, "zfoo/bar", true)
	t2 := dag.CreateSignedTestTransaction(2, time.Now().Add(time.Duration(60)*time.Second), nil, "bar/foo", false, t1)
	t3 := dag.CreateSignedTestTransaction(2, time.Now().Add(time.Duration(60)*time.Second), nil, "bar/foo", false, t2)
	t4 := dag.CreateSignedTestTransaction(3, time.Now().Add(time.Duration(30)*time.Second), nil, "1foo/bar", false, t2)

	directory := io.TestDirectory(t)
	state, _ := dag.NewState(directory)
	_ = state.Add(context.Background(), t1, dag.NumToPayload(1))
	_ = state.Add(context.Background(), t2, dag.NumToPayload(2))
	_ = state.Add(context.Background(), t3, dag.NumToPayload(2))
	_ = state.Add(context.Background(), t4, dag.NumToPayload(3))

	_ = state.Shutdown()

	t.Run("ok", func(t *testing.T) {
		outBuf := new(bytes.Buffer)
		cmd := Cmd()
		core.NewServerConfig().Load(cmd)
		cmd.SetOut(outBuf)
		cmd.SetArgs([]string{"analyze", directory})

		err := cmd.Execute()
		assert.NoError(t, err)
		out := outBuf.String()
		assert.Contains(t, out, "did:nuts:2 : 2")
		assert.Contains(t, out, "(unknown signer: embedded JWT) : 1")
		assert.Contains(t, out, "did:nuts:3 : 1")
	})
}
