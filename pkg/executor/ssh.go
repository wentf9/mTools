package executor

import (
	"context"

	"example.com/MikuTools/pkg/ssh"
)

// SSHExecutor 包装 ssh.Client 以满足 Executor 接口
type SSHExecutor struct {
	client *ssh.Client
}

func NewSSHExecutor(client *ssh.Client) *SSHExecutor {
	return &SSHExecutor{client: client}
}

func (e *SSHExecutor) Run(ctx context.Context, cmd string) (string, error) {
	return e.client.Run(ctx, cmd)
}

func (e *SSHExecutor) RunWithSudo(ctx context.Context, cmd string) (string, error) {
	return e.client.RunWithSudo(ctx, cmd)
}
