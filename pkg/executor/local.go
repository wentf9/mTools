package executor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// LocalExecutor 本地执行器
type LocalExecutor struct{}

func NewLocalExecutor() *LocalExecutor {
	return &LocalExecutor{}
}

func (e *LocalExecutor) Run(ctx context.Context, cmd string) (string, error) {
	// 使用 bash -c 执行以支持复杂的 shell 语法
	c := exec.CommandContext(ctx, "bash", "-c", cmd)
	out, err := c.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("command failed: %w, output: %s", err, string(out))
	}
	return string(out), nil
}

func (e *LocalExecutor) RunWithSudo(ctx context.Context, cmd string) (string, error) {
	// 本地提权假设当前用户在 sudoers 中且可能需要交互，或者已经有 root 权限
	// 这里简单实现，如果是 root 直接运行，否则加 sudo
	// 注意：在非交互式环境下，sudo 可能会失败
	if !strings.HasPrefix(cmd, "sudo") {
		cmd = "sudo " + cmd
	}
	return e.Run(ctx, cmd)
}
