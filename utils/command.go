package utils

import (
	"context"
)

type Command struct {
	// Sudo    uint8 // 0: 不使用sudo, 1: 使用sudo, 2: 使用su
	Content string
	context.Context
	// IsCli   bool // 是否是命令行 true: 是命令行 false: 是shell脚本
}

type SudoKey struct{}
type IsCliKey struct{}

// type CommandResult struct {
// 	Success bool
// 	Output  string
// 	Error   error
// }

type Executor interface {
	Execute(command Command) (string, error)
}

func (c Command) WithContext(ctx context.Context) Command {
	c.Context = ctx
	return c
}

func (c Command) Execute(executor Executor) (string, error) {
	return executor.Execute(c)
}

func NewSSHCommand(content string, sudo uint8, isCli bool) Command {
	ctx := context.Background()
	ctx = context.WithValue(ctx, SudoKey{}, sudo)
	ctx = context.WithValue(ctx, IsCliKey{}, isCli)
	return Command{
		Content: content,
		Context: ctx,
	}
}

func SSHCmdExecute(content string, executor Executor) (string, error) {
	cmd := NewSSHCommand(content, 0, true)
	return cmd.Execute(executor)
}
