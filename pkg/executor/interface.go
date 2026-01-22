package executor

import "context"

type Executor interface {
	// Execute 执行命令并返回输出
	Run(ctx context.Context, cmd string) (string, error)
	RunWithSu(ctx context.Context, command string, password string) (string, error)
	RunWithSudo(ctx context.Context, command string, password string) (string, error)
}

type Transfer interface {
	// Copy 复制文件 (为了统一 SCP 和 本地复制)
	Copy(ctx context.Context, src, dst string) error
}
