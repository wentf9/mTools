package runner

type ExecOptions struct {
	Command string
	Sudo    bool
}

func RunBatchCommand(opts ExecOptions) error {
	// 具体的并发执行逻辑
	return nil
}
