package executor

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// LocalExecutor 本地执行器
type LocalExecutor struct {
	password string
}

func NewLocalExecutor(password string) *LocalExecutor {
	return &LocalExecutor{password: password}
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
	if e.password == "" {
		// 如果没密码，尝试无交互 sudo
		if !strings.HasPrefix(cmd, "sudo") {
			cmd = "sudo " + cmd
		}
		return e.Run(ctx, cmd)
	}

	// 使用 sudo -S 从 stdin 读取密码
	// -p '' 隐藏提示符
	sudoCmd := fmt.Sprintf("sudo -S -p '' %s", cmd)
	c := exec.CommandContext(ctx, "bash", "-c", sudoCmd)
	
	stdin, err := c.StdinPipe()
	if err != nil {
		return "", err
	}

	go func() {
		defer stdin.Close()
		io.WriteString(stdin, e.password+"\n")
	}()

	out, err := c.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("sudo command failed: %w, output: %s", err, string(out))
	}
	return string(out), nil
}

func (e *LocalExecutor) InteractiveWithSudo(ctx context.Context, args []string) error {
	var sudoArgs []string
	if e.password != "" {
		sudoArgs = append(sudoArgs, "-S", "-p", "")
	}
	sudoArgs = append(sudoArgs, "-s")
	sudoArgs = append(sudoArgs, args...)

	c := exec.CommandContext(ctx, "sudo", sudoArgs...)
	
	if e.password != "" {
		stdin, err := c.StdinPipe()
		if err != nil {
			return err
		}
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Start(); err != nil {
			return err
		}
		// 注入密码
		stdin.Write([]byte(e.password + "\n"))
		// 将本地标准输入转发给进程
		go io.Copy(stdin, os.Stdin)
		return c.Wait()
	} else {
		// 无密码模式，直接连接标准流
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		return c.Run()
	}
}