package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"example.com/MikuTools/pkg/models"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

type Client struct {
	sshClient *ssh.Client
	node      models.Node
	host      models.Host
	identity  models.Identity
}

func newClient(raw *ssh.Client, node models.Node, host models.Host, identity models.Identity) *Client {
	return &Client{
		sshClient: raw,
		node:      node,
		host:      host,
		identity:  identity,
	}
}

// Close 关闭连接
func (c *Client) Close() error {
	return c.sshClient.Close()
}

// SSHClient 暴露底层的 ssh.Client (供高级操作使用，如 SCP)
func (c *Client) SSHClient() *ssh.Client {
	return c.sshClient
}

// Node 返回当前连接对应的节点配置
func (c *Client) Node() models.Node {
	return c.node
}

func (c *Client) Run(ctx context.Context, cmd string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	// 使用 bash -l -c 执行，以加载完整的环境变量 (如 PATH)
	wrappedCmd := fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(cmd, "'", "'\\''"))
	return startWithTimeout(ctx, session, wrappedCmd)
}

// RunScript 执行 Shell 脚本内容
func (c *Client) RunScript(ctx context.Context, scriptContent string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	session.Stdin = strings.NewReader(scriptContent)
	// 使用 bash -l -s 从 stdin 读取脚本，以加载环境变量
	return startWithTimeout(ctx, session, "bash -l -s")
}

func (c *Client) Shell(ctx context.Context) error {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	// 配置 PTY (终端模式)
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	// 获取当前终端文件描述符
	fdIn := int(os.Stdin.Fd())
	fdOut := int(os.Stdout.Fd())
	width, height, err := term.GetSize(fdOut)
	if err != nil {
		width, height = 80, 40
	}
	if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
		return fmt.Errorf("request for pty failed: %v", err)
	}
	// 获取管道
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	// 启动 Shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("start Shell failed: %v", err)
	}

	// 设置本地终端为 Raw 模式
	oldState, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("can not set term to Raw : %v", err)
	}
	defer term.Restore(fdIn, oldState)
	// ================= Windows 窗口大小自适应 =================
	go func() {
		lastW, lastH := width, height
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			currW, currH, _ := term.GetSize(fdOut)
			if currW != lastW || currH != lastH {
				session.WindowChange(currH, currW)
				lastW, lastH = currW, currH
			}
		}
	}()
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	// 启动协程处理用户输入
	go io.Copy(stdin, os.Stdin)

	return session.Wait()
}

func startWithTimeout(ctx context.Context, session *ssh.Session, command string) (string, error) {
	var b bytes.Buffer
	var mu sync.Mutex
	syncWriter := &synchronizedWriter{mu: &mu, b: &b}
	session.Stdout = syncWriter
	session.Stderr = syncWriter

	if err := session.Start(command); err != nil {
		return "", fmt.Errorf("failed to start command: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	select {
	case err := <-done:
		output := syncWriter.String()
		if err != nil {
			return output, fmt.Errorf("failed to run command: %v, output: %s", err, output)
		}
		return output, nil
	case <-ctx.Done():
		if killErr := session.Signal(ssh.SIGKILL); killErr != nil {
			return syncWriter.String(), fmt.Errorf("failed to kill command after context done: %v", killErr)
		}
		return syncWriter.String(), ctx.Err()
	}
}

type synchronizedWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w *synchronizedWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *synchronizedWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}
