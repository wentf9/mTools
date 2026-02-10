package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
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

// TODO: 在这里添加 Execute, Shell 等方法，并在这里处理 Sudo 逻辑

func (c *Client) Run(ctx context.Context, cmd string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	// 使用 bash -l -c 执行，以加载完整的环境变量 (如 PATH)
	// ss -tlpn 等命令通常在 /usr/sbin 或 /sbin 下，普通非交互式 shell 可能找不到
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

// RunWithSudo 提权执行命令，自动注入密码，并返回干净的输出
func (c *Client) RunWithSudo(ctx context.Context, command string) (string, error) {
	// 使用 bash -l -c 执行，以加载完整的环境变量
	wrappedCmd := fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))

	switch c.node.SudoMode {
	case "sudo":
		return c.runWithSudo(ctx, wrappedCmd, c.identity.Password, nil)
	case "sudoer":
		return c.runWithSudo(ctx, wrappedCmd, "", nil)
	case "su":
		return c.runWithSu(command, c.node.SuPwd)
	default:
		return "", fmt.Errorf("unsupported sudo mode: %s", c.node.SudoMode)
	}
}

// RunScriptWithSudo 提权执行脚本
func (c *Client) RunScriptWithSudo(ctx context.Context, scriptContent string) (string, error) {
	switch c.node.SudoMode {
	case "sudo":
		return c.runWithSudo(ctx, "bash -l -s", c.identity.Password, strings.NewReader(scriptContent))
	case "sudoer":
		return c.runWithSudo(ctx, "bash -l -s", "", strings.NewReader(scriptContent))
	case "su":
		// su 模式下执行脚本比较复杂，暂时通过 bash -l -c 包裹
		return c.runWithSu(fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(scriptContent, "'", "'\\''")), c.node.SuPwd)
	default:
		return "", fmt.Errorf("unsupported sudo mode: %s", c.node.SudoMode)
	}
}

// runWithSudo 执行 sudo 命令，自动注入密码，并返回干净的输出
func (c *Client) runWithSudo(ctx context.Context, command string, password string, extraStdin io.Reader) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	// 1. 设置输入流 (Stdin)
	if password != "" {
		if extraStdin != nil {
			session.Stdin = io.MultiReader(strings.NewReader(password+"\n"), extraStdin)
		} else {
			session.Stdin = strings.NewReader(password + "\n")
		}
	} else if extraStdin != nil {
		session.Stdin = extraStdin
	}

	// 2. 构建命令
	// -S: 从 Stdin 读密码
	// -p '': 将提示符设为空字符串（关键！这样输出里就不会有 "Password:" 之类的杂质）
	fullCmd := fmt.Sprintf("sudo -S -p '' %s", command)
	return startWithTimeout(ctx, session, fullCmd)
}

// runWithSu 执行 sudo 命令，自动注入密码，并返回干净的输出
func (c *Client) runWithSu(command string, password string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	// 1. 必须请求 PTY (伪终端)
	// 如果不请求，su 会拒绝从 stdin 读取密码
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // 关闭回显 (避免密码被打印出来)
		ssh.TTY_OP_ISPEED: 14400, // 输入速率
		ssh.TTY_OP_OSPEED: 14400, // 输出速率
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return "", fmt.Errorf("request for pty failed: %v", err)
	}

	// 2. 获取输入输出管道
	stdin, err := session.StdinPipe()
	if err != nil {
		return "", err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", err
	}

	// 3. 构建命令
	// 使用 su - root -c 'command'
	// -c 参数允许只执行一行命令后立即退出，而不是卡在 shell 里
	// 强制英文环境，确保提示词是 "Password:"
	cmd := fmt.Sprintf("export LC_ALL=C; su - root -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))

	if err := session.Start(cmd); err != nil {
		return "", fmt.Errorf("failed to start command: %v", err)
	}

	// 4. 实现 "Expect" 逻辑 (等待提示符 -> 输入密码)
	// 需要一个缓冲区来分析输出
	var outputBuf bytes.Buffer

	// 创建一个通道来通知我们是否找到了密码提示符
	passwordPromptFound := make(chan bool)

	// 启动一个协程不断读取 stdout
	go func() {
		buf := make([]byte, 1024)
		found := false
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				outputBuf.Write(chunk)

				// 检查是否出现 "Password:" (注意：不同系统可能是 "密码："，需根据实际情况调整)
				// 只要还没找到，就一直检测
				if !found && (strings.Contains(string(chunk), "assword:") || strings.Contains(string(chunk), "密码")) {
					found = true
					passwordPromptFound <- true
				}
			}
			if err != nil {
				// 命令结束 (EOF) 或出错
				if !found {
					// 如果到死都没找到提示符，关闭通道防止死锁
					close(passwordPromptFound)
				}
				break
			}
		}
	}()

	// 5. 等待密码提示符出现，并设置超时
	select {
	case <-passwordPromptFound:
		// 找到了提示符，发送密码
		_, err = stdin.Write([]byte(password + "\n"))
		if err != nil {
			return "", fmt.Errorf("failed to send password: %v", err)
		}
	case <-time.After(5 * time.Second):
		return outputBuf.String(), fmt.Errorf("timeout waiting for password prompt")
	}

	// 6. 等待会话结束
	err = session.Wait()

	// 获取最终输出字符串
	fullOutput := outputBuf.String()

	// 7. 清洗输出 (可选)
	// 因为是 PTY，输出里可能包含 "Password:" 和回车换行符，看起来比较乱
	// 简单的清洗逻辑：
	cleanOutput := cleanSuOutput(fullOutput)

	if err != nil {
		return cleanOutput, fmt.Errorf("command execution failed: %v", err)
	}

	return cleanOutput, nil
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

	// 设置本地终端为 Raw 模式 (这行必须在任何输出之前执行，保证体验)
	oldState, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("can not set term to Raw : %v", err)
	}
	defer term.Restore(fdIn, oldState)
	// ================= Windows 窗口大小自适应 =================
	// Windows 不支持 SIGWINCH 信号，所以我们启动一个协程，每秒检查一次窗口大小
	// 如果大小变了，就通知远程服务器调整。
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

	// 主线程或者新协程处理用户输入
	io.Copy(stdin, os.Stdin)

	return session.Wait()
}

func (c *Client) ShellWithSudo(ctx context.Context) error {
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

	// 设置本地终端为 Raw 模式 (这行必须在任何输出之前执行，保证体验)
	oldState, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("can not set term to Raw : %v", err)
	}
	defer term.Restore(fdIn, oldState)

	// ================= Windows 窗口大小自适应 =================
	// Windows 不支持 SIGWINCH 信号，所以我们启动一个协程，每秒检查一次窗口大小
	// 如果大小变了，就通知远程服务器调整。
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

	// =================== 智能 Sudo 核心逻辑开始 ===================

	// 第一步：发送 sudo 命令
	// 注意：这里不需要等待，直接发
	var sudoCmd string
	var password string
	switch c.node.SudoMode {
	case "sudo":
		sudoCmd = "sudo -i"
		password = c.identity.Password
	case "sudoer":
		sudoCmd = "sudo -i"
		password = ""
	case "su":
		sudoCmd = "su -"
		password = c.node.SuPwd
	default:
		sudoCmd = ""
	}
	stdin.Write([]byte(sudoCmd + "\n"))

	if password == "" {
		// 如果没有密码，直接交还控制权
		go io.Copy(os.Stdout, stdout)
		go io.Copy(os.Stderr, stderr)
		go io.Copy(stdin, os.Stdin)
		return session.Wait()
	}
	buf := make([]byte, 1024)
	var outputHistory bytes.Buffer
	passwordSent := false

	// 设置一个总体超时时间
	done := make(chan struct{})

	go func() {
		// 这是一个简单的定时器，5秒后如果你还没输完密码逻辑，就强制结束握手进入透传模式
		time.Sleep(5 * time.Second)
		close(done)
	}()

HandshakeLoop:
	for {
		select {
		case <-done:
			break HandshakeLoop
		default:

			n, err := stdout.Read(buf)
			if err != nil {
				break HandshakeLoop
			}

			if n <= 0 {
				continue
			}
			chunk := buf[:n]
			// 丢弃密码提示符
			// os.Stdout.Write(chunk)
			// ====================================================

			if passwordSent {
				continue
			}
			outputHistory.Write(chunk)
			text := outputHistory.String()
			// 只检测最近的 500 字符，防止 buffer 过大
			if outputHistory.Len() > 500 {
				outputHistory.Reset()
			}

			if strings.Contains(strings.ToLower(text), "assword") || strings.Contains(text, "密码") {
				stdin.Write([]byte(password + "\n"))
				passwordSent = true
				// 密码发送后，我们可以选择跳出，也可以稍等一下看有无错误
				// 这里选择直接跳出，把控制权交给 io.Copy 加快响应
				break HandshakeLoop
			}

		}
	}

	// =================== 智能 Sudo 核心逻辑结束 ===================

	// 8. 交接控制权
	// 握手结束，现在启动标准的数据转发
	// 开启协程处理远程的剩余输出
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	// 主线程或者新协程处理用户输入
	io.Copy(stdin, os.Stdin)

	return session.Wait()
}

// cleanSuOutput 简单的清洗函数，移除 Password: 提示行
func cleanSuOutput(raw string) string {
	lines := strings.Split(raw, "\n")
	var result []string
	for _, line := range lines {
		// 过滤掉包含 Password: 的行，以及空行
		trimLine := strings.TrimSpace(line)
		if strings.Contains(trimLine, "assword:") || trimLine == "" || strings.Contains(trimLine, "密码") {
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}

func startWithTimeout(ctx context.Context, session *ssh.Session, command string) (string, error) {
	// 1. 准备输出流 (捕获 Stdout 和 Stderr)
	var b bytes.Buffer
	session.Stdout = &b
	session.Stderr = &b

	// 2. 使用 Start 异步启动命令
	if err := session.Start(command); err != nil {
		return "", fmt.Errorf("failed to start sudo command: %v", err)
	}
	// 3. 创建一个通道来接收 Wait 的结果
	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	// 4. 等待命令完成或上下文取消
	select {
	case err := <-done:
		// 命令完成
		if err != nil {
			// 注意：如果密码错误，sudo 通常会报错并退出，这里会捕获到
			return b.String(), fmt.Errorf("failed to run command: %v, output: %s", err, b.String())
		}
		return b.String(), nil
	case <-ctx.Done():
		// 上下文取消，尝试终止命令
		if killErr := session.Signal(ssh.SIGKILL); killErr != nil {
			return b.String(), fmt.Errorf("failed to kill command after context done: %v", killErr)
		}
		return b.String(), ctx.Err()
	}
}
