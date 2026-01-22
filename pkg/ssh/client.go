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
	node      *models.Node
}

func NewClient(raw *ssh.Client, node *models.Node) *Client {
	return &Client{
		sshClient: raw,
		node:      node,
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
func (c *Client) Node() *models.Node {
	return c.node
}

// TODO: 在这里添加 Execute, Shell 等方法，并在这里处理 Sudo 逻辑

func (c *Client) Run(ctx context.Context, cmd string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	return startWithTimeout(ctx, session, cmd)
}

// RunWithSudo 执行 sudo 命令，自动注入密码，并返回干净的输出
func (c *Client) RunWithSudo(ctx context.Context, command string, password string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	// 1. 设置输入流 (Stdin)
	// 把 "密码 + 换行符" 准备好，放入 Stdin
	// 当 sudo -S 启动时，会立刻从这里读走密码
	if password != "" {
		session.Stdin = strings.NewReader(password + "\n")
	}

	// 2. 构建命令
	// -S: 从 Stdin 读密码
	// -p '': 将提示符设为空字符串（关键！这样输出里就不会有 "Password:" 之类的杂质）
	fullCmd := fmt.Sprintf("sudo -S -p '' %s", command)
	return startWithTimeout(ctx, session, fullCmd)
}

// RunWithSu 执行 sudo 命令，自动注入密码，并返回干净的输出
func (c *Client) RunWithSu(ctx context.Context, command string, password string) (string, error) {
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
	cmd := fmt.Sprintf("export LC_ALL=C; su - root -c '%s'", command)

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

func (c *Client) ShellWithSudo(ctx context.Context, password string) error {
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
	fd := int(os.Stdin.Fd())
	width, height, err := term.GetSize(fd)
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
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("can not set term to Raw : %v", err)
	}
	defer term.Restore(fd, oldState)

	// =================== 智能 Sudo 核心逻辑开始 ===================

	// 第一步：发送 sudo 命令
	// 注意：这里不需要等待，直接发
	stdin.Write([]byte("sudo -i\n"))

	// 第二步：智能等待密码提示符
	// 我们创建一个缓冲区，循环读取远程的输出
	buf := make([]byte, 1024)
	var outputBuffer bytes.Buffer // 用于累积最近的输出以便匹配字符串

	// 设置一个超时机制，防止 sudo 不需要密码或者卡死导致程序永远等待
	// 这里使用一个简单的标志位
	passwordSent := false

	// 我们只在“握手阶段”手动读取 stdout
	// 这是一个简单的状态机：寻找 "assword" 或 "密码"
	for !passwordSent {
		// 从远程读取数据
		n, err := stdout.Read(buf)
		if err != nil {
			if err != io.EOF {
				// 此时处于 Raw 模式，直接打印可能排版会乱，建议使用 \r\n
				fmt.Printf("\r\n读取错误: %v\r\n", err)
			}
			break
		}

		// 1. 重要：立即将读到的内容原样打印到屏幕，让用户看到 "[sudo] password for..."
		// os.Stdout.Write(buf[:n])

		// 2. 将内容存入临时 buffer 用于检查
		// 为了防止 buffer 无限增长，实际生产中应该只保留最后几百个字节，这里简化处理
		outputBuffer.Write(buf[:n])
		text := outputBuffer.String()

		// 3. 检测关键字
		// 常见的提示符有: "Password:", "[sudo] password for user:", "输入密码:"
		// 检测 "assword" (忽略大小写) 通常比较通用，且避开了首字母P的大小写问题
		// 也可以加入中文 "密码" 支持
		if strings.Contains(strings.ToLower(text), "assword") || strings.Contains(text, "密码") {
			// 找到提示符了！发送密码
			stdin.Write([]byte(password + "\n"))
			passwordSent = true

			// 此时不要 break，因为可能还有后续的回显（比如换行符），
			// 但为了简化逻辑，我们假设密码发送后就可以转交控制权了。
			// 更好的做法是再等一小会儿看有没有 "Try again" 错误，但这里先做基础版。
		}

		// 4. 超时保护逻辑 (可选)
		// 如果读了太多内容还没提示符，或者时间太久，也可以强制跳出循环交还给用户
		if outputBuffer.Len() > 500 {
			// 缓冲区过大，可能已经进入了 shell 或者 sudo 免密成功了
			// 清空 buffer 防止内存泄漏，继续在此循环或跳出视具体需求而定
			// 针对本例，如果已经不需要密码（免密sudo），用户会看到提示符，我们直接把控制权交给用户即可
			// 但如何判断免密成功比较难，通常通过超时或者检测 shell 提示符 (#/$).
			// 简单起见：这里假设必须输入密码。如果你有免密需求，需要增加超时 break。
		}
	}

	// =================== 智能 Sudo 核心逻辑结束 ===================

	// 8. 交接控制权
	// 握手结束，现在启动标准的数据转发
	// 开启协程处理远程的剩余输出
	go io.Copy(os.Stdout, stdout)
	go io.Copy(os.Stderr, stderr)

	// 主线程或者新协程处理用户输入
	// 因为 main 函数最后有 session.Wait() 阻塞，所以这里用 Copy 阻塞也行，或者放到协程里
	go io.Copy(stdin, os.Stdin)

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
