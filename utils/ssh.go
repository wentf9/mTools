package utils

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const SHELL_TMP string = "/tmp/mtool_shell_tmp.sh"

// 连接信息
type SSHCli struct {
	User string
	Pwd  string
	Host string
	Port uint16
	*ssh.Client
	LastResult string
	SuPwd      string
}

func (c *SSHCli) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// 连接对象
func (c *SSHCli) Connect() error {
	config := &ssh.ClientConfig{}
	config.SetDefaults()
	config.User = c.User
	config.Auth = []ssh.AuthMethod{ssh.Password(c.Pwd)}
	config.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }
	client, err := ssh.Dial("tcp", c.Addr(), config)
	if err != nil {
		return fmt.Errorf("ssh连接到[%s@%s:%d]失败:%v", c.User, c.Host, c.Port, err)
	}
	c.Client = client
	return nil
}

func (c *SSHCli) checkClient() error {
	if c.Client != nil {
		return nil
	}
	if err := c.Connect(); err != nil {
		return err
	} else {
		return nil
	}
}

func (c *SSHCli) checkContext(cmd Command) (bool, uint8) {
	isShell, ok := cmd.Context.Value(IsShellKey{}).(bool)
	if !ok {
		isShell = false
	}
	sudo, ok := cmd.Context.Value(SudoKey{}).(uint8)
	if !ok {
		sudo = 0
	}
	return isShell, sudo
}

// 执行shell
func (c *SSHCli) Execute(command Command) (string, error) {
	isShell, sudo := c.checkContext(command)
	if err := c.checkClient(); err != nil {
		return "", err
	}
	session, err := c.NewSession()
	if err != nil {
		return "", err
	}
	// 关闭会话
	defer session.Close()
	var buf string
	var bufBytes []byte

	if isShell {
		Logger.Debug("当前命令是shell脚本,开始将脚本内容写入远程主机临时文件")
		if err := session.Run(fmt.Sprintf("cat > %s <<- 'EOF'\n%s\nEOF", SHELL_TMP, command.Content)); err != nil {
			return "", fmt.Errorf("写入临时文件失败: %v", err)
		}
		Logger.Debug(fmt.Sprintf("已写入临时文件: %s@%s:%s", c.User, c.Host, SHELL_TMP))
		session.Close()
		if session, err = c.NewSession(); err != nil {
			return "", fmt.Errorf("创建新会话失败: %v", err)
		}
		command.Content = fmt.Sprintf("bash %s", SHELL_TMP)
	}
	if sudo != 0 {
		buf, err = c.execWithSudo(session, command.Content, sudo)
	} else {
		bufBytes, err = session.CombinedOutput("source /etc/profile && " + command.Content)
		buf = string(bufBytes)
	}
	c.LastResult = string(buf)
	return c.LastResult, err
}

// sudo模式执行命令
func (c *SSHCli) execWithSudo(session *ssh.Session, cmd string, sudo uint8) (string, error) {
	// 设置输入输出管道
	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("创建stdin管道失败: %v", err)
	}
	defer stdin.Close()
	// 使用管道获取输出
	pr, pw := io.Pipe()
	session.Stdout = pw
	session.Stderr = pw
	defer pw.Close()
	defer pr.Close()
	var sucmd string
	switch sudo {
	case 1:
		sucmd = fmt.Sprintf("sudo -S -i %s", cmd)
	case 2:
		return c.execWithSu(session, cmd)
	case 0:
		return "", fmt.Errorf("不需要sudo或su")
	}
	// 启动会话
	if err := session.Start(sucmd); err != nil {
		return "", fmt.Errorf("启动sudo会话失败: %v", err)
	}
	// 发送密码
	stdin.Write([]byte(c.Pwd + "\n"))
	Logger.Debug("已发送sudo密码")
	// 获取输出
	var output bytes.Buffer
	go func() {
		io.Copy(&output, pr)
	}()
	// 等待命令完成
	if err := session.Wait(); err != nil {
		return output.String(), fmt.Errorf("命令执行失败: %v", err)
	}
	Logger.Debug("命令执行完成,开始处理输出")
	Logger.Debug(fmt.Sprintf("原始输出 -> %s", output.String()))
	regex := regexp.MustCompile(`\[sudo\].+:`)
	// regex := regexp.MustCompile(`.*#.*`)
	outputStr := regex.ReplaceAllString(output.String(), "")

	return outputStr, nil
}

func (c *SSHCli) execWithSu(session *ssh.Session, cmd string) (string, error) {
	// 请求伪终端
	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // 禁用回显
		ssh.TTY_OP_ISPEED: 14400, // 输入速度
		ssh.TTY_OP_OSPEED: 14400, // 输出速度
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return "", fmt.Errorf("request for pseudo terminal failed: %s", err)
	}
	// 设置输入输出管道
	stdin, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("创建stdin管道失败: %v", err)
	}
	defer stdin.Close()
	// 使用管道获取输出
	pr, pw := io.Pipe()
	session.Stdout = pw
	session.Stderr = pw
	defer pw.Close()
	defer pr.Close()
	var sucmd string = "su -"

	// 准备命令
	// 首先切换到root环境，然后执行实际命令，最后退出
	if err := session.Start(sucmd); err != nil {
		return "", fmt.Errorf("启动su会话失败: %v", err)
	}

	// 创建一个缓冲区来存储输出
	var output bytes.Buffer

	// 创建通道来同步操作
	passwordSent := make(chan struct{})
	commandSent := make(chan struct{})

	// 监控输出并处理所有提示
	buffer := make([]byte, 1024)
	passwordPrompts := []string{
		"Password:",
		"密码：",
	}
	rootPrompts := []string{
		"root@",
		"#",
	}
	Logger.Debug("开始处理su交互")
Loop:
	for {
		Logger.Debug("开始读取输出")
		n, err := pr.Read(buffer)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "读取输出错误: %v\n", err)
			}
			Logger.Debug("读取到EOF,退出循环")
			break Loop // 读取错误或EOF时退出循环
		}
		output.Write(buffer[:n])
		currentOutput := string(buffer[:n])
		Logger.Debug(fmt.Sprintf("当前输出 -> %s", currentOutput))
		if strings.Contains(currentOutput, "Sorry, try again") {
			Logger.Error("su密码错误")
			return "", fmt.Errorf("su密码错误")
		}
		if strings.Contains(currentOutput, "Permission denied") {
			Logger.Error("权限被拒绝")
			return "", fmt.Errorf("权限被拒绝")
		}
		if strings.Contains(currentOutput, "logout") || strings.Contains(currentOutput, "注销") ||
			strings.Contains(currentOutput, "Connection to") || strings.Contains(currentOutput, "Connection closed") {
			Logger.Debug("会话已关闭或连接已断开")
			break Loop // 会话已关闭或连接已断开，退出循环
		}
		// 检查是否需要输入密码
		select {
		case <-passwordSent: // 如果已经发送过密码，不再发送
			goto commandCheck
		default:
			for _, prompt := range rootPrompts {
				if strings.Contains(currentOutput, prompt) {
					Logger.Debug("已是root用户,无需提权")
					// 发送实际命令
					stdin.Write([]byte(cmd + "\n"))
					Logger.Debug(fmt.Sprintf("已发送命令 -> %s", cmd))
					close(commandSent)
					close(passwordSent)
					continue Loop
				}
			}
			for _, prompt := range passwordPrompts {
				if strings.Contains(currentOutput, prompt) {
					if c.SuPwd != "" {
						stdin.Write([]byte(c.SuPwd + "\n"))
						Logger.Debug("已发送su密码")
						close(passwordSent)
						continue Loop
					} else {
						session.Close()
						return "", fmt.Errorf("需要su密码但未提供")
					}
				}
			}
			continue Loop
		}
	commandCheck:
		// 如果命令已发送且检测到新的提示符，说明命令执行完成
		select {
		case <-commandSent:
			for _, prompt := range rootPrompts {
				// 检查是否进入root环境
				if strings.Contains(currentOutput, prompt) {
					Logger.Debug("命令执行完成")
					break Loop // 退出循环
				}
			}
		default:
			for _, prompt := range rootPrompts {
				if strings.Contains(currentOutput, prompt) {
					Logger.Debug("已进入root环境")
					// 发送实际命令
					stdin.Write([]byte(cmd + "\n"))
					Logger.Debug(fmt.Sprintf("已发送命令 -> %s", cmd))
					close(commandSent)
					continue Loop
				}
			}
			if strings.Contains(currentOutput, "$") {
				return "", fmt.Errorf("未检测到root环境,su切换root环境失败,输出为:%s", output.String())
			}
		}
	}
	// 获取完整输出
	outputStr := output.String()
	if strings.Contains(strings.ToLower(outputStr), "incorrect password") {
		return outputStr, fmt.Errorf("su密码错误")
	}
	// 清理输出中的提示信息
	regex := regexp.MustCompile(`(Password:.*|密码.*|root@.*|.*#\s*)`)
	outputStr = regex.ReplaceAllString(outputStr, "")
	return outputStr, nil
}

// InteractiveSession 创建交互式终端会话
func InteractiveSession(c *SSHCli) error {
	if c.Client == nil {
		if err := c.Connect(); err != nil {
			return err
		}
	}
	session, err := c.Client.NewSession()
	if err != nil {
		return fmt.Errorf("创建会话失败: %v", err)
	}
	defer session.Close()
	// 获取当前终端文件描述符
	fdIn := int(os.Stdin.Fd())
	fdOut := int(os.Stdout.Fd())
	// 保存当前终端状态
	oldState, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("无法设置终端为raw模式: %v", err)
	}
	defer term.Restore(fdIn, oldState)

	// 获取终端窗口大小
	width, height, err := term.GetSize(fdOut)
	if err != nil {
		return fmt.Errorf("无法获取终端大小: %v", err)
	}

	// 请求伪终端
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // 启用回显
		ssh.TTY_OP_ISPEED: 14400, // 输入速度
		ssh.TTY_OP_OSPEED: 14400, // 输出速度
	}

	if err := session.RequestPty("xterm", height, width, modes); err != nil {
		return fmt.Errorf("请求伪终端失败: %v", err)
	}

	// 设置标准输入输出
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	session.Stdin = os.Stdin

	// 启动远程shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("无法启动shell: %v", err)
	}

	return session.Wait()
}

// func publicKeyAuthFunc(kPath string) ssh.AuthMethod {
// 	keyPath, err := homedir.Expand(kPath)
// 	if err != nil {
// 		log.Fatal("find key's home dir failed", err)
// 	}
// 	key, err := ioutil.ReadFile(keyPath)
// 	if err != nil {
// 		log.Fatal("ssh key file read failed", err)
// 	}
// 	// Create the Signer for this private key.
// 	signer, err := ssh.ParsePrivateKey(key)
// 	if err != nil {
// 		log.Fatal("ssh key signer failed", err)
// 	}
// 	return ssh.PublicKeys(signer)
// }

// 跳板机支持
// func (jumpHostCli SSHCli) createJumpClient(targetHostCli *SSHCli) error {
// 	jumpHostCli.Connect()
// 	config := &ssh.ClientConfig{}
// 	config.SetDefaults()
// 	config.User = targetHostCli.user
// 	config.Auth = []ssh.AuthMethod{ssh.Password(targetHostCli.pwd)}
// 	config.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }
// 	conn, err := jumpHostCli.client.Dial("tcp", targetHostCli.addr())
// 	if err != nil {
// 		return err
// 	}
// 	ncc, chans, reqs, err := ssh.NewClientConn(conn, targetHostCli.addr(), config)
// 	if err != nil {
// 		return err
// 	}
// 	targetHostCli.client = ssh.NewClient(ncc, chans, reqs)
// 	return nil
// }
