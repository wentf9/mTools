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
	User       string
	Pwd        string
	Ip         string
	Port       uint16
	Client     *ssh.Client
	Session    *ssh.Session
	LastResult string
	SuPwd      string
}

// CommandOptions 定义命令选项
type CommandOptions struct {
	Sudo    uint8  // 0: 不使用sudo, 1: 使用sudo, 2: 使用su
	Content string // 命令内容
	IsCli   bool   // 是否是命令行 true: 是命令行 false: 是shell脚本
}

func (c *SSHCli) Addr() string {
	return fmt.Sprintf("%s:%d", c.Ip, c.Port)
}

// 连接对象
func (c *SSHCli) Connect() (*ssh.Session, error) {
	if c.Client == nil {
		config := &ssh.ClientConfig{}
		config.SetDefaults()
		config.User = c.User
		config.Auth = []ssh.AuthMethod{ssh.Password(c.Pwd)}
		config.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }
		client, err := ssh.Dial("tcp", c.Addr(), config)
		if nil != err {
			return nil, err
		}
		c.Client = client
	}

	session, err := c.Client.NewSession()
	if err != nil {
		return nil, err
	}
	c.Session = session
	return session, nil
}

// InteractiveSession 创建交互式终端会话
func (c *SSHCli) InteractiveSession(session *ssh.Session) error {
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

	// 为了简单起见，这里我们不处理窗口大小改变事件
	// 如果需要处理窗口大小改变，可以根据不同操作系统添加相应的实现

	// 启动远程shell
	if err := session.Shell(); err != nil {
		return fmt.Errorf("无法启动shell: %v", err)
	}
	// if c.Sudo {
	// 	// 创建一个缓冲区来存储输出
	// 	var output bytes.Buffer
	// 	// 创建通道来同步操作
	// 	passwordSent := make(chan struct{})
	// 	sudoSent := make(chan struct{})
	// 	// 监控输出并处理所有提示
	// 	buffer := make([]byte, 1024)
	// 	passwordPrompts := []string{
	// 		"[sudo] password for",
	// 		"Password:",
	// 		"密码：",
	// 	}
	// 	for {
	// 		n, err := session.Stdin.Read(buffer)
	// 		if err != nil {
	// 			if err != io.EOF {
	// 				fmt.Fprintf(os.Stderr, "读取输出错误: %v\n", err)
	// 			}
	// 			break // 读取错误或EOF时退出循环
	// 		}
	// 		output.Write(buffer[:n])
	// 		currentOutput := string(buffer[:n])

	// 		select {
	// 		case <-sudoSent:
	// 			// 检查是否需要输入密码
	// 			select {
	// 			case <-passwordSent: // 如果已经发送过密码，不再发送
	// 				continue
	// 			default:
	// 				for _, prompt := range passwordPrompts {
	// 					if strings.Contains(currentOutput, prompt) {
	// 						if c.Pwd == "" {
	// 							session.Close()
	// 							return fmt.Errorf("需要sudo密码但未提供")
	// 						}
	// 						session.Stdout.Write([]byte(c.Pwd + "\n"))
	// 						close(passwordSent)
	// 						break
	// 					}
	// 				}
	// 			}
	// 		default:
	// 			if strings.Contains(currentOutput, "#") {
	// 				Logger.Warn("已经是root环境")
	// 				break
	// 			}
	// 			if strings.Contains(currentOutput, "$") {
	// 				fmt.Fprint(session.Stdout, "sudo -S -i\n")
	// 				close(sudoSent)
	// 				continue
	// 			}
	// 		}
	// 	}
	// }

	// 等待会话结束
	return session.Wait()
}

// 执行shell
func (c SSHCli) Run(shell CommandOptions) (string, error) {
	var session *ssh.Session
	var err error

	if c.Client == nil {
		session, err = c.Connect()
		if err != nil {
			return "", err
		}
	} else {
		session, err = c.Client.NewSession()
		if err != nil {
			return "", err
		}
	}
	c.Session = session
	// 关闭会话
	defer session.Close()
	var buf string
	var bufBytes []byte
	if !shell.IsCli {
		Logger.Debug("当前命令是shell脚本,开始将脚本内容写入远程主机临时文件")
		if err := session.Run(fmt.Sprintf("cat > %s <<- 'EOF'\n%s\nEOF", SHELL_TMP, shell.Content)); err != nil {
			return "", fmt.Errorf("写入临时文件失败: %v", err)
		}
		Logger.Debug(fmt.Sprintf("已写入临时文件: %s@%s:%s", c.User, c.Ip, SHELL_TMP))
		session.Close()
		if session, err = c.Client.NewSession(); err != nil {
			return "", fmt.Errorf("创建新会话失败: %v", err)
		}
		shell.Content = fmt.Sprintf("bash %s", SHELL_TMP)
	}
	if shell.Sudo != 0 {
		buf, err = c.execWithSudo(session, shell)
	} else {
		bufBytes, err = session.CombinedOutput("source /etc/profile && " + shell.Content)
		buf = string(bufBytes)
	}
	c.LastResult = string(buf)
	return c.LastResult, err
}

// sudo模式执行命令
func (c SSHCli) execWithSudo(session *ssh.Session, cmd CommandOptions) (string, error) {
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

	// 使用管道获取输出
	pr, pw := io.Pipe()
	session.Stdout = pw
	session.Stderr = pw
	defer pw.Close()
	defer pr.Close()
	var sucmd string
	switch cmd.Sudo {
	case 1:
		sucmd = "sudo -S -i"
	case 2:
		sucmd = "su -"
	case 0:
		return "", fmt.Errorf("不需要sudo或su")
	}
	// 准备命令
	// 首先切换到root环境，然后执行实际命令，最后退出
	if err := session.Start(sucmd); err != nil {
		return "", fmt.Errorf("启动sudo会话失败: %v", err)
	}

	// 创建一个缓冲区来存储输出
	var output bytes.Buffer

	// 创建通道来同步操作
	passwordSent := make(chan struct{})
	commandSent := make(chan struct{})

	// 监控输出并处理所有提示

	buffer := make([]byte, 1024)
	passwordPrompts := []string{
		"[sudo] password for",
		"[sudo]",
		"Password:",
		"密码：",
	}
	rootPrompts := []string{
		"root@",
		"#",
	}
	Logger.Debug("开始处理sudo交互")
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
		// 检查是否需要输入密码
		select {
		case <-passwordSent: // 如果已经发送过密码，不再发送
			goto commandCheck
		default:
			for _, prompt := range rootPrompts {
				if strings.Contains(currentOutput, prompt) {
					Logger.Debug("已是root用户,无需提权")
					// 发送实际命令
					stdin.Write([]byte(cmd.Content + "\n"))
					Logger.Debug(fmt.Sprintf("已发送命令 -> %s", cmd.Content))
					close(commandSent)
					close(passwordSent)
					continue Loop
				}
			}
			for _, prompt := range passwordPrompts {
				if strings.Contains(currentOutput, prompt) {
					if cmd.Sudo == 2 {
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
					if c.Pwd != "" {
						stdin.Write([]byte(c.Pwd + "\n"))
						Logger.Debug("已发送sudo密码")
						close(passwordSent)
						continue Loop
					} else {
						session.Close()
						return "", fmt.Errorf("需要sudo密码但未提供")
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
					stdin.Write([]byte(cmd.Content + "\n"))
					Logger.Debug(fmt.Sprintf("已发送命令 -> %s", cmd.Content))
					close(commandSent)
					continue Loop
				}
			}
			if strings.Contains(currentOutput, "$") {
				return "", fmt.Errorf("未检测到root环境,可能是用户不支持sudo,输出为:%s", output.String())
			}
		}
	}

	// 获取完整输出
	outputStr := output.String()
	if strings.Contains(strings.ToLower(outputStr), "incorrect password") {
		return outputStr, fmt.Errorf("sudo密码错误")
	}
	if strings.Contains(strings.ToLower(outputStr), "not in the sudoers") {
		return outputStr, fmt.Errorf("用户没有sudo权限")
	}
	// 清理输出中的提示信息
	regex := regexp.MustCompile(`(\[sudo\].+|Password:.*|密码.*|root@.*|.*#\s*)`)
	// regex := regexp.MustCompile(`.*#.*`)
	outputStr = regex.ReplaceAllString(outputStr, "")

	return outputStr, nil
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
