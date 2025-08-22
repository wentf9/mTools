package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/crypto/ssh"
)

// SCPClient SCP客户端结构体
type SCPClient struct {
	SSHCli
	ShowProgress bool
	Force        bool // 是否强制覆盖
}

// // ensureRemotePath 确保远程路径存在
// func (c *SCPClient) ensureRemotePath(path string) error {
// 	dir := filepath.Dir(path)
// 	if _, err := c.Run(fmt.Sprintf("mkdir -p '%s'", dir)); err != nil {
// 		return fmt.Errorf("创建远程目录失败: %v", err)
// 	}
// 	return nil
// }

// // ensureLocalPath 确保本地路径存在
// func (c *SCPClient) ensureLocalPath(path string) error {
// 	dir := filepath.Dir(path)
// 	if err := os.MkdirAll(dir, 0755); err != nil {
// 		return fmt.Errorf("创建本地目录失败: %v", err)
// 	}
// 	return nil
// }

// createScpSession 创建并配置SCP会话
func (c *SCPClient) createScpSession() (*ssh.Session, string, error) {
	Logger.Debug("创建新会话")
	session, err := c.Client.NewSession()
	if err != nil {
		return nil, "", fmt.Errorf("创建会话失败: %v", err)
	}

	Logger.Debug("检查远程主机上的scp命令")
	scpCmd := "which scp 2>/dev/null || command -v scp 2>/dev/null || type -p scp 2>/dev/null"
	scpPath, err := c.Run(CommandOptions{Sudo: 0, Content: scpCmd, IsCli: true})
	if err != nil || scpPath == "" {
		// 尝试常见的scp路径
		paths := []string{"/usr/bin/scp", "/bin/scp", "/usr/local/bin/scp"}
		for _, path := range paths {
			if _, err := c.Run(CommandOptions{Sudo: 0, Content: fmt.Sprintf("test -x '%s'", path), IsCli: true}); err == nil {
				scpPath = path
				break
			}
		}
		if scpPath == "" {
			session.Close()
			return nil, "", fmt.Errorf("未找到可用的scp命令")
		}
	} else {
		scpPath = strings.TrimSpace(scpPath)
	}
	Logger.Debug(fmt.Sprintf("使用的scp命令: %s", scpPath))
	Logger.Debug("设置环境变量以确保二进制模式传输")
	if err := session.Setenv("LANG", "C"); err != nil {
		session.Close()
		return nil, "", fmt.Errorf("设置LANG环境变量失败: %v", err)
	}
	if err := session.Setenv("LC_ALL", "C"); err != nil {
		session.Close()
		return nil, "", fmt.Errorf("设置LC_ALL环境变量失败: %v", err)
	}

	return session, scpPath, nil
}

// Upload 上传文件到远程主机
func (c *SCPClient) Upload(localPath, remotePath string, recursive bool) error {
	Logger.Debug("开始上传文件")
	// 连接到远程主机
	session, err := c.Connect()
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer session.Close()
	Logger.Debug(fmt.Sprintf("%s@%s 连接成功", c.User, c.Ip))

	// 获取本地文件信息
	localInfo, err := os.Stat(localPath)
	if err != nil {
		return fmt.Errorf("获取本地文件信息失败: %v", err)
	}

	if localInfo.IsDir() {
		if !recursive {
			return fmt.Errorf("'%s' 是目录，需要使用 -r 选项", localPath)
		}
		return c.uploadDirectory(localPath, remotePath)
	}

	return c.uploadFile(localPath, remotePath)
}

// Download 从远程主机下载文件
func (c *SCPClient) Download(remotePath, localPath string, recursive bool) error {
	// 连接到远程主机
	session, err := c.Connect()
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer session.Close()

	// 检查远程文件是否为目录
	if output, err := c.Run(CommandOptions{Sudo: 0, Content: fmt.Sprintf("test -d '%s' && echo 'DIR' || echo 'FILE'", remotePath), IsCli: true}); err != nil {
		return fmt.Errorf("检查远程路径失败: %v", err)
	} else if output == "DIR\n" {
		if !recursive {
			return fmt.Errorf("'%s' 是目录，需要使用 -r 选项", remotePath)
		}
		return c.downloadDirectory(remotePath, localPath)
	}

	return c.downloadFile(remotePath, localPath)
}

func (c *SCPClient) uploadFile(localPath, remotePath string) error {
	// 打开本地文件
	file, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("打开本地文件失败: %v", err)
	}
	defer file.Close()

	// 获取文件信息
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("获取文件信息失败: %v", err)
	}

	if _, err := c.Run(CommandOptions{Sudo: 0, Content: fmt.Sprintf("test -f '%s'", filepath.ToSlash(remotePath)), IsCli: true}); err == nil {
		if !c.Force {
			// fmt.Printf("远程文件已存在,是否覆盖? (y/n): ")
			// var response string
			// fmt.Scanln(&response)
			// if strings.ToLower(response) != "y" {
			// 	return fmt.Errorf("用户取消上传")
			// }
			return fmt.Errorf("远程文件已存在")
		}
	} else if _, err := c.Run(CommandOptions{Sudo: 0, Content: fmt.Sprintf("test -d '%s'", filepath.ToSlash(remotePath)), IsCli: true}); err == nil {
		// 如果远程路径是目录，则将文件上传到该目录
		remotePath = filepath.Join(remotePath, fileInfo.Name())
		remotePath = filepath.ToSlash(remotePath) // 确保使用正斜杠
		if !c.Force {
			if _, err := c.Run(CommandOptions{Sudo: 0, Content: fmt.Sprintf("test -f '%s'", remotePath), IsCli: true}); err == nil {
				// fmt.Printf("远程文件已存在,是否覆盖? (y/n): ")
				// var response string
				// fmt.Scanln(&response)
				// if strings.ToLower(response) != "y" {
				// 	return fmt.Errorf("用户取消上传")
				// }
				return fmt.Errorf("远程文件已存在")
			}
		}
	} else {
		// 如果远程路径不存在
		if remotePath[len(remotePath)-1] == '/' {
			return fmt.Errorf("远程路径 '%s' 是目录，但不存在: %v", remotePath, err)
		}
		if res, err := c.Run(CommandOptions{Sudo: 0, Content: fmt.Sprintf("test -d '%s'", filepath.ToSlash(filepath.Dir(remotePath))), IsCli: true}); err != nil {
			return fmt.Errorf("远程路径 '%s' 的父目录不存在: %v\n%s", remotePath, err, res)
		}
		Logger.Debug(fmt.Sprintf("远程文件 '%s' 不存在,将创建新文件", remotePath))
		if res, err := c.Run(CommandOptions{Sudo: 0, Content: fmt.Sprintf("touch '%s'", filepath.ToSlash(remotePath)), IsCli: true}); err != nil {
			return fmt.Errorf("远程文件 '%s' 创建失败: %v\n%s", remotePath, err, res)
		}
	}

	// 创建和配置会话
	session, scpPath, err := c.createScpSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// 准备scp命令
	cmd := fmt.Sprintf("%s -t '%s'", scpPath, remotePath)
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("创建stdin管道失败: %v", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建stdout管道失败: %v", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("创建stderr管道失败: %v", err)
	}

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("启动scp失败: %v", err)
	}

	// 启动错误监控
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if err != nil {
				if err != io.EOF {
					errCh <- fmt.Errorf("stderr读取错误: %v", err)
				}
				return
			}
			if n > 0 {
				errCh <- fmt.Errorf("scp错误: %s", string(buf[:n]))
				return
			}
		}
	}()

	// 等待响应
	buffer := make([]byte, 1)
	if n, err := stdout.Read(buffer); err != nil || n < 1 {
		return fmt.Errorf("读取响应失败: %v", err)
	}
	if buffer[0] != 0 {
		return fmt.Errorf("服务器返回错误: %v", buffer[0])
	}

	// 发送文件元数据
	header := fmt.Sprintf("C%04o %d %s\n", fileInfo.Mode().Perm(), fileInfo.Size(), filepath.Base(remotePath))
	if _, err := stdin.Write([]byte(header)); err != nil {
		return fmt.Errorf("发送文件元数据失败: %v", err)
	}

	// 创建进度条
	var bar *progressbar.ProgressBar
	if c.ShowProgress {
		bar = progressbar.DefaultBytes(
			fileInfo.Size(),
			fmt.Sprintf("上传 %s", filepath.Base(localPath)),
		)
	}

	// 读取服务器响应
	resp := make([]byte, 1)
	for {
		n, err := stdout.Read(resp)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("读取服务器响应失败: %v", err)
		}
		if n < 1 {
			continue
		}
		if resp[0] != 0 {
			// 检查错误通道是否有更详细的错误信息
			select {
			case err := <-errCh:
				return fmt.Errorf("服务器报错: %v", err)
			default:
				// 尝试从stderr读取错误信息
				errBuf := make([]byte, 1024)
				n, _ := stderr.Read(errBuf)
				if n > 0 {
					return fmt.Errorf("服务器错误: %s", string(errBuf[:n]))
				}
				return fmt.Errorf("服务器拒绝请求: %d", resp[0])
			}
		}
		break
	}

	// 分块传输文件内容
	buf := make([]byte, 32*1024) // 32KB buffer
	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("读取文件失败: %v", err)
		}

		// 发送数据块
		if _, err := stdin.Write(buf[:n]); err != nil {
			return fmt.Errorf("发送文件数据失败: %v", err)
		}

		if c.ShowProgress {
			bar.Add(n)
		}

		// 检查错误通道
		select {
		case err := <-errCh:
			return fmt.Errorf("传输过程中发生错误: %v", err)
		default:
		}
	}

	// 发送传输完成信号
	if _, err := stdin.Write([]byte{0}); err != nil {
		return fmt.Errorf("发送结束信号失败: %v", err)
	}

	// 等待服务器的最终确认
	for {
		n, err := stdout.Read(resp)
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("读取最终确认失败: %v", err)
		}
		if n < 1 {
			continue
		}
		if resp[0] != 0 {
			return fmt.Errorf("传输失败，服务器返回错误: %d", resp[0])
		}
		break
	}

	return nil
}

func (c *SCPClient) downloadFile(remotePath, localPath string) error {

	if _, err := c.Run(CommandOptions{Sudo: 0, Content: fmt.Sprintf("test -f '%s'", filepath.ToSlash(remotePath)), IsCli: true}); err != nil {
		return fmt.Errorf("远程文件<%s>不存在", remotePath)
	}

	// 创建和配置会话
	session, scpPath, err := c.createScpSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// 准备scp命令
	cmd := fmt.Sprintf("%s -f '%s'", scpPath, remotePath)
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("创建stdin管道失败: %v", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("创建stdout管道失败: %v", err)
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("创建stderr管道失败: %v", err)
	}

	if err := session.Start(cmd); err != nil {
		return fmt.Errorf("启动scp失败: %v", err)
	}

	// 启动错误监控
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stderr.Read(buf)
			if err != nil {
				if err != io.EOF {
					errCh <- fmt.Errorf("stderr读取错误: %v", err)
				}
				return
			}
			if n > 0 {
				errCh <- fmt.Errorf("scp错误: %s", string(buf[:n]))
				return
			}
		}
	}()

	// 发送准备信号
	if _, err := stdin.Write([]byte{0}); err != nil {
		return fmt.Errorf("发送准备信号失败: %v", err)
	}

	// 读取文件信息
	var mode os.FileMode
	var size int64
	var name string

	// 读取一行元数据
	buffer := make([]byte, 1024)
	var metadata string
	for i := 0; i < len(buffer); i++ {
		n, err := stdout.Read(buffer[i : i+1])
		if err != nil {
			return fmt.Errorf("读取文件信息失败: %v", err)
		}
		if n == 0 {
			return fmt.Errorf("意外的EOF")
		}
		if buffer[i] == '\n' {
			metadata = string(buffer[:i+1])
			break
		}
	}

	// 解析元数据
	metadataStr := strings.TrimSpace(metadata)
	Logger.Debug(fmt.Sprintf("收到的元数据: %q\n", metadataStr))

	// 检查元数据格式
	if !strings.HasPrefix(metadataStr, "C") {
		return fmt.Errorf("无效的文件信息格式: %q", metadataStr)
	}

	// 尝试解析
	matches := strings.Fields(metadataStr[1:]) // 跳过开头的'C'
	if len(matches) < 3 {
		return fmt.Errorf("文件信息不完整: %q", metadataStr)
	}

	// 解析模式
	modeInt := int64(0)
	if _, err := fmt.Sscanf(matches[0], "%o", &modeInt); err != nil {
		return fmt.Errorf("解析文件模式失败: %v", err)
	}
	mode = os.FileMode(modeInt)

	// 解析大小
	if _, err := fmt.Sscanf(matches[1], "%d", &size); err != nil {
		return fmt.Errorf("解析文件大小失败: %v", err)
	}

	// 获取文件名
	name = strings.Join(matches[2:], " ") // 处理文件名中可能包含的空格

	// 发送确认信号
	if _, err := stdin.Write([]byte{0}); err != nil {
		return fmt.Errorf("发送确认信号失败: %v", err)
	}

	// 确定本地文件路径
	targetPath := localPath
	if filepath.Base(localPath) == "." {
		// 如果目标路径是目录，使用原始文件名
		targetPath = filepath.Join(localPath, name)
	}

	// 创建本地文件
	file, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("创建本地文件失败: %v", err)
	}
	defer file.Close()

	// 创建进度条
	var bar *progressbar.ProgressBar
	if c.ShowProgress {
		bar = progressbar.DefaultBytes(
			size,
			fmt.Sprintf("下载 %s", filepath.Base(targetPath)),
		)
	}

	// 读取文件内容
	remaining := size
	buf := make([]byte, 32*1024) // 32KB buffer
	for remaining > 0 {
		n := int64(len(buf))
		if remaining < n {
			n = remaining
		}

		readCount, err := io.ReadFull(stdout, buf[:n])
		if err != nil {
			if err != io.ErrUnexpectedEOF {
				return fmt.Errorf("读取文件内容失败: %v", err)
			}
		}

		if readCount > 0 {
			if _, err := file.Write(buf[:readCount]); err != nil {
				return fmt.Errorf("写入文件失败: %v", err)
			}

			remaining -= int64(readCount)
			if c.ShowProgress {
				bar.Add(readCount)
			}
		}
	}

	// 发送确认信号
	if _, err := stdin.Write([]byte{0}); err != nil {
		return fmt.Errorf("发送确认信号失败: %v", err)
	}

	// 等待最终响应
	finalBuffer := make([]byte, 1)
	if _, err := stdout.Read(finalBuffer); err != nil && err != io.EOF {
		return fmt.Errorf("读取最终响应失败: %v", err)
	}

	return nil
}

func (c *SCPClient) uploadDirectory(localPath, remotePath string) error {
	// 创建远程目录
	if _, err := c.Run(CommandOptions{Sudo: 0, Content: fmt.Sprintf("mkdir -p '%s'", remotePath), IsCli: true}); err != nil {
		return fmt.Errorf("创建远程目录失败: %v", err)
	}

	return filepath.Walk(localPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 计算相对路径
		relPath, err := filepath.Rel(localPath, path)
		if err != nil {
			return fmt.Errorf("计算相对路径失败: %v", err)
		}

		// 构建远程路径
		remoteFilePath := filepath.Join(remotePath, relPath)

		if info.IsDir() {
			// 创建远程目录
			if _, err := c.Run(CommandOptions{Sudo: 0, Content: fmt.Sprintf("mkdir -p '%s'", remoteFilePath), IsCli: true}); err != nil {
				return fmt.Errorf("创建远程目录失败: %v", err)
			}
		} else {
			// 上传文件
			if err := c.uploadFile(path, remoteFilePath); err != nil {
				return fmt.Errorf("上传文件失败: %v", err)
			}
		}

		return nil
	})
}

func (c *SCPClient) downloadDirectory(remotePath, localPath string) error {
	// 创建本地目录
	if err := os.MkdirAll(localPath, 0755); err != nil {
		return fmt.Errorf("创建本地目录失败: %v", err)
	}

	// 获取远程文件列表
	output, err := c.Run(CommandOptions{Sudo: 0, Content: fmt.Sprintf("find '%s' -type f", remotePath), IsCli: true})
	if err != nil {
		return fmt.Errorf("获取远程文件列表失败: %v", err)
	}

	files := strings.Split(strings.TrimSpace(output), "\n")
	for _, remoteFile := range files {
		// 计算相对路径
		relPath, err := filepath.Rel(remotePath, remoteFile)
		if err != nil {
			return fmt.Errorf("计算相对路径失败: %v", err)
		}

		// 构建本地路径
		localFilePath := filepath.Join(localPath, relPath)

		// 确保本地目录存在
		if err := os.MkdirAll(filepath.Dir(localFilePath), 0755); err != nil {
			return fmt.Errorf("创建本地目录失败: %v", err)
		}

		// 下载文件
		if err := c.downloadFile(remoteFile, localFilePath); err != nil {
			return fmt.Errorf("下载文件失败: %v", err)
		}
	}

	return nil
}
