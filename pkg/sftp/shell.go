package sftp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/schollz/progressbar/v3"
)

// Shell 定义交互式 SFTP 环境
type Shell struct {
	client *Client
	cwd    string    // 远程当前目录
	stdin  io.Reader // 输入源
	stdout io.Writer // 输出源
	stderr io.Writer // 错误输出源
}

// NewShell 创建一个新的交互式 Shell
func (c *Client) NewShell(stdin io.Reader, stdout, stderr io.Writer) (*Shell, error) {
	// 获取初始远程目录
	cwd, err := c.sftpClient.Getwd()
	if err != nil {
		cwd = "."
	}

	return &Shell{
		client: c,
		cwd:    cwd,
		stdin:  stdin,
		stdout: stdout,
		stderr: stderr,
	}, nil
}

// Run 启动交互式循环 (REPL)
func (s *Shell) Run(ctx context.Context) error {
	scanner := bufio.NewScanner(s.stdin)
	s.printPrompt()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			s.printPrompt()
			continue
		}

		args := strings.Fields(line)
		cmd := args[0]
		params := args[1:]

		// 处理命令
		switch cmd {
		case "exit", "quit", "bye":
			return nil
		case "help", "?":
			s.printHelp()
		case "pwd":
			fmt.Fprintln(s.stdout, s.cwd)
		case "lpwd":
			wd, _ := os.Getwd()
			fmt.Fprintln(s.stdout, wd)
		case "ls", "ll":
			s.handleLs(params)
		case "lls":
			s.handleLocalLs(params)
		case "cd":
			s.handleCd(params)
		case "lcd":
			s.handleLocalCd(params)
		case "mkdir":
			s.handleMkdir(params)
		case "rm":
			s.handleRm(params)
		case "get":
			s.handleGet(ctx, params)
		case "put":
			s.handlePut(ctx, params)
		default:
			fmt.Fprintf(s.stderr, "未知命令: %s (输入 help 查看可用命令)\n", cmd)
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.printPrompt()
	}
	return scanner.Err()
}

// ================= 命令处理逻辑 =================

func (s *Shell) printPrompt() {
	fmt.Fprintf(s.stdout, "sftp:%s> ", s.cwd)
}

func (s *Shell) resolvePath(p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return s.client.JoinPath(s.cwd, p)
}

func (s *Shell) handleCd(args []string) {
	if len(args) == 0 {
		return
	}
	target := s.resolvePath(args[0])

	// 检查目录是否存在
	info, err := s.client.sftpClient.Stat(target)
	if err != nil {
		fmt.Fprintf(s.stderr, "cd: %v\n", err)
		return
	}
	if !info.IsDir() {
		fmt.Fprintf(s.stderr, "cd: '%s' 不是目录\n", args[0])
		return
	}
	s.cwd = target
}

func (s *Shell) handleLocalCd(args []string) {
	if len(args) == 0 {
		return
	}
	if err := os.Chdir(args[0]); err != nil {
		fmt.Fprintf(s.stderr, "lcd: %v\n", err)
	}
}

func (s *Shell) handleLs(args []string) {
	path := s.cwd
	if len(args) > 0 {
		path = s.resolvePath(args[0])
	}

	files, err := s.client.sftpClient.ReadDir(path)
	if err != nil {
		fmt.Fprintf(s.stderr, "ls: %v\n", err)
		return
	}

	// 使用 tabwriter 格式化输出
	w := tabwriter.NewWriter(s.stdout, 0, 0, 1, ' ', 0)
	for _, f := range files {
		// 简单的类似 ls -l 的输出
		modTime := f.ModTime().Format("Jan 02 15:04")
		size := formatBytes(f.Size())
		name := f.Name()
		if f.IsDir() {
			name += "/"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Mode(), size, modTime, name)
	}
	w.Flush()
}

func (s *Shell) handleLocalLs(args []string) {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		fmt.Fprintf(s.stderr, "lls: %v\n", err)
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		fmt.Fprintln(s.stdout, name)
	}
}

func (s *Shell) handleGet(ctx context.Context, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(s.stderr, "用法: get <远程文件> [本地路径]")
		return
	}
	remote := s.resolvePath(args[0])
	local := filepath.Base(remote)
	if len(args) > 1 {
		local = args[1]
	}

	fmt.Fprintf(s.stdout, "下载 %s -> %s\n", remote, local)

	// 创建进度条回调
	progress := s.createProgressBar(remote) // 预估大小可能需要 Stat，这里简化处理

	err := s.client.Download(ctx, remote, local, progress)
	if err != nil {
		fmt.Fprintf(s.stderr, "下载失败: %v\n", err)
	} else {
		fmt.Fprintln(s.stdout, "\n下载完成")
	}
}

func (s *Shell) handlePut(ctx context.Context, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(s.stderr, "用法: put <本地文件> [远程路径]")
		return
	}
	local := args[0]
	remote := s.cwd
	if len(args) > 1 {
		remote = s.resolvePath(args[1])
	} else {
		// 默认上传到当前目录
		remote = s.client.JoinPath(s.cwd, filepath.Base(local))
	}

	fmt.Fprintf(s.stdout, "上传 %s -> %s\n", local, remote)

	// 计算本地文件大小以显示准确的进度条
	var totalSize int64
	filepath.Walk(local, func(_ string, info os.FileInfo, _ error) error {
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})

	bar := progressbar.DefaultBytes(totalSize, "Uploading")
	callback := func(n int) { bar.Add(n) }

	err := s.client.Upload(ctx, local, remote, callback)
	if err != nil {
		fmt.Fprintf(s.stderr, "\n上传失败: %v\n", err)
	} else {
		fmt.Fprintln(s.stdout, "\n上传完成")
	}
}

func (s *Shell) handleMkdir(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(s.stderr, "用法: mkdir <路径>")
		return
	}
	path := s.resolvePath(args[0])
	if err := s.client.sftpClient.Mkdir(path); err != nil {
		fmt.Fprintf(s.stderr, "mkdir: %v\n", err)
	}
}

func (s *Shell) handleRm(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(s.stderr, "用法: rm <路径>")
		return
	}
	path := s.resolvePath(args[0])
	if err := s.client.sftpClient.Remove(path); err != nil {
		// 尝试作为目录删除
		if err2 := s.client.sftpClient.RemoveDirectory(path); err2 != nil {
			fmt.Fprintf(s.stderr, "rm: %v\n", err)
		}
	}
}

func (s *Shell) printHelp() {
	help := `
可用命令:
  cd <path>     切换远程目录
  lcd <path>    切换本地目录
  pwd           显示远程当前目录
  lpwd          显示本地当前目录
  ls [path]     列出远程文件
  lls [path]    列出本地文件
  get <remote> [local]  下载文件或目录
  put <local> [remote]  上传文件或目录
  mkdir <path>  创建远程目录
  rm <path>     删除远程文件或目录
  exit/quit     退出
`
	fmt.Fprintln(s.stdout, help)
}

// 简单的进度条辅助函数 (用于 Download，因为预先不知道 Total 只能用 spinner 或者先 Stat)
func (s *Shell) createProgressBar(remotePath string) ProgressCallback {
	// 尝试 Stat 获取大小
	info, err := s.client.sftpClient.Stat(remotePath)
	if err != nil {
		// 无法获取大小时使用无定量的 Spinner
		bar := progressbar.Default(-1, "Downloading")
		return func(n int) { bar.Add(n) }
	}

	//如果是目录，Stat 只能拿到目录本身的大小，不是内容的。
	//为了响应速度，这里简化处理：如果是文件显示进度，目录则显示已传输字节数
	if info.IsDir() {
		bar := progressbar.Default(-1, "Downloading (Dir)")
		return func(n int) { bar.Add(n) }
	}

	bar := progressbar.DefaultBytes(info.Size(), "Downloading")
	return func(n int) { bar.Add(n) }
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
