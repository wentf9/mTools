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
	"github.com/wentf9/xops-cli/pkg/i18n"
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

		exit, err := s.dispatchCommand(ctx, cmd, params)
		if exit {
			return err
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.printPrompt()
	}
	return scanner.Err()
}

func (s *Shell) dispatchCommand(ctx context.Context, cmd string, params []string) (bool, error) {
	switch cmd {
	case "exit", "quit", "bye":
		return true, nil
	case "help", "?":
		s.printHelp()
	case "pwd":
		_, _ = fmt.Fprintln(s.stdout, s.cwd)
	case "lpwd":
		wd, _ := os.Getwd()
		_, _ = fmt.Fprintln(s.stdout, wd)
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
		_, _ = fmt.Fprintf(s.stderr, "%s\n", i18n.Tf("sftp_shell_unknown_cmd", map[string]any{"Cmd": cmd}))
	}
	return false, nil
}

// ================= 命令处理逻辑 =================

func (s *Shell) printPrompt() {
	_, _ = fmt.Fprintf(s.stdout, "sftp:%s> ", s.cwd)
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
		_, _ = fmt.Fprintf(s.stderr, "cd: %v\n", err)
		return
	}
	if !info.IsDir() {
		_, _ = fmt.Fprintf(s.stderr, "%s\n", i18n.Tf("sftp_shell_cd_not_dir", map[string]any{"Path": args[0]}))
		return
	}
	s.cwd = target
}

func (s *Shell) handleLocalCd(args []string) {
	if len(args) == 0 {
		return
	}
	if err := os.Chdir(args[0]); err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lcd: %v\n", err)
	}
}

func (s *Shell) handleLs(args []string) {
	path := s.cwd
	if len(args) > 0 {
		path = s.resolvePath(args[0])
	}

	files, err := s.client.sftpClient.ReadDir(path)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "ls: %v\n", err)
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
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", f.Mode(), size, modTime, name)
	}
	_ = w.Flush()
}

func (s *Shell) handleLocalLs(args []string) {
	path := "."
	if len(args) > 0 {
		path = args[0]
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "lls: %v\n", err)
		return
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			name += "/"
		}
		_, _ = fmt.Fprintln(s.stdout, name)
	}
}

func (s *Shell) handleGet(ctx context.Context, args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_get_usage"))
		return
	}
	remote := s.resolvePath(args[0])
	local := filepath.Base(remote)
	if len(args) > 1 {
		local = args[1]
	}

	_, _ = fmt.Fprintln(s.stdout, i18n.Tf("sftp_shell_downloading", map[string]any{"Remote": remote, "Local": local}))

	progress := s.createProgressBar(remote)

	err := s.client.Download(ctx, remote, local, progress)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "%s\n", i18n.Tf("sftp_shell_download_failed", map[string]any{"Error": err}))
	} else {
		_, _ = fmt.Fprintln(s.stdout, i18n.T("sftp_shell_download_done"))
	}
}

func (s *Shell) handlePut(ctx context.Context, args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_put_usage"))
		return
	}
	local := args[0]
	var remote string

	if len(args) > 1 {
		remote = s.resolvePath(args[1])
	} else {
		remote = s.client.JoinPath(s.cwd, filepath.Base(local))
	}

	_, _ = fmt.Fprintln(s.stdout, i18n.Tf("sftp_shell_uploading", map[string]any{"Local": local, "Remote": remote}))

	// 计算本地文件大小以显示准确的进度条
	var totalSize int64
	_ = filepath.Walk(local, func(_ string, info os.FileInfo, _ error) error {
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})

	bar := progressbar.DefaultBytes(totalSize, "Uploading")
	callback := func(n int) { _ = bar.Add(n) }

	err := s.client.Upload(ctx, local, remote, callback)
	if err != nil {
		_, _ = fmt.Fprintf(s.stderr, "%s\n", i18n.Tf("sftp_shell_upload_failed", map[string]any{"Error": err}))
	} else {
		_, _ = fmt.Fprintln(s.stdout, i18n.T("sftp_shell_upload_done"))
	}
}

func (s *Shell) handleMkdir(args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_mkdir_usage"))
		return
	}
	path := s.resolvePath(args[0])
	if err := s.client.sftpClient.Mkdir(path); err != nil {
		_, _ = fmt.Fprintf(s.stderr, "mkdir: %v\n", err)
	}
}

func (s *Shell) handleRm(args []string) {
	if len(args) < 1 {
		_, _ = fmt.Fprintln(s.stderr, i18n.T("sftp_shell_rm_usage"))
		return
	}
	path := s.resolvePath(args[0])
	if err := s.client.sftpClient.Remove(path); err != nil {
		// 尝试作为目录删除
		if err2 := s.client.sftpClient.RemoveDirectory(path); err2 != nil {
			_, _ = fmt.Fprintf(s.stderr, "rm: %v\n", err)
		}
	}
}

func (s *Shell) printHelp() {
	_, _ = fmt.Fprintln(s.stdout, i18n.T("sftp_shell_help"))
}

// 简单的进度条辅助函数 (用于 Download，因为预先不知道 Total 只能用 spinner 或者先 Stat)
func (s *Shell) createProgressBar(remotePath string) ProgressCallback {
	// 尝试 Stat 获取大小
	info, err := s.client.sftpClient.Stat(remotePath)
	if err != nil {
		// 无法获取大小时使用无定量的 Spinner
		bar := progressbar.Default(-1, "Downloading")
		return func(n int) { _ = bar.Add(n) }
	}

	//如果是目录，Stat 只能拿到目录本身的大小，不是内容的。
	//为了响应速度，这里简化处理：如果是文件显示进度，目录则显示已传输字节数
	if info.IsDir() {
		bar := progressbar.Default(-1, "Downloading (Dir)")
		return func(n int) { _ = bar.Add(n) }
	}

	bar := progressbar.DefaultBytes(info.Size(), "Downloading")
	return func(n int) { _ = bar.Add(n) }
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
