package sftp

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/chzyer/readline"
)

// SftpCompleter 实现 readline.AutoCompleter 接口
// 提供命令名和路径的自动补全功能
type SftpCompleter struct {
	shell *Shell
}

// Do 执行自动补全，返回候选列表和已匹配长度
func (c *SftpCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	content := string(line[:pos])

	// 场景1：补全命令名（行首无空格）
	if !strings.Contains(content, " ") {
		return c.completeCommand(content)
	}

	// 场景2：补全命令参数
	// 找到最后一个未完成的参数
	parts := strings.Fields(content)
	if len(parts) < 1 {
		return nil, 0
	}

	cmd := parts[0]

	// 计算当前正在输入的参数前缀
	// 如果内容以空格结尾，说明用户在输入新参数
	var partial string
	if strings.HasSuffix(content, " ") {
		partial = ""
	} else if len(parts) > 1 {
		partial = parts[len(parts)-1]
	} else {
		return nil, 0
	}

	switch cmd {
	case "cd", "ls", "ll", "get", "mkdir", "rm":
		return c.completeRemotePath(partial)
	case "lcd", "lls", "lll", "put":
		return c.completeLocalPath(partial)
	}

	return nil, 0
}

// completeCommand 补全命令名
func (c *SftpCompleter) completeCommand(prefix string) ([][]rune, int) {
	commands := []string{
		"exit", "quit", "bye", "help", "?",
		"pwd", "lpwd", "ls", "ll", "lls", "lll",
		"cd", "lcd", "mkdir", "rm", "get", "put",
	}

	var candidates [][]rune
	for _, cmd := range commands {
		if strings.HasPrefix(cmd, prefix) {
			// 返回需要补全的部分（去掉已输入的前缀）
			remainder := cmd[len(prefix):]
			candidates = append(candidates, []rune(remainder))
		}
	}

	if len(candidates) == 0 {
		return nil, 0
	}

	return candidates, len(prefix)
}

// completeRemotePath 补全远程路径
func (c *SftpCompleter) completeRemotePath(partial string) ([][]rune, int) {
	if c.shell == nil || c.shell.client == nil {
		return nil, 0
	}

	var dir, prefix string
	if strings.Contains(partial, "/") {
		// 包含路径分隔符，分离目录和前缀
		lastSlash := strings.LastIndex(partial, "/")
		dir = partial[:lastSlash+1]
		prefix = partial[lastSlash+1:]
	} else {
		// 不包含路径分隔符，使用当前目录
		dir = c.shell.cwd
		prefix = partial
	}

	// 处理相对路径
	if !strings.HasPrefix(dir, "/") {
		dir = c.shell.client.JoinPath(c.shell.cwd, dir)
	}

	// 读取目录内容
	entries, err := c.shell.client.sftpClient.ReadDir(dir)
	if err != nil {
		return nil, 0
	}

	var candidates [][]rune
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, prefix) {
			remainder := name[len(prefix):]
			if entry.IsDir() {
				remainder += "/"
			}
			candidates = append(candidates, []rune(remainder))
		}
	}

	if len(candidates) == 0 {
		return nil, 0
	}

	return candidates, len(prefix)
}

// completeLocalPath 补全本地路径
func (c *SftpCompleter) completeLocalPath(partial string) ([][]rune, int) {
	var dir, prefix string
	if strings.Contains(partial, string(filepath.Separator)) {
		// 包含路径分隔符，分离目录和前缀
		lastSep := strings.LastIndex(partial, string(filepath.Separator))
		dir = partial[:lastSep+1]
		prefix = partial[lastSep+1:]
	} else {
		// 不包含路径分隔符，使用当前目录
		dir = "."
		prefix = partial
	}

	// 读取目录内容
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0
	}

	var candidates [][]rune
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, prefix) {
			remainder := name[len(prefix):]
			if entry.IsDir() {
				remainder += string(filepath.Separator)
			}
			candidates = append(candidates, []rune(remainder))
		}
	}

	if len(candidates) == 0 {
		return nil, 0
	}

	return candidates, len(prefix)
}

// 确保 SftpCompleter 实现了 readline.AutoCompleter 接口
var _ readline.AutoCompleter = (*SftpCompleter)(nil)
