package utils

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
)

type Command struct {
	// Sudo    uint8 // 0: 不使用sudo, 1: 使用sudo, 2: 使用su
	Content string
	context.Context
	// IsCli   bool // 是否是命令行 true: 是命令行 false: 是shell脚本
}

type SudoKey struct{}
type IsShellKey struct{}

// type CommandResult struct {
// 	Success bool
// 	Output  string
// 	Error   error
// }

type Executor interface {
	Execute(command Command) (string, error)
}

func (c Command) WithContext(ctx context.Context) Command {
	c.Context = ctx
	return c
}

func (c Command) Execute(executor Executor) (string, error) {
	return executor.Execute(c)
}

func NewSSHCommand(content string, sudo uint8, isShell bool) Command {
	ctx := context.Background()
	ctx = context.WithValue(ctx, SudoKey{}, sudo)
	ctx = context.WithValue(ctx, IsShellKey{}, isShell)
	return Command{
		Content: content,
		Context: ctx,
	}
}

func SSHCmdExecute(content string, executor Executor) (string, error) {
	cmd := NewSSHCommand(content, 0, false)
	return cmd.Execute(executor)
}

func SSHCmdExecuteWithSudo(content string, executor Executor) (string, error) {
	cmd := NewSSHCommand(content, 1, false)
	return cmd.Execute(executor)
}

func NewLocalCommand(content string, sudo uint8, isShell bool) Command {
	ctx := context.Background()
	ctx = context.WithValue(ctx, SudoKey{}, sudo)
	ctx = context.WithValue(ctx, IsShellKey{}, isShell)
	return Command{
		Content: content,
		Context: ctx,
	}
}

func LocalCmdExecute(content string, executor Executor) (string, error) {
	cmd := NewLocalCommand(content, 0, false)
	return cmd.Execute(executor)
}

func LocalCmdExecuteWithSudo(content string, executor Executor) (string, error) {
	cmd := NewLocalCommand(content, 1, false)
	return cmd.Execute(executor)
}

type LocalExecutor struct{}

func (le *LocalExecutor) checkContext(cmd Command) (bool, uint8) {
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

func (le *LocalExecutor) Execute(command Command) (string, error) {
	isShell, sudo := le.checkContext(command)
	if sudo != 0 {
		return le.executeWithSudo(command, isShell)
	}
	var cmd *exec.Cmd
	if isShell {
		Logger.Debug("当前命令是shell脚本")
		cmd = exec.Command("bash", command.Content)
	} else {
		Logger.Debug("当前命令是命令行命令")
		cmd = exec.Command("bash", "-c", command.Content)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("执行命令失败: %v|命令输出: %s", err, string(output))
	}
	return string(output), nil
}

func (le *LocalExecutor) executeWithSudo(command Command, isShell bool) (string, error) {
	rootCheckCmd := exec.Command("bash", "-c", "test `id -u` -eq 0 && echo yes || echo no")
	out, err := rootCheckCmd.CombinedOutput()

	if err == nil && string(bytes.TrimSpace(out)) == "yes" {
		// 已经是root用户，直接执行命令
		var c *exec.Cmd
		if isShell {
			Logger.Debug("当前命令是shell脚本,当前已经是root环境")
			c = exec.Command("bash", "-c", fmt.Sprintf("bash '%s'", command.Content))
		} else {
			Logger.Debug("当前命令是命令行命令,当前已经是root环境")
			c = exec.Command("bash", "-c", command.Content)
		}
		output, err := c.CombinedOutput()
		return string(output), err
	}
	passwords, err := LoadPasswords()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load passwords: %v\n", err)
		passwords = NewPasswordStore()
	}
	passwordModified := false
	currentOsUser := GetCurrentUser()
	localPassword := ""
	passCount := 0
	maxAttempts := 3
	if storedPass, ok := passwords.GetPass(currentOsUser, "localhost"); ok {
		localPassword = storedPass
	}
	for {
		if localPassword == "" {
			// 如果没有保存的密码，从终端读取
			newPass, err := ReadPasswordFromTerminal(fmt.Sprintf("请输入 %s@%s 的密码: ", currentOsUser, "localhost"))
			if err == nil {
				localPassword = newPass
				passCount++
			} else {
				return "", fmt.Errorf("读取密码失败: %v", err)
			}
		}
		sshClient := SSHCli{
			Host: "localhost",
			User: currentOsUser,
			Pwd:  localPassword,
			Port: 22,
		}
		err = sshClient.Connect()
		if err != nil {
			if passCount < maxAttempts {
				fmt.Fprintf(os.Stderr, "连接到本地主机失败: %v\n请重新输入密码\n", err)
				localPassword = ""
				continue
			}
			return "", fmt.Errorf("连接到本地主机失败: %v", err)
		}
		passwordModified = passwords.SaveOrUpdate(currentOsUser, "localhost", localPassword)
		sshClient.Close()
		break
	}
	if passwordModified {
		if err := passwords.Save2File(); err != nil {
			fmt.Fprintf(os.Stderr, "保存密码到文件失败: %v", err)
		} else {
			Logger.Info(fmt.Sprintf("密码已保存到文件: %s@%s", currentOsUser, "localhost"))
		}
	}
	var cmd *exec.Cmd
	if isShell {
		Logger.Debug("当前命令是shell脚本,使用sudo执行")
		cmd = exec.Command("bash", "-c", fmt.Sprintf("sudo -S bash '%s'", command.Content))
	} else {
		Logger.Debug("当前命令是命令行命令,使用sudo执行")
		cmd = exec.Command("bash", "-c", fmt.Sprintf("sudo -S %s", command.Content))
	}
	stdin, err := cmd.StdinPipe()
	// 使用管道获取输出
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	cmd.Stderr = pw
	defer pw.Close()
	defer pr.Close()
	if err != nil {
		return "", fmt.Errorf("创建stdin管道失败: %v", err)
	}
	defer stdin.Close()
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("命令启动失败: %v", err)
	}
	// 发送密码
	stdin.Write([]byte(localPassword + "\n"))
	Logger.Debug("已发送sudo密码")
	// 获取输出
	var output bytes.Buffer
	go func() {
		io.Copy(&output, pr)
	}()
	// 等待命令完成
	if err := cmd.Wait(); err != nil {
		return output.String(), fmt.Errorf("命令执行失败: %v", err)
	}
	Logger.Debug("命令执行完成,开始处理输出")
	Logger.Debug(fmt.Sprintf("原始输出 -> %s", output.String()))
	regex := regexp.MustCompile(`\[sudo\].+:`)
	// regex := regexp.MustCompile(`.*#.*`)
	outputStr := regex.ReplaceAllString(output.String(), "")
	return outputStr, err
}
