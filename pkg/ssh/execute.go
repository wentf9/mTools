package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func (c *Client) RunWithSudo(ctx context.Context, command string) (string, error) {
	c.maybeDetectSudoMode(ctx)
	wrappedCmd := fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))

	switch c.node.SudoMode {
	case "root":
		return c.Run(ctx, command)
	case "sudo":
		return c.runWithSudo(ctx, wrappedCmd, c.identity.Password, nil)
	case "sudoer":
		return c.runWithSudo(ctx, wrappedCmd, "", nil)
	case "su":
		return c.runWithSu(command, c.node.SuPwd)
	default:
		return "", fmt.Errorf("unknown sudo mode: %s, please check config to set sudo mode", c.node.SudoMode)
	}
}

// RunScriptWithSudo 提权执行脚本
func (c *Client) RunScriptWithSudo(ctx context.Context, scriptContent string) (string, error) {
	c.maybeDetectSudoMode(ctx)
	switch c.node.SudoMode {
	case "root":
		return c.RunScript(ctx, scriptContent)
	case "sudo":
		return c.runWithSudo(ctx, "bash -l -s", c.identity.Password, strings.NewReader(scriptContent))
	case "sudoer":
		return c.runWithSudo(ctx, "bash -l -s", "", strings.NewReader(scriptContent))
	case "su":
		return c.runWithSu(fmt.Sprintf("bash -l -c '%s'", strings.ReplaceAll(scriptContent, "'", "'\\''")), c.node.SuPwd)
	default:
		return "", fmt.Errorf("unsupported sudo mode: %s", c.node.SudoMode)
	}
}

func (c *Client) runWithSudo(ctx context.Context, command string, password string, extraStdin io.Reader) (string, error) {
	if password == "" && c.node.SudoMode == "sudo" {
		return "", fmt.Errorf("sudo password is required but not provided")
	}

	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = session.Close() }()

	if password != "" {
		if extraStdin != nil {
			session.Stdin = io.MultiReader(strings.NewReader(password+"\n"), extraStdin)
		} else {
			session.Stdin = strings.NewReader(password + "\n")
		}
	} else if extraStdin != nil {
		session.Stdin = extraStdin
	}

	fullCmd := fmt.Sprintf("sudo -S -p '' %s", command)
	return startWithTimeout(ctx, session, fullCmd)
}

func (c *Client) runWithSu(command string, password string) (string, error) {
	session, err := c.sshClient.NewSession()
	if err != nil {
		return "", err
	}
	defer func() { _ = session.Close() }()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
		return "", fmt.Errorf("request for pty failed: %w", err)
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		return "", err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return "", err
	}

	cmd := fmt.Sprintf("export LC_ALL=C; su - root -c '%s'", strings.ReplaceAll(command, "'", "'\\''"))

	if err := session.Start(cmd); err != nil {
		return "", fmt.Errorf("failed to start command: %w", err)
	}

	var outputBuf bytes.Buffer
	passwordPromptFound := make(chan bool)

	go func() {
		buf := make([]byte, 1024)
		found := false
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				outputBuf.Write(chunk)
				if !found && (strings.Contains(string(chunk), "assword:") || strings.Contains(string(chunk), "密码")) {
					found = true
					passwordPromptFound <- true
				}
			}
			if err != nil {
				if !found {
					close(passwordPromptFound)
				}
				break
			}
		}
	}()

	select {
	case <-passwordPromptFound:
		_, err = stdin.Write([]byte(password + "\n"))
		if err != nil {
			return "", fmt.Errorf("failed to send password: %w", err)
		}
	case <-time.After(5 * time.Second):
		return outputBuf.String(), fmt.Errorf("timeout waiting for password prompt")
	}

	err = session.Wait()
	cleanOutput := cleanSuOutput(outputBuf.String())
	if err != nil {
		return cleanOutput, fmt.Errorf("command execution failed: %w", err)
	}

	return cleanOutput, nil
}

func (c *Client) ShellWithSudo(ctx context.Context) error {
	c.maybeDetectSudoMode(ctx)
	if c.node.SudoMode == "root" {
		return c.Shell(ctx)
	}
	session, err := c.sshClient.NewSession()
	if err != nil {
		return err
	}
	defer func() { _ = session.Close() }()
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	fdIn := int(os.Stdin.Fd())
	fdOut := int(os.Stdout.Fd())
	width, height, err := term.GetSize(fdOut)
	if err != nil {
		width, height = 80, 40
	}
	if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
		return fmt.Errorf("request for pty failed: %w", err)
	}
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	stderr, _ := session.StderrPipe()

	if err := session.Shell(); err != nil {
		return fmt.Errorf("start Shell failed: %w", err)
	}

	oldState, err := term.MakeRaw(fdIn)
	if err != nil {
		return fmt.Errorf("can not set term to Raw : %w", err)
	}
	defer func() { _ = term.Restore(fdIn, oldState) }()

	go func() {
		lastW, lastH := width, height
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			currW, currH, _ := term.GetSize(fdOut)
			if currW != lastW || currH != lastH {
				_ = session.WindowChange(currH, currW)
				lastW, lastH = currW, currH
			}
		}
	}()

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
	case "root":
		sudoCmd = ""
		password = ""
	default:
		sudoCmd = ""
	}
	_, _ = stdin.Write([]byte(sudoCmd + "\n"))

	if password == "" {
		go func() { _, _ = io.Copy(os.Stdout, stdout) }()
		go func() { _, _ = io.Copy(os.Stderr, stderr) }()
		go func() { _, _ = io.Copy(stdin, os.Stdin) }()
		return session.Wait()
	}
	buf := make([]byte, 1024)
	var outputHistory bytes.Buffer
	passwordSent := false
	done := make(chan struct{})

	go func() {
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
			if passwordSent {
				continue
			}
			outputHistory.Write(chunk)
			text := outputHistory.String()
			if outputHistory.Len() > 500 {
				outputHistory.Reset()
			}
			if strings.Contains(strings.ToLower(text), "assword") || strings.Contains(text, "密码") {
				_, _ = stdin.Write([]byte(password + "\n"))
				_ = true
				break HandshakeLoop
			}
		}
	}

	go func() { _, _ = io.Copy(os.Stdout, stdout) }()
	go func() { _, _ = io.Copy(os.Stderr, stderr) }()
	go func() { _, _ = io.Copy(stdin, os.Stdin) }()

	return session.Wait()
}

func cleanSuOutput(raw string) string {
	lines := strings.Split(raw, "\n")
	var result []string
	for _, line := range lines {
		trimLine := strings.TrimSpace(line)
		if strings.Contains(trimLine, "assword:") || trimLine == "" || strings.Contains(trimLine, "密码") {
			continue
		}
		result = append(result, line)
	}
	return strings.Join(result, "\n")
}
