package sftp

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDispatchCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	s := &Shell{
		cwd:    "/test/remote/dir",
		stdout: &stdout,
		stderr: &stderr,
	}

	tests := []struct {
		name       string
		cmd        string
		params     []string
		wantExit   bool
		wantErr    bool
		wantOutput string
	}{
		{"exit command", "exit", nil, true, false, ""},
		{"quit command", "quit", nil, true, false, ""},
		{"bye command", "bye", nil, true, false, ""},
		{"pwd command", "pwd", nil, false, false, "/test/remote/dir\n"},
		{"help command", "help", nil, false, false, "可用命令:"},
		{"unknown command", "unknown_cmd", nil, false, false, "未知命令: unknown_cmd"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout.Reset()
			stderr.Reset()

			exit, err := s.dispatchCommand(context.Background(), tt.cmd, tt.params)
			if exit != tt.wantExit {
				t.Errorf("dispatchCommand() exit = %v, want %v", exit, tt.wantExit)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("dispatchCommand() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Validate outputs
			out := stdout.String()
			errout := stderr.String()

			if tt.name == "unknown command" {
				if !strings.Contains(errout, tt.wantOutput) {
					t.Errorf("stderr output = %q, want it to contain %q", errout, tt.wantOutput)
				}
			} else if tt.cmd == "pwd" || tt.cmd == "help" {
				if !strings.Contains(out, tt.wantOutput) {
					t.Errorf("stdout output = %q, want it to contain %q", out, tt.wantOutput)
				}
			}
		})
	}
}
