package ssh

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/wentf9/xops-cli/pkg/models"
)

func TestGetSudoParams(t *testing.T) {
	tests := []struct {
		name        string
		mode        models.SudoMode
		password    string
		suPwd       string
		expectedCmd string
		expectedPwd string
	}{
		{"sudo mode", models.SudoModeSudo, "mypass", "", "sudo -i", "mypass"},
		{"sudoer mode", models.SudoModeSudoer, "mypass", "", "sudo -i", ""},
		{"su mode", models.SudoModeSu, "", "rootpass", "su -", "rootpass"},
		{"root mode", models.SudoModeRoot, "", "", "", ""},
		{"invalid mode", models.SudoMode("unknown"), "", "", "", ""},
		{"empty mode", models.SudoModeNone, "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &Client{
				node: models.Node{
					SudoMode: tt.mode,
					SuPwd:    tt.suPwd,
				},
				identity: models.Identity{
					Password: tt.password,
				},
			}

			cmd, pwd := c.getSudoParams()
			if cmd != tt.expectedCmd {
				t.Errorf("expected cmd %q, got %q", tt.expectedCmd, cmd)
			}
			if pwd != tt.expectedPwd {
				t.Errorf("expected pwd %q, got %q", tt.expectedPwd, pwd)
			}
		})
	}
}

func TestProcessSuOutputForPassword(t *testing.T) {
	stdout := bytes.NewBufferString("some output\nPassword: ")
	outputBuf := &bytes.Buffer{}
	foundCh := make(chan bool, 1)

	go processSuOutputForPassword(stdout, foundCh, outputBuf)

	select {
	case found := <-foundCh:
		if !found {
			t.Errorf("expected true, got false")
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timeout waiting for password prompt")
	}

	if !strings.Contains(outputBuf.String(), "Password:") {
		t.Errorf("expected output buffer to contain 'Password:', got %q", outputBuf.String())
	}
}

func TestHandlePasswordHandshake(t *testing.T) {
	stdout := bytes.NewBufferString("some output\n[sudo] password for user: ")
	stdin := &bytes.Buffer{}

	handlePasswordHandshake(stdout, stdin, "mypassword")

	if stdin.String() != "mypassword\n" {
		t.Errorf("expected 'mypassword\\n', got %q", stdin.String())
	}
}
