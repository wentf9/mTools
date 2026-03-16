package logger

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

const ansiEscape = "\033"

func TestSetColorMode_Never(t *testing.T) {
	SetColorMode("never")
	if ColorEnabled() {
		t.Error("expected ColorEnabled false when mode is never")
	}
}

func TestSetColorMode_Always(t *testing.T) {
	SetColorMode("always")
	if !ColorEnabled() {
		t.Error("expected ColorEnabled true when mode is always")
	}
}

func TestSetColorMode_AutoRespectsNO_COLOR(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	SetColorMode("auto")
	if ColorEnabled() {
		t.Error("expected ColorEnabled false when NO_COLOR is set")
	}
	t.Setenv("NO_COLOR", "")
}

func TestPrintInfo_NoANSIWhenDisabled(t *testing.T) {
	SetColorMode("never")
	defer SetColorMode("auto")

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	PrintInfo("test message")

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()
	if strings.Contains(out, ansiEscape) {
		t.Errorf("output should not contain ANSI escape when disabled, got %q", out)
	}
	if !strings.Contains(out, "test message") {
		t.Errorf("output should contain message, got %q", out)
	}
}

func TestPrintInfo_ANSIWhenEnabled(t *testing.T) {
	SetColorMode("always")
	defer SetColorMode("auto")

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w

	PrintInfo("test message")

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()
	if !strings.Contains(out, ansiEscape) {
		t.Errorf("output should contain ANSI escape when enabled, got %q", out)
	}
	if !strings.Contains(out, "test message") {
		t.Errorf("output should contain message, got %q", out)
	}
}

func TestPrintError_NoANSIWhenDisabled(t *testing.T) {
	SetColorMode("never")
	defer SetColorMode("auto")

	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	PrintError("error message")

	_ = w.Close()
	os.Stderr = old

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	out := buf.String()
	if strings.Contains(out, ansiEscape) {
		t.Errorf("stderr should not contain ANSI escape when disabled, got %q", out)
	}
	if !strings.Contains(out, "error message") {
		t.Errorf("output should contain message, got %q", out)
	}
}
