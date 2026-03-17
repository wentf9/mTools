package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestToAbsolutePath(t *testing.T) {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()

	tests := []struct {
		name        string
		input       string
		wantContain string // 使用包含检查而非精确匹配
	}{
		{
			name:        "empty string",
			input:       "",
			wantContain: "",
		},
		{
			name:        "tilde expansion",
			input:       "~/.ssh/id_rsa",
			wantContain: filepath.Join(home, ".ssh", "id_rsa"),
		},
		{
			name:        "tilde only",
			input:       "~",
			wantContain: home,
		},
		{
			name:        "relative path converted to absolute",
			input:       ".ssh/id_rsa",
			wantContain: filepath.Join(cwd, ".ssh", "id_rsa"),
		},
		{
			name:        "dot relative path",
			input:       "./id_rsa",
			wantContain: filepath.Join(cwd, "id_rsa"),
		},
		{
			name:        "parent relative path",
			input:       "../id_rsa",
			wantContain: filepath.Join(cwd, "..", "id_rsa"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToAbsolutePath(tt.input)
			if result != tt.wantContain {
				t.Errorf("ToAbsolutePath(%q) = %q, want %q", tt.input, result, tt.wantContain)
			}
		})
	}
}

func TestToAbsolutePath_AbsolutePath(t *testing.T) {
	// 测试绝对路径行为：在 Windows 和 Linux 上行为不同
	// 在 Windows 上，/home/user/id_rsa 会被转换为 D:\home\user\id_rsa
	// 这是 filepath.Abs 的预期行为
	absPath := "/home/user/.ssh/id_rsa"
	result := ToAbsolutePath(absPath)
	// 验证结果是绝对路径
	if !filepath.IsAbs(result) {
		t.Errorf("ToAbsolutePath(%q) = %q, should be absolute path", absPath, result)
	}
}
