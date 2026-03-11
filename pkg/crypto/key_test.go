package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateKey_NewKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "subdir", "config.key")

	key, err := LoadOrGenerateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrGenerateKey failed: %v", err)
	}

	if len(key) != KeySize {
		t.Errorf("key size = %d, want %d", len(key), KeySize)
	}

	// 验证文件已创建
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}

	// 验证文件权限 (0600)
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("key file permissions = %o, want 0600", perm)
	}
}

func TestLoadOrGenerateKey_ExistingKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "config.key")

	// 先生成
	key1, err := LoadOrGenerateKey(keyPath)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// 再加载
	key2, err := LoadOrGenerateKey(keyPath)
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	// 两次应返回相同的 key
	if string(key1) != string(key2) {
		t.Error("loading existing key should return the same bytes")
	}
}

func TestLoadOrGenerateKey_InvalidSize(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "bad.key")

	// 写入一个错误大小的文件
	if err := os.WriteFile(keyPath, []byte("too-short"), 0600); err != nil {
		t.Fatalf("failed to create bad key file: %v", err)
	}

	_, err := LoadOrGenerateKey(keyPath)
	if err == nil {
		t.Error("expected error for invalid key size")
	}
}
