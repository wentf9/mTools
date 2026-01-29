package crypto

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

const KeySize = 32 // AES-256 需要 32 字节密钥

// LoadOrGenerateKey 尝试从指定路径加载密钥
// 如果文件不存在，会自动生成一个新的随机密钥并保存，权限设置为 0600
func LoadOrGenerateKey(path string) ([]byte, error) {
	// 1. 尝试读取现有密钥
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != KeySize {
			return nil, fmt.Errorf("invalid key file size in '%s': expected %d, got %d", path, KeySize, len(key))
		}
		return key, nil
	}

	// 如果错误不是"文件不存在"，则直接返回错误
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// 2. 生成新密钥
	key = make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// 3. 确保目录存在
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory '%s': %w", dir, err)
	}

	// 4. 保存密钥 (非常重要：设置 0600 权限，仅所有者可读写)
	if err := os.WriteFile(path, key, 0600); err != nil {
		return nil, fmt.Errorf("failed to save key file: %w", err)
	}

	return key, nil
}
