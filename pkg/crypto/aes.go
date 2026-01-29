package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const (
	// Prefix 用于标识加密字段的前缀，方便配置文件解析
	Prefix = "ENC:"
)

// Crypter 封装了 AES-GCM 的操作
type Crypter struct {
	gcm cipher.AEAD
}

// NewCrypter 创建一个新的加解密实例
// key 必须是 32 字节 (AES-256)
func NewCrypter(key []byte) (*Crypter, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: expected 32 bytes, got %d", len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Crypter{gcm: gcm}, nil
}

// Encrypt 加密字符串
// 输出格式: ENC:<Base64(Nonce + Ciphertext)>
func (c *Crypter) Encrypt(plaintext string) (string, error) {
	// 1. 生成随机 Nonce (Number used once)
	// GCM 标准 Nonce 长度为 12 字节
	nonce := make([]byte, c.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// 2. 加密 (Seal)
	// Seal 会将结果追加到第一个参数 (dst) 后面，这里我们将 Nonce 作为前缀一并存储
	ciphertext := c.gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	// 3. Base64 编码并添加前缀
	return Prefix + base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 解密字符串
// 输入格式必须以 ENC: 开头
func (c *Crypter) Decrypt(encoded string) (string, error) {
	// 1. 检查格式
	if !strings.HasPrefix(encoded, Prefix) {
		return "", fmt.Errorf("invalid format: missing '%s' prefix", Prefix)
	}

	// 2. Base64 解码
	raw := strings.TrimPrefix(encoded, Prefix)
	data, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}

	// 3. 分离 Nonce 和 Ciphertext
	nonceSize := c.gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]

	// 4. 解密 (Open)
	plaintext, err := c.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return string(plaintext), nil
}

// IsEncrypted 辅助函数：判断字符串是否是加密格式
func IsEncrypted(s string) bool {
	return strings.HasPrefix(s, Prefix)
}
