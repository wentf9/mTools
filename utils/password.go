package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/term"
)

const (
	passwordFileName = ".mtool_passwords.json"
	keyFileName      = ".mtool_key"
)

// EncryptedPassword 存储加密后的密码和用于解密的随机向量
type EncryptedPassword struct {
	Ciphertext string `json:"ciphertext"`
	IV         string `json:"iv"`
}

type PasswordStore map[string]EncryptedPassword

// 获取或生成加密密钥
func getEncryptionKey() ([]byte, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(homeDir, keyFileName)

	// 尝试读取现有的密钥
	key, err := os.ReadFile(keyPath)
	if err == nil && len(key) == 32 {
		return key, nil
	}

	// 生成新的随机密钥
	key = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}

	// 保存密钥
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, err
	}

	return key, nil
}

// 加密密码
func encryptPassword(password string) (EncryptedPassword, error) {
	key, err := getEncryptionKey()
	if err != nil {
		return EncryptedPassword{}, fmt.Errorf("获取加密密钥失败: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return EncryptedPassword{}, err
	}

	// 生成随机IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return EncryptedPassword{}, err
	}

	// 加密密码
	paddedPassword := pkcs7Padding([]byte(password), aes.BlockSize)
	ciphertext := make([]byte, len(paddedPassword))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPassword)

	return EncryptedPassword{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		IV:         base64.StdEncoding.EncodeToString(iv),
	}, nil
}

// 解密密码
func decryptPassword(ep EncryptedPassword) (string, error) {
	key, err := getEncryptionKey()
	if err != nil {
		return "", fmt.Errorf("获取加密密钥失败: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(ep.Ciphertext)
	if err != nil {
		return "", err
	}

	iv, err := base64.StdEncoding.DecodeString(ep.IV)
	if err != nil {
		return "", err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("密文长度不是块大小的整数倍")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	unpaddedPlaintext, err := pkcs7Unpadding(plaintext)
	if err != nil {
		return "", err
	}

	return string(unpaddedPlaintext), nil
}

// PKCS7 填充
func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// PKCS7 去除填充
func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("数据长度为0")
	}
	padding := int(data[length-1])
	if padding > aes.BlockSize || padding == 0 {
		return nil, fmt.Errorf("无效的填充")
	}
	for i := 0; i < padding; i++ {
		if data[length-1-i] != byte(padding) {
			return nil, fmt.Errorf("填充无效")
		}
	}
	return data[:length-padding], nil
}

func getPasswordFilePath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, passwordFileName), nil
}

func LoadPasswords() (PasswordStore, error) {
	path, err := getPasswordFilePath()
	if err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return make(PasswordStore), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return make(PasswordStore), nil
	}

	var store PasswordStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}
	return store, nil
}

func (ps PasswordStore) Save() error {
	path, err := getPasswordFilePath()
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func (ps PasswordStore) Get(user, ip string) (string, bool) {
	key := fmt.Sprintf("%s@%s", user, ip)
	encPass, ok := ps[key]
	if !ok {
		return "", false
	}
	pass, err := decryptPassword(encPass)
	if err != nil {
		return "", false
	}
	return pass, true
}

func (ps PasswordStore) Set(user, ip, password string) error {
	key := fmt.Sprintf("%s@%s", user, ip)
	encPass, err := encryptPassword(password)
	if err != nil {
		return fmt.Errorf("加密密码失败: %v", err)
	}
	ps[key] = encPass
	return nil
}

// ReadPasswordFromTerminal 从终端安全地读取密码
func ReadPasswordFromTerminal(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // 打印换行符，因为 ReadPassword 不会打印换行符
	if err != nil {
		return "", err
	}
	return string(password), nil
}
