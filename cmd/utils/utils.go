package utils

import (
	"fmt"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// ParseAddr 解析 user@host:port 格式的字符串
func ParseAddr(input string) (string, string, uint16) {
	var user, host string = "", ""
	var port uint16 = 0
	if atIndex := strings.Index(input, ":"); atIndex != -1 {
		port = ParsePort(input[atIndex+1:])
		input = input[:atIndex]
	}
	if atIndex := strings.Index(input, "@"); atIndex != -1 {
		user = input[:atIndex]
		input = input[atIndex+1:]
	}
	host = input

	return user, host, port
}

// ParsePort 解析端口字符串
// 如果输入为空字符串，则返回0
func ParsePort(input string) uint16 {
	if input == "" {
		return 0
	}
	port64, err := strconv.ParseUint(input, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(port64)
}

func GetCurrentUser() string {
	currentUser, err := user.Current()
	if err != nil {
		return ""
	}
	return currentUser.Username
}

func GetConfigFilePath() (configPath, keyPath string) {
	user, err := user.Current()
	if err != nil {
		return "", ""
	}
	return filepath.Join(user.HomeDir, ".mtools", ConfigFileName), filepath.Join(user.HomeDir, ".mtools", ConfigKeyName)
}

func GetPasswordFilePath() string {
	user, err := user.Current()
	if err != nil {
		return ""
	}
	return filepath.Join(user.HomeDir, PasswordFileName)
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
