package utils

import (
	"fmt"
	"net"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"example.com/MikuTools/pkg/config"
	"golang.org/x/term"
)

// GetLocalSudoPassword 尝试从配置文件中获取本地 sudo 密码
func GetLocalSudoPassword() string {
	configPath, keyPath := GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return ""
	}
	provider := config.NewProvider(cfg)

	// 尝试查找别名为 "localhost" 或 "local" 的节点
	nodeId := provider.Find("localhost")
	if nodeId == "" {
		nodeId = provider.Find("local")
	}
	if nodeId == "" {
		// 尝试当前用户名
		nodeId = provider.Find(GetCurrentUser())
	}

	if nodeId != "" {
		if id, ok := provider.GetIdentity(nodeId); ok {
			return id.Password
		}
	}
	return ""
}

// ParseAddr 解析 user@host:port 格式的字符串
func ParseAddr(input string) (string, string, uint16) {
	var user, host string = "", ""
	var port uint16 = 0
	if atIndex := strings.Index(input, ":"); atIndex != -1 {
		port = ParsePort(input[atIndex+1:])
		input = input[:atIndex]
	}
	if atIndex := strings.Index(input, "@"); atIndex != -1 {
		user = strings.TrimSpace(input[:atIndex])
		input = input[atIndex+1:]
	}
	host = strings.TrimSpace(input)

	return user, host, port
}

// ParseHost 解析 host:port 格式的字符串
func ParseHost(input string) (string, uint16) {
	var host string = ""
	var port uint16 = 0
	if atIndex := strings.Index(input, ":"); atIndex != -1 {
		port = ParsePort(input[atIndex+1:])
		input = input[:atIndex]
	}
	host = input
	return host, port
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

// IsValidIP 检查给定的字符串是否是有效的IPv4/IPv6地址
// 返回true表示是有效的IP地址，false表示无效
func IsValidIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil
}

// IsValidCIDR 检查给定的字符串是否是有效的CIDR表示法
// 返回true表示是有效的CIDR，false表示无效
func IsValidCIDR(cidrStr string) bool {
	_, _, err := net.ParseCIDR(cidrStr)
	return err == nil
}
