package utils

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/wentf9/xops-cli/pkg/config"
	"golang.org/x/term"
)

// GetConfigStore 返回配置存储、Provider、配置对象及其可能发生的错误
func GetConfigStore() (config.Store, config.ConfigProvider, *config.Configuration, error) {
	configPath, keyPathCfg := GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPathCfg)
	cfg, err := configStore.Load()
	if err != nil {
		return nil, nil, nil, err
	}
	return configStore, config.NewProvider(cfg), cfg, nil
}

// GetLocalSudoPassword 尝试从配置文件中获取本地 sudo 密码
func GetLocalSudoPassword() string {
	_, provider, _, err := GetConfigStore()
	if err != nil {
		return ""
	}

	nodeID := provider.Find("localhost")
	if nodeID == "" {
		nodeID = provider.Find("local")
	}
	if nodeID == "" {
		nodeID = provider.Find(GetCurrentUser())
	}

	if nodeID != "" {
		if id, ok := provider.GetIdentity(nodeID); ok {
			return id.Password
		}
	}
	return ""
}

// ParseAddr 解析 user@host:port 格式的字符串
func ParseAddr(input string) (string, string, uint16) {
	input = strings.TrimSpace(input)
	var user, host string
	var port uint16
	if atIndex := strings.LastIndex(input, ":"); atIndex != -1 {
		p := ParsePort(input[atIndex+1:])
		if p != 0 {
			port = p
			input = strings.TrimSpace(input[:atIndex])
		}
	}
	if atIndex := strings.Index(input, "@"); atIndex != -1 {
		user = strings.TrimSpace(input[:atIndex])
		input = strings.TrimSpace(input[atIndex+1:])
	}
	host = strings.TrimSpace(input)
	return user, host, port
}

// ParseHost 解析 host:port 格式的字符串
func ParseHost(input string) (string, uint16) {
	var host string
	var port uint16
	if atIndex := strings.Index(input, ":"); atIndex != -1 {
		port = ParsePort(input[atIndex+1:])
		input = input[:atIndex]
	}
	host = input
	return host, port
}

// ParsePort 解析端口字符串
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
	return filepath.Join(user.HomeDir, ".xops", ConfigFileName), filepath.Join(user.HomeDir, ".xops", ConfigKeyName)
}

func GetPasswordFilePath() string {
	user, err := user.Current()
	if err != nil {
		return ""
	}
	return filepath.Join(user.HomeDir, ".xops", PasswordFileName)
}

// ReadPasswordFromTerminal 从终端安全地读取密码
func ReadPasswordFromTerminal(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}

// IsValidIP 检查给定的字符串是否是有效的IP地址
func IsValidIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil
}

// IsValidCIDR 检查给定的字符串是否是有效的CIDR表示法
func IsValidCIDR(cidrStr string) bool {
	_, _, err := net.ParseCIDR(cidrStr)
	return err == nil
}
