package utils

import (
	// "fmt"
	"fmt"
	"net"
	"os/user"
	"strconv"
	"strings"
)

// ParseUserIP 解析 user@ip:port 格式的字符串
func ParseAddr(input string) (string, string, uint16) {
	var user, ip string = "", ""
	var port uint16 = 0
	if atIndex := strings.Index(input, ":"); atIndex != -1 {
		port = ParsePort(input[atIndex+1:])
		input = input[:atIndex]
	}
	if atIndex := strings.Index(input, "@"); atIndex != -1 {
		user = input[:atIndex]
		input = input[atIndex+1:]
	}
	ip = input

	return user, ip, port
}

// ParsePort 解析端口字符串
// 如果输入为空字符串，则返回0
func ParsePort(input string) uint16 {
	if input == "" {
		return 0
	}
	port64, err := strconv.ParseUint(input, 10, 16)
	if err != nil {
		Logger.Error(fmt.Sprintf("解析端口失败: %v", err))
		return 0
	}
	return uint16(port64)
}

// IsValidIPv4 检查给定的字符串是否是有效的IPv4地址
// 返回true表示是有效的IPv4地址，false表示无效
func IsValidIPv4(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	return ip != nil && ip.To4() != nil
}

func GetCurrentUser() string {
	currentUser, err := user.Current()
	if err != nil {
		Logger.Error(fmt.Sprintf("获取当前系统用户失败: %v", err))
		return ""
	}
	return currentUser.Username
}
