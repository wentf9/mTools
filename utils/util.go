package utils

import (
	// "fmt"
	"encoding/json"
	"fmt"
	"net"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

// GetLocalIp 获取本机ip地址
func GetLocalIp() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		Logger.Error(fmt.Sprintf("获取本机IP地址失败: %v", err))
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				return ipNet.IP.String()
			}
		}
	}
	return "127.0.0.1"
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

// IsValidCIDR 检查给定的字符串是否是有效的CIDR表示法
// 返回true表示是有效的CIDR，false表示无效
func IsValidCIDR(cidrStr string) bool {
	_, _, err := net.ParseCIDR(cidrStr)
	return err == nil
}

func GetCurrentUser() string {
	currentUser, err := user.Current()
	if err != nil {
		Logger.Error(fmt.Sprintf("获取当前系统用户失败: %v", err))
		return ""
	}
	return currentUser.Username
}

// RWMap 一个读写锁保护的线程安全的map
type RWMap[KEY comparable, VALUE any] struct {
	sync.RWMutex // 读写锁保护下面的map字段

	m map[KEY]VALUE
}

// NewRWMap 新建一个RWMap
func NewRWMap[KEY comparable, VALUE any](n int) *RWMap[KEY, VALUE] {
	return &RWMap[KEY, VALUE]{
		m: make(map[KEY]VALUE, n),
	}
}

func NewRWMapFromMap[KEY comparable, VALUE any](m map[KEY]VALUE) *RWMap[KEY, VALUE] {
	return &RWMap[KEY, VALUE]{
		m: m,
	}
}

// Get 从map中读取一个值
func (m *RWMap[KEY, VALUE]) Get(k KEY) (VALUE, bool) {
	if m == nil || m.m == nil {
		var zero VALUE
		return zero, false
	}

	m.RLock()
	defer m.RUnlock()

	v, existed := m.m[k] // 在锁的保护下从map中读取
	return v, existed
}

// Set 设置一个键值对
func (m *RWMap[KEY, VALUE]) Set(k KEY, v VALUE) {
	if m == nil {
		return
	}
	if m.m == nil {
		m.m = make(map[KEY]VALUE)
	}
	m.Lock() // 锁保护
	defer m.Unlock()
	m.m[k] = v
}

// Delete 删除一个键
func (m *RWMap[KEY, VALUE]) Delete(k KEY) {
	if m == nil || m.m == nil {
		return
	}

	m.Lock() // 锁保护
	defer m.Unlock()

	delete(m.m, k)
}

// Len map的长度
func (m *RWMap[KEY, VALUE]) Len() int {
	if m == nil || m.m == nil {
		return 0
	}

	m.RLock() // 锁保护
	defer m.RUnlock()

	return len(m.m)
}

func (m *RWMap[KEY, VALUE]) GetMap() map[KEY]VALUE {
	if m == nil {
		return nil
	}

	m.RLock() // 锁保护
	defer m.RUnlock()

	if m.m == nil {
		return nil
	}

	return m.m
}

// Each 遍历map
func (m *RWMap[KEY, VALUE]) Each(f func(k KEY, v VALUE) bool) {
	if m == nil || m.m == nil || f == nil {
		return
	}

	m.RLock() //遍历期间一直持有读锁
	defer m.RUnlock()

	for k, v := range m.m {
		if !f(k, v) {
			return
		}
	}
}

// IsWindows 检查当前操作系统是否是Windows
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// IsLinux 检查当前操作系统是否是Linux
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// IsMacOS 检查当前操作系统是否是macOS
func IsMacOS() bool {
	return runtime.GOOS == "darwin"
}

func StringToUnicode(s string) string {
	var result strings.Builder
	for _, r := range s {
		if r <= 0xFFFF {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			// 处理超过U+FFFF的字符（如emoji）
			result.WriteString(fmt.Sprintf("\\U%08x", r))
		}
	}
	return result.String()
}

func UnicodeToString(s string) (string, error) {
	// 使用json.Unmarshal来处理Unicode转义序列
	str := "\"" + s + "\""
	var result string
	err := json.Unmarshal([]byte(str), &result)
	if err != nil {
		return "", fmt.Errorf("无效的Unicode序列: %v", err)
	}
	return result, nil
}

// 将字符串转换为UTF-8编码（&#x...;格式）
func StringToUTF8(s string) string {
	var result strings.Builder
	for _, r := range s {
		result.WriteString(fmt.Sprintf("&#x%X;", r))
	}
	return result.String()
}

// 将UTF-8编码（&#x...;格式）转换回字符串
func Utf8ToString(s string) (string, error) {
	var result strings.Builder
	parts := strings.Split(s, "&#x")

	for i, part := range parts {
		if i == 0 {
			// 第一个部分可能不是编码
			if part != "" && !strings.HasPrefix(s, "&#x") {
				result.WriteString(part)
			}
			continue
		}

		// 查找分号位置
		semicolonPos := strings.Index(part, ";")
		if semicolonPos == -1 {
			return "", fmt.Errorf("无效的UTF-8编码格式: 缺少分号")
		}

		// 提取十六进制数字部分
		hexStr := part[:semicolonPos]
		// 将十六进制字符串转换为整数
		codePoint, err := strconv.ParseInt(hexStr, 16, 32)
		if err != nil {
			return "", fmt.Errorf("无效的十六进制数字: %s", hexStr)
		}

		// 将代码点转换为字符
		result.WriteRune(rune(codePoint))

		// 添加剩余部分（如果有）
		if len(part) > semicolonPos+1 {
			result.WriteString(part[semicolonPos+1:])
		}
	}

	// 如果没有找到任何编码，直接返回原字符串
	if result.Len() == 0 {
		return s, nil
	}

	return result.String(), nil
}
