package utils

import (
	// "fmt"
	"fmt"
	"net"
	"os/user"
	"strconv"
	"strings"
	"sync"
)

type CommandResult struct {
	Host    string
	Success bool
	Output  string
	Error   error
}

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
