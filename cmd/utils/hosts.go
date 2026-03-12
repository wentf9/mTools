package utils

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type HostInfo struct {
	Host       string
	Port       uint16
	Alias      string
	User       string
	Password   string
	KeyPath    string
	Passphrase string
}

func ReadCSVFile(path string) ([]HostInfo, error) {
	if filepath.IsLocal(path) {
		if wd, err := os.Getwd(); err == nil {
			path = filepath.Join(wd, path)
		}
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CSV文件不存在: %v", err)
		}
		return nil, fmt.Errorf("无法打开CSV文件: %v", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)
	// 允许不一致的列数（可选，视CSV规范而定）
	reader.FieldsPerRecord = -1

	// 读取表头
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("读取CSV表头失败: %v", err)
	}

	// 建立列索引映射
	colMap := make(map[string]int)
	for i, col := range header {
		colMap[strings.ToLower(strings.TrimSpace(col))] = i
	}

	// 定义字段映射关系
	findIdx := func(names ...string) int {
		for _, name := range names {
			if idx, ok := colMap[strings.ToLower(name)]; ok {
				return idx
			}
		}
		return -1
	}

	idxHost := findIdx("host", "主机", "主机地址", "ip", "address")
	idxPort := findIdx("port", "端口")
	idxAlias := findIdx("alias", "别名", "name")
	idxUser := findIdx("user", "用户", "用户名", "username")
	idxPass := findIdx("password", "密码", "登录密码")
	idxKey := findIdx("key", "私钥", "私钥地址", "keypath", "identity_file")
	idxKeyPass := findIdx("keypass", "key_pass", "私钥密码", "passphrase")

	if idxHost == -1 {
		return nil, fmt.Errorf("CSV文件表头必须包含 '主机' 或 'IP' 列")
	}

	var hosts []HostInfo
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("读取CSV记录失败: %v", err)
		}

		getVal := func(idx int) string {
			if idx != -1 && idx < len(record) {
				return strings.TrimSpace(record[idx])
			}
			return ""
		}

		hostStr := getVal(idxHost)
		if hostStr == "" {
			continue
		}

		host, port := ParseHost(hostStr)
		// 如果CSV中有专门的端口列，则覆盖解析出的端口
		if pStr := getVal(idxPort); pStr != "" {
			var p uint16
			fmt.Sscanf(pStr, "%d", &p)
			if p != 0 {
				port = p
			}
		}

		hosts = append(hosts, HostInfo{
			Host:       host,
			Port:       port,
			Alias:      getVal(idxAlias),
			User:       getVal(idxUser),
			Password:   getVal(idxPass),
			KeyPath:    getVal(idxKey),
			Passphrase: getVal(idxKeyPass),
		})
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("CSV文件中没有找到有效的主机信息")
	}

	return hosts, nil
}

func ParseHosts(ip, hostFile, csvFile string) ([]HostInfo, error) {
	var hosts []string
	var HostsInfo []HostInfo
	if csvFile != "" {
		var err error
		HostsInfo, err = ReadCSVFile(csvFile)
		if err != nil {
			return nil, err
		}
	} else {
		if ip != "" {
			parts := strings.Split(ip, ",")
			for _, p := range parts {
				hosts = append(hosts, strings.TrimSpace(p))
			}
		} else if hostFile != "" {
			// 复用 ParseHost 逻辑而不是简单的正则替换，以确保格式一致
			file, err := os.ReadFile(hostFile)
			if err == nil {
				lines := strings.Split(string(file), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" {
						hosts = append(hosts, line)
					}
				}
			}
		}
		for _, host := range hosts {
			u, h, p := ParseAddr(host)
			HostsInfo = append(HostsInfo, HostInfo{
				Host: h,
				Port: p,
				User: u,
			})
		}
	}
	return HostsInfo, nil
}
