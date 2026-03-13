package utils

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// HostInfo 存储从CSV或参数中解析出的主机信息
type HostInfo struct {
	Host       string
	Port       uint16
	Alias      string
	User       string
	Password   string
	KeyPath    string
	Passphrase string
}

// ReadCSVFile 从指定路径读取CSV文件并解析为主机列表
func ReadCSVFile(path string) ([]HostInfo, error) {
	if filepath.IsLocal(path) {
		if wd, err := os.Getwd(); err == nil {
			path = filepath.Join(wd, path)
		}
	}

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CSV文件不存在: %w", err)
		}
		return nil, fmt.Errorf("无法打开CSV文件: %w", err)
	}
	defer func() { _ = file.Close() }()

	reader := csv.NewReader(file)
	// 允许不一致的列数（可选，视CSV规范而定）
	reader.FieldsPerRecord = -1

	// 读取表头
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("读取CSV表头失败: %w", err)
	}

	mapping := buildCSVMapping(header)

	if mapping.host == -1 {
		return nil, fmt.Errorf("CSV文件表头必须包含 '主机' 或 'IP' 列")
	}

	var hosts []HostInfo
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("读取CSV记录失败: %w", err)
		}

		hostInfo := parseHostRecord(record, mapping)
		if hostInfo != nil {
			hosts = append(hosts, *hostInfo)
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("CSV文件中没有找到有效的主机信息")
	}

	return hosts, nil
}

// ParseHosts 综合处理单主机、主机文件和CSV文件中的主机信息
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

type csvHostMapping struct {
	host, port, alias, user, pass, key, keyPass int
}

func buildCSVMapping(header []string) csvHostMapping {
	colMap := make(map[string]int)
	for i, col := range header {
		colMap[strings.ToLower(strings.TrimSpace(col))] = i
	}

	findIdx := func(names ...string) int {
		for _, name := range names {
			if idx, ok := colMap[strings.ToLower(name)]; ok {
				return idx
			}
		}
		return -1
	}

	return csvHostMapping{
		host:    findIdx("host", "主机", "主机地址", "ip", "address"),
		port:    findIdx("port", "端口"),
		alias:   findIdx("alias", "别名", "name"),
		user:    findIdx("user", "用户", "用户名", "username"),
		pass:    findIdx("password", "密码", "登录密码"),
		key:     findIdx("key", "私钥", "私钥地址", "keypath", "identity_file"),
		keyPass: findIdx("keypass", "key_pass", "私钥密码", "passphrase"),
	}
}

func parseHostRecord(record []string, mapping csvHostMapping) *HostInfo {
	getVal := func(idx int) string {
		if idx != -1 && idx < len(record) {
			return strings.TrimSpace(record[idx])
		}
		return ""
	}

	hostStr := getVal(mapping.host)
	if hostStr == "" {
		return nil
	}

	host, port := ParseHost(hostStr)
	if pStr := getVal(mapping.port); pStr != "" {
		var p uint16
		if _, err := fmt.Sscanf(pStr, "%d", &p); err == nil && p != 0 {
			port = p
		}
	}

	return &HostInfo{
		Host:       host,
		Port:       port,
		Alias:      getVal(mapping.alias),
		User:       getVal(mapping.user),
		Password:   getVal(mapping.pass),
		KeyPath:    getVal(mapping.key),
		Passphrase: getVal(mapping.keyPass),
	}
}
