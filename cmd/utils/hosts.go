package utils

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type HostInfo struct {
	Host     string
	Port     uint16
	User     string
	Password string
}

func ReadCSVFile(path string) ([]HostInfo, error) {
	if filepath.IsLocal(path) {
		if wd, err := os.Getwd(); err == nil {
			path = filepath.Join(wd, path)
		}
	}

	var hosts []HostInfo
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("CSV文件不存在: %v", err)
		}
		return nil, fmt.Errorf("无法打开CSV文件: %v", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	firstLine := true

	for {
		line, err := reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("读取CSV文件失败: %v", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			if err == io.EOF {
				break
			}
			continue
		}

		// 跳过CSV头行
		if firstLine {
			firstLine = false
			if strings.Contains(strings.ToLower(line), "ip") {
				continue
			}
		}

		// 分割CSV行
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			return nil, fmt.Errorf("CSV格式错误,每行需要包含: host[:port],用户名,密码")
		}

		// 移除字段中的引号和空白
		hostStr := strings.Trim(strings.TrimSpace(fields[0]), "\"'")
		user := strings.Trim(strings.TrimSpace(fields[1]), "\"'")
		password := strings.Trim(strings.TrimSpace(fields[2]), "\"'")
		host, port := ParseHost(hostStr)
		// if _, err := net.ResolveIPAddr("ip", host); err != nil {
		// 	return nil, fmt.Errorf("无法从 %s 解析出有效的ip地址: %v", host, err)
		// }
		hosts = append(hosts, HostInfo{
			Host:     host,
			Port:     port,
			User:     user,
			Password: password,
		})

		if err == io.EOF {
			break
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("CSV文件中没有找到有效的主机信息")
	}

	return hosts, nil
}

func BufferedReadIpFile(path string) []string {
	var hosts []string
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	reg := regexp.MustCompile(`\s`)
	for {
		line, err := reader.ReadString('\n')
		if err == nil {
			line = reg.ReplaceAllString(line, "")
			if line == "" {
				continue
			}
			hosts = append(hosts, line)
		} else if err == io.EOF {
			line = reg.ReplaceAllString(line, "")
			if line != "" {
				hosts = append(hosts, line)
			}
			break
		} else {
			break
		}
	}
	return hosts
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
			hosts = strings.Split(ip, ",")
		} else if hostFile != "" {
			hosts = BufferedReadIpFile(hostFile)
		}
		for _, host := range hosts {
			u, h, p := ParseAddr(host)
			// if _, err := net.ResolveIPAddr("ip", h); err != nil {
			// 	return nil, fmt.Errorf("无法从 %s 解析出有效的ip地址: %v", host, err)
			// }
			HostsInfo = append(HostsInfo, HostInfo{
				Host: h,
				Port: p,
				User: u,
			})
		}
	}
	return HostsInfo, nil
}
