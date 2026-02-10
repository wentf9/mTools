package cmd

import (
	cmdutils "example.com/MikuTools/cmd/utils"
)

// 这些全局变量是由于重构 exec.go 而移出的，为了保持其他旧代码（如 firewall.go）兼容而保留。
// 建议后续将这些代码也重构为使用 Options 结构体的模式。
var (
	ip       string
	port     uint16
	user     string
	password string
	hostFile string
	csvFile  string
	suPwd    string
)

func parseHosts(ip, hostFile, csvFile string) ([]string, []cmdutils.HostInfo, error) {
	return cmdutils.ParseHosts(ip, hostFile, csvFile)
}
