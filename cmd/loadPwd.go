package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"example.com/MikuTools/utils"
	"github.com/spf13/cobra"
)

// loadPwdCmd represents the loadPwd command
var loadPwdCmd = &cobra.Command{
	Use:   "loadPwd",
	Short: "加载密码并保存",
	Long: `从csv文件中加载密码并保存到密码文件中
会建立ssh连接验证密码准确性`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			os.Exit(0)
		}
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "参数数量错误\n")
			cmd.Help()
			os.Exit(1)
		}
		csvFile := args[0]
		hosts, err := readCSVFile(csvFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "读取CSV文件失败: %v\n", err)
			os.Exit(1)
		}
		if len(hosts) == 0 {
			fmt.Fprintf(os.Stderr, "CSV文件中没有找到有效的主机信息\n")
			os.Exit(1)
		}
		ExecuteConcurrently(nil, hosts, utils.CommandOptions{
			Sudo:    0,
			Content: "whoami",
			IsCli:   true,
		}, len(hosts))
	},
}

func readCSVFile(path string) ([]hostInfo, error) {
	if filepath.IsLocal(path) {
		if wd, err := os.Getwd(); err == nil {
			path = filepath.Join(wd, path)
		} else {
			utils.Logger.Warn(fmt.Sprintf("获取当前工作目录失败: %v", err))
		}
	}

	var hosts []hostInfo
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
			return nil, fmt.Errorf("CSV格式错误,每行需要包含: IP,用户名,密码")
		}

		// 移除字段中的引号和空白
		ip := strings.Trim(strings.TrimSpace(fields[0]), "\"'")
		user := strings.Trim(strings.TrimSpace(fields[1]), "\"'")
		password := strings.Trim(strings.TrimSpace(fields[2]), "\"'")

		if !utils.IsValidIPv4(ip) {
			return nil, fmt.Errorf("无效的IP地址: %s", ip)
		}

		hosts = append(hosts, hostInfo{
			ip:       ip,
			user:     user,
			password: password,
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

func init() {
	rootCmd.AddCommand(loadPwdCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// firewallCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// firewallCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
