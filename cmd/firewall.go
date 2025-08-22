package cmd

import (
	"fmt"
	"os"
	"strings"

	"example.com/MikuTools/utils"
	"github.com/spf13/cobra"
)

var (
	protocol string
	// fport     uint16
	permanent bool
	zone      string
	service   string
	rich      string
	action    string
)

// firewallCmd represents the firewall command
var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "管理远程主机的防火墙设置",
	Long: `使用此命令管理远程Linux主机的防火墙设置。基于firewall-cmd实现。
支持同时对多台主机进行防火墙规则管理。

示例:
  # 添加端口规则
  mtool firewall --action add-port --port 80 --protocol tcp -i "192.168.1.100,192.168.1.101" -u root
  
  # 添加服务规则
  mtool firewall --action add-service --service http -i "192.168.1.100" -u root
  
  # 删除端口规则
  mtool firewall --action remove-port --port 80 --protocol tcp -i "192.168.1.100" -u root
  
  # 查看防火墙状态
  mtool firewall --action status -i "192.168.1.100" -u root

  # 重载防火墙配置
  mtool firewall --action reload -i "192.168.1.100" -u root

支持的操作(--action):
  status        - 显示防火墙状态
  reload        - 重载防火墙配置
  add-port      - 添加端口规则
  remove-port   - 删除端口规则
  add-service   - 添加服务规则
  remove-service - 删除服务规则
  add-rich      - 添加富规则
  remove-rich   - 删除富规则`,
	Run: func(cmd *cobra.Command, args []string) {
		var hosts []string
		var csvHosts []hostInfo

		// 解析主机列表
		if csvFile != "" {
			var err error
			csvHosts, err = readCSVFile(csvFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "读取CSV文件失败: %v\n", err)
				os.Exit(1)
			}
		} else {
			if ip != "" {
				hosts = strings.Split(ip, ",")
			} else if hostFile != "" {
				hosts = bufferedReadIpFile(hostFile)
			}

			for _, host := range hosts {
				if !utils.IsValidIPv4(host) {
					fmt.Fprintf(os.Stderr, "错误: 非法的ip地址: %s\n", host)
					os.Exit(1)
				}
			}
		}

		// 构建防火墙命令
		var command string
		switch action {
		case "status":
			command = "firewall-cmd --state && echo '当前配置:' && firewall-cmd --list-all"
		case "reload":
			command = "firewall-cmd --reload"
		case "add-port", "remove-port":
			if port == 0 || protocol == "" {
				fmt.Fprintf(os.Stderr, "错误: 端口和协议是必需的\n")
				os.Exit(1)
			}
			op := "--add-port"
			if action == "remove-port" {
				op = "--remove-port"
			}
			command = fmt.Sprintf("firewall-cmd %s %d/%s", op, port, protocol)
		case "add-service", "remove-service":
			if service == "" {
				fmt.Fprintf(os.Stderr, "错误: 服务名是必需的\n")
				os.Exit(1)
			}
			op := "--add-service"
			if action == "remove-service" {
				op = "--remove-service"
			}
			command = fmt.Sprintf("firewall-cmd %s=%s", op, service)
		case "add-rich", "remove-rich":
			if rich == "" {
				fmt.Fprintf(os.Stderr, "错误: 富规则是必需的\n")
				os.Exit(1)
			}
			op := "--add-rich-rule"
			if action == "remove-rich" {
				op = "--remove-rich-rule"
			}
			command = fmt.Sprintf("firewall-cmd %s='%s'", op, rich)
		default:
			fmt.Fprintf(os.Stderr, "错误: 不支持的操作: %s\n", action)
			os.Exit(1)
		}

		// 添加区域参数
		if zone != "" && action != "status" && action != "reload" {
			command += fmt.Sprintf(" --zone=%s", zone)
		}

		// 添加permanent标志
		if permanent && action != "status" && action != "reload" {
			command += " --permanent"
		}

		// 检查防火墙是否安装和运行
		checkCommand := "command -v firewall-cmd >/dev/null 2>&1 || { echo '错误: firewall-cmd 未安装'; exit 1; }; " +
			"systemctl is-active --quiet firewalld || { echo '错误: firewalld 服务未运行'; exit 1; }; "

		// 执行命令
		concurrency := len(hosts)
		if csvFile != "" {
			concurrency = len(csvHosts)
		}
		commandOptions := utils.CommandOptions{
			Sudo:    1,
			Content: checkCommand + command,
			IsCli:   true,
		}
		ExecuteConcurrently(hosts, csvHosts, commandOptions, concurrency)
	},
}

func init() {
	rootCmd.AddCommand(firewallCmd)

	// 继承全局标志
	firewallCmd.PersistentFlags().StringVarP(&ip, "ip", "i", "", "目标主机,多个主机用逗号分隔")
	firewallCmd.PersistentFlags().StringVarP(&user, "user", "u", "", "SSH用户名")
	firewallCmd.PersistentFlags().StringVarP(&password, "passwd", "p", "", "SSH密码")
	firewallCmd.PersistentFlags().StringVarP(&hostFile, "ifile", "I", "", "主机列表文件路径")
	firewallCmd.PersistentFlags().StringVarP(&csvFile, "csv", "", "", "CSV文件路径(包含主机IP,用户名,密码)")

	// 防火墙特定标志
	firewallCmd.Flags().StringVar(&protocol, "protocol", "", "协议(tcp/udp)")
	firewallCmd.Flags().Uint16Var(&port, "port", 0, "端口号")
	firewallCmd.Flags().BoolVar(&permanent, "permanent", false, "是否永久生效")
	firewallCmd.Flags().StringVar(&zone, "zone", "", "防火墙区域")
	firewallCmd.Flags().StringVar(&service, "service", "", "服务名称")
	firewallCmd.Flags().StringVar(&rich, "rich-rule", "", "富规则")
	firewallCmd.Flags().StringVar(&action, "action", "", "操作类型(status/reload/add-port/remove-port/add-service/remove-service/add-rich/remove-rich)")

	firewallCmd.MarkFlagsOneRequired("ip", "ifile", "csv")
	firewallCmd.MarkFlagsMutuallyExclusive("ip", "ifile", "csv")
	firewallCmd.MarkFlagRequired("action")
}
