package cmd

import (
	"fmt"

	"os"
	"os/exec"
	"strings"

	"example.com/MikuTools/utils"
	"github.com/spf13/cobra"
)

var (
	firewallProtocol string // 协议类型(tcp/udp)
	// fport     uint16
	firewallNotPermanent bool
	firewallZone         string
	firewallRemove       bool   // 是否删除规则,如果为false则添加规则
	firewallCheckCommand string = "command -v firewall-cmd >/dev/null 2>&1 || { echo '错误: firewall-cmd 未安装'; exit 1; }; " +
		"systemctl is-active --quiet firewalld || { echo '错误: firewalld 服务未运行'; exit 1; }; "
	firewallReload        bool
	firewallReloadCommand string = "firewall-cmd --reload ;"
	firewallLocalMode     bool   = false // 是否本地模式,如果为true则不使用SSH连接,直接在本地执行命令

)

// firewallCmd represents the firewall command
var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "管理远程主机的防火墙设置",
	Long: `使用此命令管理远程Linux主机的防火墙设置。基于firewall-cmd实现。
支持同时对多台主机进行防火墙规则管理。

示例:
  # 添加端口规则
  mtool firewall port 80 -i "192.168.1.100,192.168.1.101" -u root
  
  # 添加服务规则
  mtool firewall service http -i "192.168.1.100" -u root
  
  # 删除端口规则
  mtool firewall port 80 -r -i "192.168.1.100" -u root
  
  # 查看防火墙状态
  mtool firewall list -i "192.168.1.100" -u root

  # 重载防火墙配置
  mtool firewall reload -i "192.168.1.100" -u root`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		rootCmd.PersistentPreRun(rootCmd, args)
		tcp, _ := cmd.Flags().GetBool("tcp")
		udp, _ := cmd.Flags().GetBool("udp")
		if tcp || udp {
			if tcp {
				firewallProtocol = "tcp"
			} else {
				firewallProtocol = "udp"
			}
		} else {
			firewallProtocol = "tcp" // 默认协议
		}
		if ip == "" && hostFile == "" && csvFile == "" {
			firewallLocalMode = true
			utils.Logger.Warn("未指定目标主机, 切换到本地模式")
		}
		if firewallLocalMode {
			if !utils.IsLinux() {
				fmt.Fprintf(os.Stderr, "错误: 仅支持在Linux系统上管理本机防火墙\n")
				os.Exit(1)
			}
		}
	},
}

func startFirewallCmd(command string) {
	utils.Logger.Debug(fmt.Sprintf("待执行命令: %s", command))
	if firewallLocalMode {
		// 使用 "sh -c" 来执行复杂的shell命令字符串。
		// 直接使用 exec.Command(command) 会将整个字符串作为单个命令名, 导致执行失败。
		cmd := exec.Command("bash", "-c", command)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "执行命令失败: %v\n", err)
			fmt.Fprintf(os.Stderr, "命令输出: %s\n", string(output))
			os.Exit(1)
		}
		fmt.Printf("%s\n", string(output))
		return
	}
	hosts, csvHosts, err := parseHosts(ip, hostFile, csvFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "解析主机列表失败: %v\n", err)
		os.Exit(1)
	}
	// 执行命令
	concurrency := len(hosts)
	if csvFile != "" {
		concurrency = len(csvHosts)
	}
	sshCommand := utils.NewSSHCommand(command, 1, true)
	ExecuteConcurrently(hosts, csvHosts, sshCommand, concurrency)
}

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "列出防火墙规则",
	Long:  `列出主机的防火墙规则。基于firewall-cmd实现。支持同时对多台主机进行防火墙规则查看。`,
	Run: func(cmd *cobra.Command, args []string) {
		command := firewallCheckCommand + "firewall-cmd --state && echo '当前配置:' && firewall-cmd"
		if firewallZone != "" {
			command = fmt.Sprintf("%s --zone=%s", command, firewallZone)
		}
		command += " --list-all"
		startFirewallCmd(command)
	},
}

// portCmd represents the port command
var portCmd = &cobra.Command{
	Use:   "port <port1,port2,...> [-r|--remove] [--tcp|--udp] [--reload] [--not-permanent]",
	Short: "添加/删除端口规则",
	Long: `添加/删除主机的防火墙端口规则。基于firewall-cmd实现。支持同时对多台主机进行防火墙规则管理。
	用法：
	  mtool firewall port 端口号1,端口号2,... [-r|--remove] [--tcp|--udp] [--reload]
	  mtool firewall port 端口号1 端口号2 ... [-r|--remove] [--tcp|--udp] [--reload]
	  端口号支持单个端口(80)或端口范围(1000-2000)`,
	Args: func(cmd *cobra.Command, args []string) error {
		utils.Logger.Debug(fmt.Sprintf("传入参数: %v", args))
		if len(args) < 1 {
			return fmt.Errorf("错误: 必须指定端口号")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		var ports []string
		var portStrs []string
		if len(args) == 1 {
			portStrs = strings.Split(args[0], ",")
		} else {
			portStrs = args
		}
		for _, portStr := range portStrs {
			if strings.Contains(portStr, "-") {
				// 处理端口范围
				head, tail, _ := strings.Cut(portStr, "-")
				for _, port := range []string{head, tail} {
					p := utils.ParsePort(port)
					if p == 0 {
						fmt.Fprintf(os.Stderr, "错误: 无效的端口号: %s\n", port)
						os.Exit(1)
					}
				}
				ports = append(ports, portStr)
				continue
			}
			p := utils.ParsePort(portStr)
			if p == 0 {
				fmt.Fprintf(os.Stderr, "错误: 无效的端口号: %s\n", portStr)
				os.Exit(1)
			}
			ports = append(ports, portStr)
		}

		if len(ports) == 0 {
			fmt.Fprint(os.Stderr, "错误: 未从参数中解析到有效的端口号\n")
			os.Exit(1)
		}
		var action string
		if firewallRemove {
			action = "--remove-port"
		} else {
			action = "--add-port"
		}
		command := firewallCheckCommand
		for _, port := range ports {
			command += "firewall-cmd"
			if !firewallNotPermanent {
				command += " --permanent"
			}
			if firewallZone != "" {
				command = fmt.Sprintf("%s --zone=%s", command, firewallZone)
			}
			command = fmt.Sprintf("%s %s=%s/%s;", command, action, port, firewallProtocol)
		}
		if firewallReload {
			command += firewallReloadCommand
		}
		startFirewallCmd(command)
	},
}

// serviceCmd represents the service command
var serviceCmd = &cobra.Command{
	Use:   "service <service1,service2,...> [-r|--remove] [--reload] [--not-permanent]",
	Short: "添加/删除服务规则",
	Long: `添加/删除主机的防火墙服务规则。基于firewall-cmd实现。支持同时对多台主机进行防火墙规则管理。
	用法：
	  mtool firewall port service1,service2,... [-r|--remove] [--tcp|--udp] [--reload]
	  mtool firewall port service1 service2 ... [-r|--remove] [--tcp|--udp] [--reload]
	  端口号支持单个端口(80)或端口范围(1000-2000)`,
	Args: func(cmd *cobra.Command, args []string) error {
		if cmd.Args == nil || len(args) < 1 {
			return fmt.Errorf("错误: 必须指定服务名")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {

		var services []string
		var serviceStrs []string
		if len(args) == 1 {
			serviceStrs = strings.Split(args[0], ",")
		} else {
			serviceStrs = args
		}

		for _, serviceStr := range serviceStrs {
			if serviceStr == "" {
				continue
			}
			services = append(services, serviceStr)
		}
		if len(services) == 0 {
			fmt.Fprint(os.Stderr, "错误: 未从参数中解析到有效的服务名\n")
			os.Exit(1)
		}
		var action string
		if firewallRemove {
			action = "--remove-service"
		} else {
			action = "--add-service"
		}
		command := firewallCheckCommand
		for _, service := range services {
			command += "firewall-cmd"
			if !firewallNotPermanent {
				command += " --permanent"
			}
			if firewallZone != "" {
				command = fmt.Sprintf("%s --zone=%s", command, firewallZone)
			}
			command = fmt.Sprintf("%s %s=%s;", command, action, service)
		}
		if firewallReload {
			command += firewallReloadCommand
		}
		startFirewallCmd(command)
	},
}

// ruleCmd represents the rule command
var ruleCmd = &cobra.Command{
	Use:   "rule [端口号1,端口号2,...] <源IP1,源IP2,...> [-r|--remove] [--tcp|--udp] [--reload] [--not-permanent] [--accept|--reject|--drop]",
	Short: "添加/删除富规则",
	Long: `添加/删除主机的防火墙富规则。基于firewall-cmd实现。支持同时对多台主机进行防火墙规则管理。
用法：
  mtool firewall rule [端口号1,端口号2,...] 源IP1,源IP2,... [-r|--remove] [--tcp|--udp] [--reload] [--accept|--reject|--drop]
  目的端口支持单个端口号和端口范围(如:80-443),源ip支持ipv4格式的单个ip或cidr格式(如:10.0.0.0/24)的网段
  只有一个参数的情况下必须是ip,管理源ip的全部请求,两个参数时端口在前,ip在后,管理源ip对目的端口的请求`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("错误:至少要有一个参数")
		}
		if len(args) > 2 {
			return fmt.Errorf("错误:参数过多(最多两个)")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		var portStrs []string = []string{}

		var sourceIPs []string
		if len(args) == 1 {
			sourceIPs = strings.Split(args[0], ",")
		} else {
			portStrs = strings.Split(args[0], ",")
			sourceIPs = strings.Split(args[1], ",")
		}
		var ports []string = []string{}
		for _, portStr := range portStrs {
			if strings.Contains(portStr, "-") {
				// 处理端口范围
				head, tail, _ := strings.Cut(portStr, "-")
				for _, port := range []string{head, tail} {
					p := utils.ParsePort(port)
					if p == 0 {
						fmt.Fprintf(os.Stderr, "错误: 无效的端口号: %s\n", port)
						os.Exit(1)
					}
				}
				ports = append(ports, portStr)
				continue
			}
			p := utils.ParsePort(portStr)
			if p == 0 {
				fmt.Fprintf(os.Stderr, "错误: 无效的端口号: %s\n", portStr)
				os.Exit(1)
			}
			ports = append(ports, portStr)
		}
		for _, sourceIP := range sourceIPs {
			if utils.IsValidIPv4(sourceIP) || utils.IsValidCIDR(sourceIP) {
				continue
			} else {
				fmt.Fprintf(os.Stderr, "错误: 非法的源IP: %s\n", sourceIP)
				os.Exit(1)
			}
		}
		var reject, drop bool
		reject, _ = cmd.Flags().GetBool("reject")
		drop, _ = cmd.Flags().GetBool("drop")
		var firewallAction string
		if reject {
			firewallAction = "reject"
		} else if drop {
			firewallAction = "drop"
		} else {
			firewallAction = "accept" // 默认接受
		}
		var action string
		if firewallRemove {
			action = "--remove-rich-rule"
		} else {
			action = "--add-rich-rule"
		}
		rule := "firewall-cmd"
		if !firewallNotPermanent {
			rule += " --permanent"
		}
		if firewallZone != "" {
			rule = fmt.Sprintf("%s --zone=%s", rule, firewallZone)
		}
		portRule := fmt.Sprintf("port protocol=\"%s\"", firewallProtocol)
		sourceRule := "rule family=\"ipv4\""
		command := firewallCheckCommand
		// 构建富规则
		if len(ports) < 1 {
			for _, sourceIP := range sourceIPs {
				command += fmt.Sprintf("%s %s='%s source address=\"%s\" %s';",
					rule, action, sourceRule, sourceIP, firewallAction)
			}
		} else {
			for _, port := range ports {
				for _, sourceIP := range sourceIPs {
					command += fmt.Sprintf("%s %s='%s source address=\"%s\" %s port=\"%s\" %s';",
						rule, action, sourceRule, sourceIP, portRule, port, firewallAction)
				}
			}
		}
		if firewallReload {
			command += firewallReloadCommand
		}
		startFirewallCmd(command)
	},
}

// reloadCmd represents the reload command
var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "重新加载防火墙配置",
	Long:  `重新加载主机的防火墙配置。基于firewall-cmd实现。支持同时对多台主机进行防火墙配置重载。`,
	Run: func(cmd *cobra.Command, args []string) {
		command := firewallCheckCommand + firewallReloadCommand
		startFirewallCmd(command)
	},
}

func init() {
	rootCmd.AddCommand(firewallCmd)
	firewallCmd.AddCommand(listCmd)
	firewallCmd.AddCommand(portCmd)
	firewallCmd.AddCommand(ruleCmd)
	firewallCmd.AddCommand(serviceCmd)
	firewallCmd.AddCommand(reloadCmd)

	// 继承全局标志
	firewallCmd.PersistentFlags().StringVarP(&ip, "ip", "i", "", "目标主机,多个主机用逗号分隔")
	firewallCmd.PersistentFlags().StringVarP(&user, "user", "u", "", "SSH用户名")
	firewallCmd.PersistentFlags().StringVarP(&password, "passwd", "p", "", "SSH密码")
	firewallCmd.PersistentFlags().StringVarP(&hostFile, "ifile", "I", "", "主机列表文件路径")
	firewallCmd.PersistentFlags().StringVarP(&csvFile, "csv", "", "", "CSV文件路径(包含主机IP,用户名,密码)")

	// 防火墙特定标志
	firewallCmd.PersistentFlags().Bool("tcp", false, "协议tcp,默认tcp")
	firewallCmd.PersistentFlags().Bool("udp", false, "协议udp")
	firewallCmd.PersistentFlags().BoolVar(&firewallReload, "reload", false, "是否重载防火墙配置,默认false,启用此项时将在执行操作后立即重载防火墙配置")
	firewallCmd.PersistentFlags().BoolVar(&firewallNotPermanent, "not-permanent", false, "是否临时规则,默认false,如果为true则添加永久规则,永久规则需要重载防火墙配置后才生效")
	firewallCmd.PersistentFlags().BoolVarP(&firewallRemove, "remove", "r", false, "是否删除规则,默认false,如果为false则添加规则")
	firewallCmd.PersistentFlags().StringVarP(&firewallZone, "zone", "z", "", "防火墙区域")

	firewallCmd.MarkFlagsMutuallyExclusive("ip", "ifile", "csv")
	firewallCmd.MarkFlagsMutuallyExclusive("tcp", "udp")

	ruleCmd.Flags().BoolP("accept", "A", false, "是否接受匹配的流量,默认接受")
	ruleCmd.Flags().BoolP("reject", "R", false, "是否拒绝匹配的流量,默认接受")
	ruleCmd.Flags().BoolP("drop", "D", false, "是否丢弃匹配的流量,默认接受")
	ruleCmd.MarkFlagsMutuallyExclusive("accept", "reject", "drop")
}
