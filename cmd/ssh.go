package cmd

import (
	"fmt"
	"os"

	"example.com/MikuTools/utils"
	"github.com/spf13/cobra"
)

var sshCmd = &cobra.Command{
	Use:   "ssh [user@]ip[:port]",
	Short: "SSH连接到指定主机",
	Long: `建立SSH连接并提供交互式终端
	用法：
	mtool ssh user@ip[:port]
	mtool ssh user ip [port]
	mtool -i ip -u user
	用户和ip为必选参数,端口默认为22,一般不需要修改
	通过flags提供ip和用户信息时会忽略参数提供的信息
	如果未通过-p选项显式提供密码,将会从终端输入或通过保存的密码文件读取密码
	成功登录过的用户和ip组合的密码将会保存到密码文件中
	密码采用对称加密算法加密保存,密码文件位置为~/.mtool_passwords.json`,
	Run: func(cmd *cobra.Command, args []string) {
		// 检查必需的参数
		if ip == "" {
			if len(args) == 2 {
				// 如果提供了参数，尝试从中解析IP和用户名
				ip = args[1]
				user = args[0]
			} else if len(args) == 1 {
				// 如果只提供了一个参数，按照user@ip:port格式解析
				u, i, p := utils.ParseAddr(args[0])
				if i == "" {
					fmt.Fprintf(os.Stderr, "错误: 必须提供主机IP\n")
					os.Exit(1)
				}
				if u != "" {
					user = u
				}
				if p != 0 {
					port = p
				}
				ip = i
			} else if len(args) == 3 {
				// 如果提供了三个参数，假设是 user ip port
				user = args[0]
				ip = args[1]
				if port = utils.ParsePort(args[2]); port == 0 {
					fmt.Fprintf(os.Stderr, "错误: 端口<%s>格式错误\n", args[2])
					os.Exit(1)
				}
			} else if len(args) > 3 {
				fmt.Fprintf(os.Stderr, "错误: 参数过多\n")
				os.Exit(1)
			} else if len(args) == 0 {
				fmt.Fprintf(os.Stderr, "错误: 必须提供主机IP\n")
				os.Exit(1)
			}
		}
		if !utils.IsValidIPv4(ip) {
			fmt.Fprintf(os.Stderr, "错误: 无效的IP地址: %s\n", ip)
			os.Exit(1)
		}
		if user == "" {
			if u := utils.GetCurrentUser(); u != "" {
				utils.Logger.Debug(fmt.Sprintf("当前系统用户: %s", u))
				user = u
			} else {
				fmt.Fprintf(os.Stderr, "错误: 未指定用户,且当前系统用户无法获取\n")
				os.Exit(1)
			}
		}

		// 加载保存的密码
		passwords, err := utils.LoadPasswords()
		if err != nil {
			utils.Logger.Warn(fmt.Sprintf("无法加载已保存的密码: %v\n", err))
			utils.Logger.Warn("将创建一个新的密码存储")
			passwords = utils.NewPasswordStore()
		}

		// 如果没有提供密码，尝试使用保存的密码
		hostPassword := password
		if hostPassword == "" {
			if storedPass, ok := passwords.GetPass(user, ip); ok {
				hostPassword = storedPass
			} else {
				// 如果没有保存的密码，从终端读取
				if newPass, err := utils.ReadPasswordFromTerminal(fmt.Sprintf("请输入 %s@%s 的密码: ", user, ip)); err == nil {
					hostPassword = newPass
				} else {
					fmt.Fprintf(os.Stderr, "读取密码失败: %v\n", err)
					os.Exit(1)
				}
			}
		}

		// 创建SSH客户端
		c := utils.SSHCli{
			Ip:   ip,
			Port: port,
			User: user,
			Pwd:  hostPassword,
		}

		// 建立连接
		session, err := c.Connect()
		if err != nil {
			fmt.Fprintf(os.Stderr, "连接失败: %v\n", err)
			os.Exit(1)
		}
		defer c.Client.Close()

		// 如果连接成功且密码是新的，保存密码
		if passwords.SaveOrUpdate(user, ip, hostPassword) {
			if err := passwords.Save2File(); err != nil {
				utils.Logger.Error(fmt.Sprintf("保存密码到文件失败: %v\n", err))
			} else {
				utils.Logger.Info(fmt.Sprintf("密码已保存到文件: %s@%s", user, ip))
			}
		}

		// 启动交互式会话
		if err := c.InteractiveSession(session); err != nil {
			fmt.Fprintf(os.Stderr, "会话异常: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	rootCmd.AddCommand(sshCmd)

	sshCmd.PersistentFlags().StringVarP(&ip, "ip", "i", "", "目标主机IP地址")
	sshCmd.PersistentFlags().Uint16Var(&port, "port", 22, "SSH端口")
	sshCmd.PersistentFlags().StringVarP(&user, "user", "u", "", "SSH用户名")
	sshCmd.PersistentFlags().StringVarP(&password, "passwd", "p", "", "SSH密码")
	// sshCmd.Flags().BoolVarP(&sudo, "sudo", "S", false, "是否启动sudo环境(Todo)")
	// sshCmd.MarkFlagRequired("ip")
}
