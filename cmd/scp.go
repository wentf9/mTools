package cmd

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"example.com/MikuTools/utils"
	"github.com/spf13/cobra"
)

/*
1.scp user@host1:/file1 user@host2:/file2
在两个远程主机之间传输文件，采用本机中转，可直接流式传输，不经过本地磁盘读写
2.scp file1 file2 -h host1,host2,host3... -u user1,user2,user3... -p 22,22,22... -P pass1,pass2,pass3...
将file1传输到多个远程主机，file1是否可以是远程主机地址，多个远程地址参数如何设计，多个主机的端口，用户，主机名，认证信息等各种配置应如何设计参数
应该是单个主机的源地址到多个主机的目的地址，反过来是否有意义
3.如果有未保存的主机，需要提供认证信息
在2的场景里如果多个远程地址都没有认证信息是否要每个主机都在控制台提示输入密码，交互是否合理，存在无认证信息的主机的情况下是否可以直接提示，不执行传输
4.是否可以与多主机命令执行的功能复用逻辑
*/
type ScpOptions struct {
	SshOptions
	maxTask   int
	maxThread int
	source    string
	dest      string
}

func NewScpOptions() *SftpOptions {
	return &SftpOptions{
		SshOptions: *NewSshOptions(),
	}
}

func NewCmdScp() *cobra.Command {
	o := NewScpOptions()
	cmd := &cobra.Command{
		Use:   "scp [[user@]host:]source_file [[user@]host:]dest_file",
		Short: "在主机之间传输文件",
		Long: `在主机之间传输文件
用法示例:
mtool scp [[user@]host:]source_file [[user@]host:]dest_file [--task maxTask] [--thread maxThread]
用户和主机为必选参数,端口默认为22,一般不需要修改
通过flags提供主机和用户信息时会忽略参数提供的信息
如果未通过-p选项显式提供密码,将会从终端输入或通过保存的密码文件读取密码
成功登录过的用户和主机组合的密码将会保存到密码文件中
密码采用对称加密算法加密保存,密码文件位置为~/.mtool_passwords.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Complete(cmd, args)
			if err := o.Validate(); err != nil {
				return fmt.Errorf("参数错误: %v", err)
			}
			return o.Run()
		},
	}
	cmd.Flags().IntVar(&o.maxTask, "task", 0, "同时下载文件数")
	cmd.Flags().IntVar(&o.maxThread, "thread", 0, "单个文件同时下载线程")
	cmd.Flags().StringVarP(&o.Password, "password", "P", "", "SSH密码")
	cmd.Flags().StringVarP(&o.KeyFile, "key", "i", "", "SSH私钥文件路径")
	cmd.Flags().StringVarP(&o.KeyPass, "key_pass", "W", "", "SSH私钥密码")
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "j", "", "跳板机地址[user@]host[:port]")
	cmd.Flags().StringVarP(&o.Alias, "alias", "a", "", "连接别名")
	cmd.MarkFlagsMutuallyExclusive("password", "key")
	return cmd
}

var (
	sourcePath  string
	destPath    string
	isRecursive bool
)

// scpCmd represents the scp command
var scpCmd = &cobra.Command{
	Use:   "scp localpath user@host:remotepath",
	Short: "在本地和远程主机之间传输文件",
	Long: `在本地和远程主机之间传输文件，支持多台主机并行传输。
	用法类似于Linux scp命令:
	从本地复制到远程：
	mtool scp [-r] 本地路径 用户@主机:远程路径
	mtool scp [-r] --src 本地路径 -u 用户 -i "主机1,主机2" --dest 远程路径

	从远程复制到本地：
	mtool scp [-r] 用户@主机:远程路径 本地路径
	mtool scp [-r] -u 用户 -i "主机1,主机2" --src 远程路径 --dest 本地路径
	远程路径不要使用~符号,相对路径默认就是家目录
	-r: 递归复制目录
	--progress: 显示传输进度`,
	Run: func(cmd *cobra.Command, args []string) {
		var hosts []string
		var csvHosts []hostInfo
		var localPath, remotePath string
		var isUpload bool

		// 解析参数
		if len(args) == 2 {
			// 传统SCP格式：source dest
			if strings.Contains(args[0], ":") {
				// 从远程下载
				isUpload = false
				parts := strings.Split(args[0], ":")
				if len(parts) != 2 {
					fmt.Fprintf(os.Stderr, "无效的源路径格式\n")
					os.Exit(1)
				}
				hostParts := strings.Split(parts[0], "@")
				if len(hostParts) != 2 {
					fmt.Fprintf(os.Stderr, "无效的主机格式\n")
					os.Exit(1)
				}
				user = hostParts[0]
				hosts = []string{hostParts[1]}
				remotePath = parts[1]
				localPath = args[1]
			} else if strings.Contains(args[1], ":") {
				// 上传到远程
				isUpload = true
				parts := strings.Split(args[1], ":")
				if len(parts) != 2 {
					fmt.Fprintf(os.Stderr, "无效的目标路径格式\n")
					os.Exit(1)
				}
				hostParts := strings.Split(parts[0], "@")
				if len(hostParts) != 2 {
					fmt.Fprintf(os.Stderr, "无效的主机格式\n")
					os.Exit(1)
				}
				user = hostParts[0]
				hosts = []string{hostParts[1]}
				localPath = args[0]
				remotePath = parts[1]
			}
		} else {
			// 使用标志参数
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
						fmt.Println("错误:非法的ip地址:" + host)
						os.Exit(1)
					}
				}
			}

			if sourcePath == "" || destPath == "" {
				fmt.Fprintf(os.Stderr, "必须指定源路径和目标路径\n")
				os.Exit(1)
			}

			if strings.Contains(sourcePath, ":") {
				isUpload = false
				remotePath = sourcePath
				localPath = destPath
			} else {
				isUpload = true
				localPath = sourcePath
				remotePath = destPath
			}
		}

		// 加载密码存储
		passwords, err := utils.LoadPasswords()
		if err != nil {
			fmt.Fprintf(os.Stderr, "无法加载密码存储: %v\n", err)
			passwords = utils.NewPasswordStore()
		}

		passwordModified := false

		// 创建文件传输通道
		concurrency := len(hosts)
		if csvFile != "" {
			concurrency = len(csvHosts)
		}
		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		// 执行文件传输
		transferFile := func(h string, u string, p string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			hostPassword := p
			if hostPassword == "" {
				if storedPass, ok := passwords.GetPass(u, h); ok {
					hostPassword = storedPass
				} else {
					if newPass, err := utils.ReadPasswordFromTerminal(fmt.Sprintf("请输入 %s@%s 的密码: ", u, h)); err == nil {
						hostPassword = newPass
					} else {
						fmt.Fprintf(os.Stderr, "读取密码失败: %v\n", err)
						return
					}
				}

			}
			showProgress, _ := cmd.Flags().GetBool("progress")
			force, _ := cmd.Flags().GetBool("force")
			scp := utils.SCPClient{
				SSHCli: utils.SSHCli{
					Host: h,
					Port: port,
					User: u,
					Pwd:  hostPassword,
				},
				ShowProgress: showProgress,
				Force:        force,
			}

			var err error
			if isUpload {
				err = scp.Upload(localPath, remotePath, isRecursive)
			} else {
				err = scp.Download(remotePath, localPath, isRecursive)
			}

			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] 传输失败: %v\n", h, err)
				return
			}

			// 保存新密码
			if hostPassword != "" {
				passwordModified = passwords.SaveOrUpdate(u, h, hostPassword)
			}

			fmt.Printf("[%s] 传输完成\n", h)
		}

		if len(csvHosts) > 0 {
			for _, host := range csvHosts {
				wg.Add(1)
				go transferFile(host.ip, host.user, host.password)
			}
		} else {
			for _, h := range hosts {
				wg.Add(1)
				go transferFile(h, user, password)
			}
		}

		wg.Wait()

		if passwordModified {
			if err := passwords.Save2File(); err != nil {
				fmt.Fprintf(os.Stderr, "保存密码到文件失败: %v", err)
			} else {
				utils.Logger.Info(fmt.Sprintf("密码已保存到文件: %s@%s", user, ip))
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(scpCmd)

	scpCmd.Flags().StringVarP(&ip, "ip", "i", "", "目标主机,多个主机用逗号分隔")
	scpCmd.Flags().Uint16Var(&port, "port", 22, "SSH端口")
	scpCmd.Flags().StringVarP(&user, "user", "u", "", "SSH用户名")
	scpCmd.Flags().StringVarP(&password, "passwd", "p", "", "SSH密码")
	scpCmd.Flags().StringVarP(&hostFile, "ifile", "I", "", "主机列表文件路径")
	scpCmd.Flags().StringVarP(&csvFile, "csv", "", "", "CSV文件路径(包含主机IP,用户名,密码)")
	scpCmd.Flags().StringVar(&sourcePath, "src", "", "源路径")
	scpCmd.Flags().StringVar(&destPath, "dest", "", "目标路径")
	scpCmd.Flags().BoolVarP(&isRecursive, "recursive", "r", false, "递归复制目录")
	scpCmd.Flags().BoolP("progress", "v", false, "显示传输进度")
	scpCmd.Flags().BoolP("force", "f", false, "强制覆盖远程文件")

}
