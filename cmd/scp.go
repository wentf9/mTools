package cmd

import (
	"fmt"
	"os"
	"strings"
	"sync"

	"example.com/MikuTools/utils"
	"github.com/spf13/cobra"
)

var (
	sourcePath  string
	destPath    string
	isRecursive bool
)

// scpCmd represents the scp command
var scpCmd = &cobra.Command{
	Use:   "scp",
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
			passwords = make(utils.PasswordStore)
		}

		var mu sync.Mutex
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
				mu.Lock()
				if storedPass, ok := passwords.Get(u, h); ok {
					hostPassword = storedPass
				} else {
					if newPass, err := utils.ReadPasswordFromTerminal(fmt.Sprintf("请输入 %s@%s 的密码: ", u, h)); err == nil {
						hostPassword = newPass
					} else {
						fmt.Fprintf(os.Stderr, "读取密码失败: %v\n", err)
						return
					}
				}
				mu.Unlock()
			}
			showProgress, _ := cmd.Flags().GetBool("progress")
			force, _ := cmd.Flags().GetBool("force")
			scp := utils.SCPClient{
				SSHCli: utils.SSHCli{
					Ip:   h,
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
			mu.Lock()
			if storedPass, ok := passwords.Get(u, h); !ok || storedPass != hostPassword {
				if err := passwords.Set(u, h, hostPassword); err == nil {
					passwordModified = true
				}
			}
			mu.Unlock()

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
			if err := passwords.Save(); err != nil {
				fmt.Fprintf(os.Stderr, "保存密码失败: %v\n", err)
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(scpCmd)

	scpCmd.PersistentFlags().StringVarP(&ip, "ip", "i", "", "目标主机,多个主机用逗号分隔")
	scpCmd.PersistentFlags().Uint16Var(&port, "port", 22, "SSH端口")
	scpCmd.PersistentFlags().StringVarP(&user, "user", "u", "", "SSH用户名")
	scpCmd.PersistentFlags().StringVarP(&password, "passwd", "p", "", "SSH密码")
	scpCmd.PersistentFlags().StringVarP(&hostFile, "ifile", "I", "", "主机列表文件路径")
	scpCmd.PersistentFlags().StringVarP(&csvFile, "csv", "", "", "CSV文件路径(包含主机IP,用户名,密码)")
	scpCmd.Flags().StringVar(&sourcePath, "src", "", "源路径")
	scpCmd.Flags().StringVar(&destPath, "dest", "", "目标路径")
	scpCmd.Flags().BoolVarP(&isRecursive, "recursive", "r", false, "递归复制目录")
	scpCmd.Flags().BoolP("progress", "v", false, "显示传输进度")
	scpCmd.Flags().BoolP("force", "f", false, "强制覆盖远程文件")

}
