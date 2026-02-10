package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/config"
	"example.com/MikuTools/pkg/models"
	"example.com/MikuTools/pkg/ssh"
	pkgutils "example.com/MikuTools/pkg/utils"
	"github.com/spf13/cobra"
)

type ExecOptions struct {
	SshOptions
	HostFile  string
	CSVFile   string
	CmdFile   string
	ShellFile string
	Command   string
	TaskCount int
	Su        bool
	SuPwd     string
}

func NewExecOptions() *ExecOptions {
	return &ExecOptions{
		SshOptions: *NewSshOptions(),
		TaskCount:  1,
	}
}

func NewCmdExec() *cobra.Command {
	o := NewExecOptions()
	cmd := &cobra.Command{
		Use:   "exec [flags] [command]",
		Short: "对一个或多个远程主机执行命令",
		Long: `对一个或多个远程主机执行命令。支持批量执行和提权。
用法示例:
mtool exec -H host1,host2 -c "uptime"
mtool exec -I hosts.txt -s script.sh
mtool exec user@host "df -h"

通过flags提供主机和用户信息时会覆盖参数提供的信息。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Complete(cmd, args)
			if err := o.Validate(); err != nil {
				return err
			}
			return o.Run()
		},
	}

	// 基础连接参数
	cmd.Flags().StringVarP(&o.Host, "host", "H", "", "目标主机,多个主机用逗号分隔")
	cmd.Flags().Uint16VarP(&o.Port, "port", "P", 0, "SSH端口")
	cmd.Flags().StringVarP(&o.User, "user", "u", "", "SSH用户名")
	cmd.Flags().StringVarP(&o.Password, "password", "w", "", "SSH密码")
	cmd.Flags().StringVarP(&o.KeyFile, "key", "i", "", "SSH私钥文件路径")
	cmd.Flags().StringVarP(&o.KeyPass, "key_pass", "W", "", "SSH私钥密码")
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "j", "", "跳板机地址[user@]host[:port]")
	cmd.Flags().StringVarP(&o.Alias, "alias", "a", "", "连接别名")

	// 提权参数
	cmd.Flags().BoolVarP(&o.Sudo, "sudo", "s", false, "使用sudo执行")
	cmd.Flags().BoolVar(&o.Su, "su", false, "使用su切换到root执行")
	cmd.Flags().StringVar(&o.SuPwd, "suPwd", "", "su切换root的密码")

	// 执行参数
	cmd.Flags().StringVarP(&o.Command, "cmd", "c", "", "要执行的命令")
	cmd.Flags().StringVarP(&o.HostFile, "ifile", "I", "", "主机列表文件")
	cmd.Flags().StringVar(&o.CSVFile, "csv", "", "CSV格式主机列表 (ip,user,password)")
	cmd.Flags().StringVarP(&o.CmdFile, "cfile", "C", "", "包含命令的文件")
	cmd.Flags().StringVar(&o.ShellFile, "shell", "", "本地Shell脚本文件")
	cmd.Flags().IntVar(&o.TaskCount, "task", 1, "并行执行的主机数")

	cmd.MarkFlagsMutuallyExclusive("password", "key")
	cmd.MarkFlagsMutuallyExclusive("host", "ifile", "csv")
	cmd.MarkFlagsMutuallyExclusive("cmd", "cfile", "shell")
	cmd.MarkFlagsMutuallyExclusive("sudo", "su")

	return cmd
}

func (o *ExecOptions) Complete(cmd *cobra.Command, args []string) {
	o.args = args
	if len(args) == 1 && o.Command == "" && o.CmdFile == "" && o.ShellFile == "" {
		// 检查是否是 [user@]host 格式，或者是直接的命令
		if strings.Contains(args[0], "@") || !strings.Contains(args[0], " ") {
			// 可能是主机地址，尝试解析
			u, h, p := utils.ParseAddr(args[0])
			if h != "" {
				if o.Host == "" {
					o.Host = h
				}
				if o.User == "" {
					o.User = u
				}
				if o.Port == 0 {
					o.Port = p
				}
			} else {
				// 否则视为命令
				o.Command = args[0]
			}
		} else {
			o.Command = args[0]
		}
	} else if len(args) > 1 {
		// 可能是 host command ...
		u, h, p := utils.ParseAddr(args[0])
		if h != "" {
			if o.Host == "" {
				o.Host = h
			}
			if o.User == "" {
				o.User = u
			}
			if o.Port == 0 {
				o.Port = p
			}
			if o.Command == "" {
				o.Command = strings.Join(args[1:], " ")
			}
		} else {
			if o.Command == "" {
				o.Command = strings.Join(args, " ")
			}
		}
	}
}

func (o *ExecOptions) Validate() error {
	if o.Command == "" && o.CmdFile == "" && o.ShellFile == "" {
		return fmt.Errorf("必须指定要执行的命令或脚本")
	}
	if o.Host == "" && o.HostFile == "" && o.CSVFile == "" {
		return fmt.Errorf("必须指定目标主机")
	}
	return nil
}

func (o *ExecOptions) Run() error {
	configPath, keyPath := utils.GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %v", err)
	}
	provider := config.NewProvider(cfg)
	connector := ssh.NewConnector(provider)
	defer connector.CloseAll()

	// 准备执行内容
	var execCmd string
	var isScript bool
	if o.ShellFile != "" {
		content, err := os.ReadFile(o.ShellFile)
		if err != nil {
			return fmt.Errorf("读取脚本文件失败: %v", err)
		}
		execCmd = string(content)
		isScript = true
	} else if o.CmdFile != "" {
		content, err := os.ReadFile(o.CmdFile)
		if err != nil {
			return fmt.Errorf("读取命令文件失败: %v", err)
		}
		execCmd = strings.TrimSpace(string(content))
	} else {
		execCmd = o.Command
	}

	hosts, csvHosts, err := utils.ParseHosts(o.Host, o.HostFile, o.CSVFile)
	if err != nil {
		return err
	}

	ctx := context.Background()
	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))

	// 结果收集（可选，目前直接打印）

	executeOnHost := func(h string, u string, pass string) {
		wp.Execute(func() {
			addr := utils.HostInfo{IP: h, User: u, Password: pass}
			nodeId, updated, err := o.getOrCreateNode(provider, addr)
			if err != nil {
				fmt.Printf("[%s] 错误: %v\n", h, err)
				return
			}
			if updated {
				configStore.Save(cfg)
			}

			client, err := connector.Connect(ctx, nodeId)
			if err != nil {
				fmt.Printf("[%s] 连接失败: %v\n", h, err)
				return
			}

			var output string
			var execErr error

			if isScript {
				if o.Sudo || o.Su {
					output, execErr = client.RunScriptWithSudo(ctx, execCmd)
				} else {
					output, execErr = client.RunScript(ctx, execCmd)
				}
			} else {
				if o.Sudo || o.Su {
					output, execErr = client.RunWithSudo(ctx, execCmd)
				} else {
					output, execErr = client.Run(ctx, execCmd)
				}
			}

			if execErr != nil {
				fmt.Printf("[ERROR] %s\n------------\n%s\n错误: %v\n", h, output, execErr)
			} else {
				fmt.Printf("[SUCCESS] %s\n------------\n%s\n", h, output)
			}
		})
	}

	for _, h := range hosts {
		executeOnHost(h, o.User, o.Password)
	}
	for _, ch := range csvHosts {
		executeOnHost(ch.IP, ch.User, ch.Password)
	}

	wp.Wait()
	return nil
}

func (o *ExecOptions) getOrCreateNode(provider config.ConfigProvider, addr utils.HostInfo) (string, bool, error) {
	host := addr.IP
	user := addr.User
	port := o.Port

	if user == "" {
		user = utils.GetCurrentUser()
	}
	if port == 0 {
		port = 22
	}

	nodeId := provider.Find(host)
	if nodeId == "" {
		nodeId = provider.Find(fmt.Sprintf("%s@%s:%d", user, host, port))
	}

	if nodeId != "" {
		updated := o.updateNode(nodeId, provider, addr.Password)
		return nodeId, updated, nil
	}

	// 创建新节点
	nodeId = fmt.Sprintf("%s@%s:%d", user, host, port)
	sudoMode := "none"
	if o.Sudo {
		sudoMode = "sudo"
	} else if o.Su {
		sudoMode = "su"
	}

	node := models.Node{
		HostRef:     fmt.Sprintf("%s:%d", host, port),
		IdentityRef: fmt.Sprintf("%s@%s", user, host),
		ProxyJump:   o.JumpHost,
		SudoMode:    sudoMode,
		SuPwd:       o.SuPwd,
	}

	if node.ProxyJump != "" {
		jumpHost := provider.Find(node.ProxyJump)
		if jumpHost == "" {
			return "", false, fmt.Errorf("跳板机 %s 信息不存在", node.ProxyJump)
		}
		node.ProxyJump = jumpHost
	}

	identity := models.Identity{
		User: user,
	}

	password := addr.Password
	if password == "" && o.KeyFile == "" {
		// 批量执行时，如果没密码，可能需要从终端读一次，但多主机并发读密码会有问题
		// 理想情况下批量执行应该要求已保存密码或通过 flag 提供
		// 这里简单处理
		pass, err := utils.ReadPasswordFromTerminal(fmt.Sprintf("请输入 %s@%s 的密码: ", user, host))
		if err != nil {
			return "", false, err
		}
		password = pass
	}

	if password != "" {
		identity.Password = password
		identity.AuthType = "password"
	} else if o.KeyFile != "" {
		identity.KeyPath = o.KeyFile
		identity.Passphrase = o.KeyPass
		identity.AuthType = "key"
	}

	provider.AddNode(nodeId, node)
	provider.AddHost(node.HostRef, models.Host{Address: host, Port: port})
	provider.AddIdentity(node.IdentityRef, identity)

	return nodeId, true, nil
}

func (o *ExecOptions) updateNode(nodeId string, provider config.ConfigProvider, password string) bool {
	node, _ := provider.GetNode(nodeId)
	identity, _ := provider.GetIdentity(nodeId)
	updated := false

	if password != "" {
		identity.Password = password
		identity.AuthType = "password"
		updated = true
	}

	sudoMode := "none"
	if o.Sudo {
		sudoMode = "sudo"
	} else if o.Su {
		sudoMode = "su"
	}

	if sudoMode != "none" && node.SudoMode != sudoMode {
		node.SudoMode = sudoMode
		updated = true
	}

	if o.SuPwd != "" && node.SuPwd != o.SuPwd {
		node.SuPwd = o.SuPwd
		updated = true
	}

	if updated {
		provider.AddNode(nodeId, node)
		provider.AddIdentity(node.IdentityRef, identity)
	}

	return updated
}

func init() {
	rootCmd.AddCommand(NewCmdExec())
}
