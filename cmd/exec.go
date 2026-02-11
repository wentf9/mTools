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
	ShellFile string
	Command   string
	Tag       string
	TaskCount int
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
mtool exec -t web -c "uptime"
mtool exec -I hosts.txt --shell script.sh
mtool exec user@host "df -h"

通过flags提供主机和用户信息时会覆盖参数提供的信息。
使用 --tag 时会忽略其他主机指定方式。`,
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
	cmd.Flags().Uint16VarP(&o.Port, "port", "p", 0, "SSH端口")
	cmd.Flags().StringVarP(&o.User, "user", "u", "", "SSH用户名")
	cmd.Flags().StringVarP(&o.Password, "password", "P", "", "SSH密码")
	cmd.Flags().StringVarP(&o.KeyFile, "key", "i", "", "SSH私钥文件路径")
	cmd.Flags().StringVarP(&o.KeyPass, "key_pass", "w", "", "SSH私钥密码")
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "j", "", "跳板机地址[user@]host[:port]")
	cmd.Flags().StringVarP(&o.Alias, "alias", "a", "", "连接别名")

	// 提权参数
	cmd.Flags().BoolVarP(&o.Sudo, "sudo", "s", false, "使用sudo执行")
	cmd.Flags().StringVar(&o.SuPwd, "suPwd", "", "su切换root的密码")

	// 执行参数
	cmd.Flags().StringVarP(&o.Command, "cmd", "c", "", "要执行的命令")
	cmd.Flags().StringVarP(&o.HostFile, "ifile", "I", "", "主机列表文件")
	cmd.Flags().StringVar(&o.CSVFile, "csv", "", "CSV格式主机列表 (ip,user,password)")
	cmd.Flags().StringVarP(&o.Tag, "tag", "t", "", "按分组(标签)执行")
	cmd.Flags().StringVar(&o.ShellFile, "shell", "", "本地Shell脚本文件")
	cmd.Flags().IntVar(&o.TaskCount, "task", 3, "并行执行的主机数")

	cmd.MarkFlagsMutuallyExclusive("password", "key")
	cmd.MarkFlagsMutuallyExclusive("host", "ifile", "csv", "tag")
	cmd.MarkFlagsMutuallyExclusive("cmd", "shell")

	return cmd
}

func (o *ExecOptions) Complete(cmd *cobra.Command, args []string) {
	o.args = args
	if len(args) == 0 {
		return
	}

	if o.Command == "" && o.ShellFile == "" {
		hostPart := args[0]
		cmdIdx := 1

		// 如果指定了 tag，args 全部视为命令内容
		if o.Tag != "" {
			o.Command = strings.Join(args, " ")
			return
		}

		// 支持 "iaas @10.238.221.45" 这种中间带空格的格式
		if len(args) > 1 && strings.HasPrefix(args[1], "@") {
			hostPart = args[0] + args[1]
			cmdIdx = 2
		}

		u, h, p := utils.ParseAddr(hostPart)
		// 如果解析出了主机，且不包含空格或者是 [user@]host 格式
		if h != "" && (strings.Contains(hostPart, "@") || !strings.Contains(hostPart, " ")) {
			if o.Host == "" {
				o.Host = h
			}
			if o.User == "" {
				o.User = u
			}
			if o.Port == 0 {
				o.Port = p
			}
			if o.Command == "" && len(args) > cmdIdx {
				o.Command = strings.Join(args[cmdIdx:], " ")
			}
		} else {
			// 否则第一个参数不是主机，可能是命令的一部分
			if o.Command == "" {
				o.Command = strings.Join(args, " ")
			}
		}
	} else {
		// 已经有命令了，检查第一个参数是否是主机
		if o.Host == "" && o.Tag == "" && len(args) > 0 {
			hostPart := args[0]
			if len(args) > 1 && strings.HasPrefix(args[1], "@") {
				hostPart = args[0] + args[1]
			}
			u, h, p := utils.ParseAddr(hostPart)
			if h != "" {
				o.Host = h
				if o.User == "" {
					o.User = u
				}
				if o.Port == 0 {
					o.Port = p
				}
			}
		}
	}
}

func (o *ExecOptions) Validate() error {
	if o.Command == "" && o.ShellFile == "" {
		return fmt.Errorf("必须指定要执行的命令或脚本")
	}
	if o.Host == "" && o.HostFile == "" && o.CSVFile == "" && o.Tag == "" {
		return fmt.Errorf("必须指定目标主机或标签组")
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
	} else {
		execCmd = o.Command
	}

	ctx := context.Background()
	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))

	type hostTask struct {
		nodeId string
		host   string
		port   uint16
		user   string
		pass   string
	}
	var tasks []hostTask
	configUpdated := false

	if o.Tag != "" {
		nodes := provider.GetNodesByTag(o.Tag)
		if len(nodes) == 0 {
			return fmt.Errorf("标签组 %s 为空或不存在", o.Tag)
		}
		for nodeId := range nodes {
			hostObj, _ := provider.GetHost(nodeId)
			identity, _ := provider.GetIdentity(nodeId)
			tasks = append(tasks, hostTask{
				nodeId: nodeId,
				host:   hostObj.Address,
				port:   hostObj.Port,
				user:   identity.User,
				pass:   identity.Password,
			})
		}
	} else {
		hosts, err := utils.ParseHosts(o.Host, o.HostFile, o.CSVFile)
		if err != nil {
			return err
		}

		for _, h := range hosts {
			if h.User == "" {
				h.User = o.User
			}
			if h.Password == "" {
				h.Password = o.Password
			}
			if h.Port == 0 {
				h.Port = o.Port
			}

			addr := utils.HostInfo{Host: h.Host, Port: h.Port, User: h.User, Password: h.Password}
			nodeId, updated, err := o.getOrCreateNode(provider, addr)
			if err != nil {
				fmt.Printf("[%s] 错误: %v\n", h.Host, err)
				continue
			}
			if updated {
				configUpdated = true
			}
			tasks = append(tasks, hostTask{
				nodeId: nodeId,
				host:   h.Host,
				port:   h.Port,
				user:   h.User,
				pass:   h.Password,
			})
		}
	}

	if configUpdated {
		configStore.Save(cfg)
	}

	for _, task := range tasks {
		t := task // capture range variable
		wp.Execute(func() {
			client, err := connector.Connect(ctx, t.nodeId)
			if err != nil {
				fmt.Printf("[%s] 连接失败: %v\n", t.host, err)
				return
			}

			var output string
			var execErr error

			if isScript {
				if o.Sudo {
					output, execErr = client.RunScriptWithSudo(ctx, execCmd)
				} else {
					output, execErr = client.RunScript(ctx, execCmd)
				}
			} else {
				if o.Sudo {
					output, execErr = client.RunWithSudo(ctx, execCmd)
				} else {
					output, execErr = client.Run(ctx, execCmd)
				}
			}

			if execErr != nil {
				fmt.Printf("[ERROR] %s\n------------\n%s\n错误: %v\n", t.host, output, execErr)
			} else {
				fmt.Printf("[SUCCESS] %s\n------------\n%s\n", t.host, output)
			}
		})
	}

	wp.Wait()
	return nil
}

func (o *ExecOptions) getOrCreateNode(provider config.ConfigProvider, addr utils.HostInfo) (string, bool, error) {
	host := strings.TrimSpace(addr.Host)
	user := strings.TrimSpace(addr.User)
	port := addr.Port

	if user == "" {
		user = utils.GetCurrentUser()
	}
	if port == 0 {
		port = 22
	}

	nodeId := provider.Find(fmt.Sprintf("%s@%s:%d", user, host, port))
	if nodeId == "" {
		nodeId = provider.Find(host)
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

	provider.AddHost(node.HostRef, models.Host{Address: host, Port: port})
	provider.AddIdentity(node.IdentityRef, identity)
	provider.AddNode(nodeId, node)

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
