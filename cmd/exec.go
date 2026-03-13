package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
	pkgutils "github.com/wentf9/xops-cli/pkg/utils"
)

type ExecOptions struct {
	SshOptions
	HostFile  string
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
xops exec -H host1,host2 -c "uptime"
xops exec -t web -c "uptime"
xops exec -I hosts.txt --shell script.sh
xops exec user@host "df -h"

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
	cmd.Flags().StringVarP(&o.Tag, "tag", "t", "", "按分组(标签)执行")
	cmd.Flags().StringVar(&o.ShellFile, "shell", "", "本地Shell脚本文件")
	cmd.Flags().IntVar(&o.TaskCount, "task", 3, "并行执行的主机数")

	cmd.MarkFlagsMutuallyExclusive("password", "key")
	cmd.MarkFlagsMutuallyExclusive("host", "ifile", "tag")
	cmd.MarkFlagsMutuallyExclusive("cmd", "shell")

	return cmd
}

func (o *ExecOptions) extractCommandFromArgs(args []string) {
	hostPart := args[0]
	cmdIdx := 1
	if o.Tag != "" {
		o.Command = strings.Join(args, " ")
		return
	}
	if len(args) > 1 && strings.HasPrefix(args[1], "@") {
		hostPart = args[0] + args[1]
		cmdIdx = 2
	}
	u, h, p := utils.ParseAddr(hostPart)
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
		if o.Command == "" {
			o.Command = strings.Join(args, " ")
		}
	}
}

func (o *ExecOptions) extractHostFromArgs(args []string) {
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

func (o *ExecOptions) Complete(cmd *cobra.Command, args []string) {
	o.args = args
	if len(args) == 0 {
		return
	}
	if o.Command == "" && o.ShellFile == "" {
		o.extractCommandFromArgs(args)
	} else {
		o.extractHostFromArgs(args)
	}
}

func (o *ExecOptions) Validate() error {
	if o.Command == "" && o.ShellFile == "" {
		return fmt.Errorf("必须指定要执行的命令或脚本")
	}
	if o.Host == "" && o.HostFile == "" && o.Tag == "" {
		return fmt.Errorf("必须指定目标主机或标签组")
	}
	return nil
}

type execHostTask struct {
	nodeID string
	host   string
	port   uint16
	user   string
	pass   string
}

func (o *ExecOptions) Run() error {
	configPath, keyPath := utils.GetConfigFilePath()
	configStore := config.NewDefaultStore(configPath, keyPath)
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %w", err)
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
			return fmt.Errorf("读取脚本文件失败: %w", err)
		}
		execCmd = string(content)
		isScript = true
	} else {
		execCmd = o.Command
	}

	ctx := context.Background()
	wp := pkgutils.NewWorkerPool(uint(o.TaskCount))

	var tasks []execHostTask
	var errTask error

	if o.Tag != "" {
		tasks, errTask = o.buildTasksFromTags(provider)
	} else {
		tasks, errTask = o.buildTasksFromHosts(provider)
	}

	if errTask != nil {
		return errTask
	}

	for _, task := range tasks {
		t := task // capture range variable
		wp.Execute(func() {
			client, err := connector.Connect(ctx, t.nodeID)
			if err != nil {
				logger.PrintErrorf("[%s] 连接失败: %v", t.host, err)
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
				logger.PrintErrorf("%s\n------------\n%s\n错误: %v", t.host, output, execErr)
			} else {
				logger.PrintSuccessf("%s\n------------\n%s", t.host, output)
			}
		})
	}

	wp.Wait()
	if err := configStore.Save(cfg); err != nil {
		logger.PrintErrorf("保存配置失败: %v", err)
	}
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

	nodeID := provider.Find(fmt.Sprintf("%s@%s:%d", user, host, port))
	if nodeID == "" {
		nodeID = provider.Find(host)
	}

	if nodeID != "" {
		updated := o.updateNodeFromHostInfo(nodeID, provider, addr)
		return nodeID, updated, nil
	}

	nodeID, err := o.execCreateNewNode(provider, host, user, port, addr)
	return nodeID, true, err
}

func (o *ExecOptions) buildTasksFromTags(provider config.ConfigProvider) ([]execHostTask, error) {
	var tasks []execHostTask
	nodes := provider.GetNodesByTag(o.Tag)
	if len(nodes) == 0 {
		return nil, fmt.Errorf("标签组 %s 为空或不存在", o.Tag)
	}
	for nodeID := range nodes {
		hostObj, _ := provider.GetHost(nodeID)
		identity, _ := provider.GetIdentity(nodeID)
		tasks = append(tasks, execHostTask{
			nodeID: nodeID,
			host:   hostObj.Address,
			port:   hostObj.Port,
			user:   identity.User,
			pass:   identity.Password,
		})
	}
	return tasks, nil
}

func (o *ExecOptions) buildTasksFromHosts(provider config.ConfigProvider) ([]execHostTask, error) {
	var tasks []execHostTask
	hosts, err := utils.ParseHosts(o.Host, o.HostFile, "")
	if err != nil {
		return nil, err
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
		addr := utils.HostInfo{
			Host:       h.Host,
			Port:       h.Port,
			User:       h.User,
			Password:   h.Password,
			Alias:      h.Alias,
			KeyPath:    h.KeyPath,
			Passphrase: h.Passphrase,
		}
		nodeID, _, err := o.getOrCreateNode(provider, addr)
		if err != nil {
			logger.PrintErrorf("[%s] 错误: %v", h.Host, err)
			continue
		}
		tasks = append(tasks, execHostTask{
			nodeID: nodeID,
			host:   h.Host,
			port:   h.Port,
			user:   h.User,
			pass:   h.Password,
		})
	}
	return tasks, nil
}

func (o *ExecOptions) execCreateNewNode(provider config.ConfigProvider, host, user string, port uint16, addr utils.HostInfo) (string, error) {
	nodeID := fmt.Sprintf("%s@%s:%d", user, host, port)
	sudoMode := models.SudoModeNone
	if o.Sudo {
		sudoMode = models.SudoModeSudo
	}

	node := models.Node{
		HostRef:     fmt.Sprintf("%s:%d", host, port),
		IdentityRef: fmt.Sprintf("%s@%s", user, host),
		ProxyJump:   o.JumpHost,
		SudoMode:    sudoMode,
		SuPwd:       o.SuPwd,
	}

	if addr.Alias != "" {
		node.Alias = []string{addr.Alias}
	} else if o.Alias != "" {
		node.Alias = []string{o.Alias}
	}

	if node.ProxyJump != "" {
		jumpHost := provider.Find(node.ProxyJump)
		if jumpHost == "" {
			return "", fmt.Errorf("跳板机 %s 信息不存在", node.ProxyJump)
		}
		node.ProxyJump = jumpHost
	}

	identity := models.Identity{
		User: user,
	}

	password := addr.Password
	if password == "" && addr.KeyPath == "" {
		if o.Password != "" {
			password = o.Password
		} else if o.KeyFile == "" {
			pass, err := utils.ReadPasswordFromTerminal(fmt.Sprintf("请输入 %s@%s 的密码: ", user, host))
			if err != nil {
				return "", err
			}
			password = pass
		}
	}

	if password != "" {
		identity.Password = password
		identity.AuthType = "password"
	} else {
		keyPath := addr.KeyPath
		if keyPath == "" {
			keyPath = o.KeyFile
		}
		keyPass := addr.Passphrase
		if keyPass == "" {
			keyPass = o.KeyPass
		}

		if keyPath != "" {
			identity.KeyPath = keyPath
			identity.Passphrase = keyPass
			identity.AuthType = "key"
		}
	}

	provider.AddHost(node.HostRef, models.Host{Address: host, Port: port})
	provider.AddIdentity(node.IdentityRef, identity)
	provider.AddNode(nodeID, node)

	return nodeID, nil
}

func appendExecAlias(slice []string, val string) ([]string, bool) {
	if val == "" {
		return slice, false
	}
	for _, item := range slice {
		if item == val {
			return slice, false
		}
	}
	return append(slice, val), true
}

func (o *ExecOptions) updateNodeFromHostInfo(nodeID string, provider config.ConfigProvider, addr utils.HostInfo) bool {
	node, _ := provider.GetNode(nodeID)
	identity, _ := provider.GetIdentity(nodeID)
	updated := false

	// 更新密码或密钥
	if addr.Password != "" {
		if identity.Password != addr.Password || identity.AuthType != "password" {
			identity.Password = addr.Password
			identity.AuthType = "password"
			updated = true
		}
	} else if addr.KeyPath != "" {
		if identity.KeyPath != addr.KeyPath || identity.Passphrase != addr.Passphrase || identity.AuthType != "key" {
			identity.KeyPath = addr.KeyPath
			identity.Passphrase = addr.Passphrase
			identity.AuthType = "key"
			updated = true
		}
	}

	// 更新别名
	aliases, changed := appendExecAlias(node.Alias, addr.Alias)
	if changed {
		node.Alias = aliases
		updated = true
	}

	sudoMode := models.SudoModeNone
	if o.Sudo {
		sudoMode = models.SudoModeSudo
	}

	if sudoMode != models.SudoModeNone && node.SudoMode != sudoMode {
		node.SudoMode = sudoMode
		updated = true
	}

	if o.SuPwd != "" && node.SuPwd != o.SuPwd {
		node.SuPwd = o.SuPwd
		updated = true
	}

	if updated {
		provider.AddNode(nodeID, node)
		provider.AddIdentity(node.IdentityRef, identity)
	}

	return updated
}

func init() {
	rootCmd.AddCommand(NewCmdExec())
}
