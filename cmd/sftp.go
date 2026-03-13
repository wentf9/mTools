package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"strings"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/sftp"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type SftpOptions struct {
	SshOptions
	maxTask   int
	maxThread int
}

func NewSftpOptions() *SftpOptions {
	return &SftpOptions{
		SshOptions: *NewSshOptions(),
	}
}

func NewCmdSftp() *cobra.Command {
	o := NewSftpOptions()
	cmd := &cobra.Command{
		Use:   "sftp [user@]host[:port]",
		Short: "通过sftp连接到指定主机",
		Long: `通过sftp连接到指定主机并提供交互式终端。
用法示例:
xops sftp user@host[:port] [-P password] [--task maxTask] [--thread maxThread]
用户和主机为必选参数,端口默认为22,一般不需要修改
通过flags提供主机和用户信息时会忽略参数提供的信息
如果未通过-p选项显式提供密码,将会从终端输入或通过保存的密码文件读取密码
成功登录过的用户和主机组合的密码将会保存到密码文件中
密码采用对称加密算法加密保存,密码文件位置为~/.xops_passwords.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Complete(cmd, args)
			if err := o.Validate(); err != nil {
				return fmt.Errorf("参数错误: %w", err)
			}
			return o.Run()
		},
	}
	cmd.Flags().IntVar(&o.maxTask, "task", 0, "同时下载文件数")
	cmd.Flags().IntVar(&o.maxThread, "thread", 0, "单个文件同时下载线程")
	cmd.Flags().StringVarP(&o.Password, "password", "P", "", "SSH密码")
	cmd.Flags().StringVarP(&o.KeyFile, "key", "i", "", "SSH私钥文件路径")
	cmd.Flags().StringVarP(&o.KeyPass, "key_pass", "w", "", "SSH私钥密码")
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "j", "", "跳板机地址[user@]host[:port]")
	cmd.Flags().StringVarP(&o.Alias, "alias", "a", "", "连接别名")
	cmd.Flags().StringSliceVarP(&o.Tags, "tag", "t", []string{}, "为节点添加标签(分组)")
	cmd.MarkFlagsMutuallyExclusive("password", "key")
	return cmd
}

func (o *SftpOptions) Run() error {
	configStore := config.NewDefaultStore(utils.GetConfigFilePath())
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %w", err)
	}

	provider := config.NewProvider(cfg)

	var nodeID string
	updated := false
	if nodeID = provider.Find(o.Host); nodeID != "" {
		updated = update(nodeID, &o.SshOptions, provider)
	} else if nodeID = provider.Find(fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)); nodeID != "" {
		updated = update(nodeID, &o.SshOptions, provider)
	} else {
		updated = true
		nodeID = fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)
		node := models.Node{
			HostRef:     fmt.Sprintf("%s:%d", o.Host, o.Port),
			IdentityRef: fmt.Sprintf("%s@%s", o.User, o.Host),
			ProxyJump:   o.JumpHost,
			SudoMode:    "sudo",
			Tags:        o.Tags,
		}
		if node.ProxyJump != "" {
			jumpHost := provider.Find(node.ProxyJump)
			if jumpHost == "" {
				return fmt.Errorf("跳板机 %s 信息不存在,请先保存跳板机信息", node.ProxyJump)
			}
			node.ProxyJump = jumpHost
		}
		hostObj := models.Host{
			Address: strings.TrimSpace(o.Host),
			Port:    o.Port,
		}
		if o.Alias != "" {
			node.Alias = append(node.Alias, strings.TrimSpace(o.Alias))
		}
		identity := models.Identity{
			User: strings.TrimSpace(o.User),
		}
		if o.Password == "" && o.KeyFile == "" {
			if pass, err := utils.ReadPasswordFromTerminal("请输入密码: "); err != nil {
				return err
			} else {
				identity.Password = pass
				identity.AuthType = "password"
			}
		} else if o.Password != "" {
			identity.Password = o.Password
			identity.AuthType = "password"
		} else if o.KeyFile != "" {
			identity.KeyPath = o.KeyFile
			identity.Passphrase = o.KeyPass
			identity.AuthType = "key"
		}
		provider.AddHost(node.HostRef, hostObj)
		provider.AddIdentity(node.IdentityRef, identity)
		provider.AddNode(nodeID, node)
	}
	connector := ssh.NewConnector(provider)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := connector.Connect(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("连接失败: %w", err)
	}
	sftpClient, err := sftp.NewClient(
		client,
		sftp.WithConcurrentFiles(o.maxTask),
		sftp.WithThreadsPerFile(o.maxThread),
	)
	if err != nil {
		return fmt.Errorf("连接失败: %w", err)
	}
	defer func() { _ = sftpClient.Close() }()
	defer func() { _ = client.Close() }()
	// 启动 Shell
	// 使用 os.Stdin, os.Stdout 绑定到当前终端
	shell, err := sftpClient.NewShell(os.Stdin, os.Stdout, os.Stderr)
	if err != nil {
		return fmt.Errorf("sftp交互式环境创建失败: %w", err)
	}
	if err := shell.Run(context.Background()); err != nil {
		return fmt.Errorf("sftp交互式环境启动失败: %w", err)
	}
	if updated {
		if err := configStore.Save(cfg); err != nil {
			return fmt.Errorf("保存配置文件失败: %w", err)
		}
	}
	return nil
}

func init() {
	rootCmd.AddCommand(NewCmdSftp())
}
