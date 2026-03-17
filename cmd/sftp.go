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
	"github.com/wentf9/xops-cli/pkg/i18n"
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
		Short: i18n.T("sftp_short"),
		Long:  i18n.T("sftp_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Complete(cmd, args)
			if err := o.Validate(); err != nil {
				return fmt.Errorf("参数错误: %w", err)
			}
			return o.Run()
		},
	}
	cmd.Flags().IntVar(&o.maxTask, "task", 0, i18n.T("flag_sftp_task"))
	cmd.Flags().IntVar(&o.maxThread, "thread", 0, i18n.T("flag_sftp_thread"))
	cmd.Flags().StringVarP(&o.Password, "password", "P", "", i18n.T("flag_password"))
	cmd.Flags().StringVarP(&o.KeyFile, "key", "i", "", i18n.T("flag_key"))
	cmd.Flags().StringVarP(&o.KeyPass, "key_pass", "w", "", i18n.T("flag_key_pass"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "j", "", i18n.T("flag_jump"))
	cmd.Flags().StringVarP(&o.Alias, "alias", "a", "", i18n.T("flag_alias"))
	cmd.Flags().StringSliceVarP(&o.Tags, "tag", "t", []string{}, i18n.T("flag_tag"))
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
		nodeID, err = o.createNewNode(provider)
		if err != nil {
			return err
		}
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

func (o *SftpOptions) createNewNode(provider config.ConfigProvider) (string, error) {
	nodeID := fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)
	node := models.Node{
		HostRef:     fmt.Sprintf("%s:%d", o.Host, o.Port),
		IdentityRef: fmt.Sprintf("%s@%s", o.User, o.Host),
		ProxyJump:   o.JumpHost,
		SudoMode:    models.SudoModeAuto,
		Tags:        o.Tags,
	}
	if node.ProxyJump != "" {
		jumpHost := provider.Find(node.ProxyJump)
		if jumpHost == "" {
			return "", fmt.Errorf("跳板机 %s 信息不存在,请先保存跳板机信息", node.ProxyJump)
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
		pass, err := utils.ReadPasswordFromTerminal(i18n.T("prompt_enter_password"))
		if err != nil {
			return "", err
		}
		identity.Password = pass
		identity.AuthType = "password"
	} else if o.Password != "" {
		identity.Password = o.Password
		identity.AuthType = "password"
	} else if o.KeyFile != "" {
		identity.KeyPath = utils.ToAbsolutePath(o.KeyFile)
		identity.Passphrase = o.KeyPass
		identity.AuthType = "key"
	}
	provider.AddHost(node.HostRef, hostObj)
	provider.AddIdentity(node.IdentityRef, identity)
	provider.AddNode(nodeID, node)
	return nodeID, nil
}

func init() {
	rootCmd.AddCommand(NewCmdSftp())
}
