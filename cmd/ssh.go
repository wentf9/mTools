package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/models"
	"github.com/wentf9/xops-cli/pkg/ssh"
)

type SshOptions struct {
	Host     string
	Port     uint16
	User     string
	Password string
	KeyFile  string
	KeyPass  string
	Sudo     bool
	Alias    string
	JumpHost string
	Tags     []string
	args     []string
}

func NewSshOptions() *SshOptions {
	return &SshOptions{
		Sudo: false,
	}
}

func NewCmdSsh() *cobra.Command {
	o := NewSshOptions()
	cmd := &cobra.Command{
		Use:   "ssh [user@]host[:port]",
		Short: i18n.T("ssh_short"),
		Long:  i18n.T("ssh_long"),
		RunE: func(cmd *cobra.Command, args []string) error {
			o.Complete(cmd, args)
			if err := o.Validate(); err != nil {
				return fmt.Errorf("参数错误: %w", err)
			}
			return o.Run()
		},
	}
	cmd.Flags().StringVarP(&o.Host, "host", "H", "", i18n.T("flag_host"))
	cmd.Flags().Uint16VarP(&o.Port, "port", "p", 0, i18n.T("flag_port"))
	cmd.Flags().StringVarP(&o.User, "user", "u", "", i18n.T("flag_user"))
	cmd.Flags().StringVarP(&o.Password, "password", "P", "", i18n.T("flag_password"))
	cmd.Flags().StringVarP(&o.KeyFile, "key", "i", "", i18n.T("flag_key"))
	cmd.Flags().StringVarP(&o.KeyPass, "key_pass", "w", "", i18n.T("flag_key_pass"))
	cmd.Flags().BoolVarP(&o.Sudo, "sudo", "s", false, i18n.T("flag_sudo"))
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "j", "", i18n.T("flag_jump"))
	cmd.Flags().StringVarP(&o.Alias, "alias", "a", "", i18n.T("flag_alias"))
	cmd.Flags().StringSliceVarP(&o.Tags, "tag", "t", []string{}, i18n.T("flag_tag"))
	cmd.MarkFlagsMutuallyExclusive("password", "key")
	return cmd
}

func (o *SshOptions) Complete(cmd *cobra.Command, args []string) {
	o.args = args
}

func (o *SshOptions) Validate() error {
	if len(o.args) > 1 {
		return fmt.Errorf("期望一个参数，但提供了 %d 个", len(o.args))
	}
	if len(o.args) == 0 && o.Host == "" {
		return fmt.Errorf("未提供主机地址")
	} else if len(o.args) == 1 {
		u, h, p := utils.ParseAddr(o.args[0])
		if h == "" && o.Host == "" {
			return fmt.Errorf("无效的主机地址")
		}
		if o.Host == "" {
			o.Host = h
		}
		if o.User == "" {
			o.User = u
		}
		if o.Port == 0 {
			o.Port = p
		}
	}
	if o.User == "" {
		o.User = utils.GetCurrentUser()
	}
	if o.Port == 0 {
		o.Port = 22
	}
	if strings.Contains(o.Alias, "@") || strings.Contains(o.Alias, ":") {
		return errors.New("别名中不可含有<@>或<:>符号")
	}
	return nil
}

func (o *SshOptions) Run() error {
	configStore := config.NewDefaultStore(utils.GetConfigFilePath())
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %w", err)
	}

	provider := config.NewProvider(cfg)

	var nodeID string
	updated := false
	if nodeID = provider.Find(o.Host); nodeID != "" {
		updated = update(nodeID, o, provider)
	} else if nodeID = provider.Find(fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)); nodeID != "" {
		updated = update(nodeID, o, provider)
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
	defer func() { _ = client.Close() }()
	if o.Sudo {
		if err := client.ShellWithSudo(ctx); err != nil {
			return fmt.Errorf("启动sudo环境失败: %w", err)
		}
	} else {
		if err := client.Shell(ctx); err != nil {
			return fmt.Errorf("启动交互式终端失败: %w", err)
		}
	}
	if updated {
		if err := configStore.Save(cfg); err != nil {
			return fmt.Errorf("保存配置文件失败: %w", err)
		}
	}
	return nil
}

func updateNodeFields(node *models.Node, o *SshOptions, provider config.ConfigProvider) bool {
	nodeUpdated := false
	if o.JumpHost != "" {
		jumpHost := provider.Find(o.JumpHost)
		if jumpHost != "" && jumpHost != node.ProxyJump {
			node.ProxyJump = jumpHost
			nodeUpdated = true
		}
	}
	if o.Sudo {
		node.SudoMode = models.SudoModeSudo
		nodeUpdated = true
	}
	if o.Alias != "" {
		node.Alias = append(node.Alias, o.Alias)
		nodeUpdated = true
	}
	if len(o.Tags) > 0 {
		tagMap := make(map[string]bool)
		for _, t := range node.Tags {
			tagMap[t] = true
		}
		for _, t := range o.Tags {
			if !tagMap[t] {
				node.Tags = append(node.Tags, t)
				nodeUpdated = true
			}
		}
	}
	return nodeUpdated
}

func updateIdentityFields(identity *models.Identity, o *SshOptions) bool {
	identityUpdated := false
	if o.Password != "" {
		identity.Password = o.Password
		identity.AuthType = "password"
		identityUpdated = true
	} else if o.KeyFile != "" {
		identity.KeyPath = o.KeyFile
		identity.AuthType = "key"
		identityUpdated = true
	}
	if o.KeyPass != "" {
		identity.Passphrase = o.KeyPass
		identityUpdated = true
	}
	return identityUpdated
}

func (o *SshOptions) createNewNode(provider config.ConfigProvider) (string, error) {
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
		identity.KeyPath = o.KeyFile
		identity.Passphrase = o.KeyPass
		identity.AuthType = "key"
	}
	provider.AddHost(node.HostRef, hostObj)
	provider.AddIdentity(node.IdentityRef, identity)
	provider.AddNode(nodeID, node)
	return nodeID, nil
}

func update(nodeID string, o *SshOptions, provider config.ConfigProvider) bool {
	if o.Password == "" && o.KeyFile == "" && o.JumpHost == "" && !o.Sudo && o.Alias == "" && len(o.Tags) == 0 {
		return false
	}
	node, _ := provider.GetNode(nodeID)
	identity, _ := provider.GetIdentity(nodeID)

	nodeUpdated := updateNodeFields(&node, o, provider)
	identityUpdated := updateIdentityFields(&identity, o)

	if nodeUpdated {
		provider.AddNode(nodeID, node)
	}
	if identityUpdated {
		provider.AddIdentity(node.IdentityRef, identity)
	}
	return nodeUpdated || identityUpdated
}

func init() {
	rootCmd.AddCommand(NewCmdSsh())
}
