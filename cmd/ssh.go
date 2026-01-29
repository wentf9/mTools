package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/config"
	"example.com/MikuTools/pkg/models"
	"example.com/MikuTools/pkg/ssh"
	"github.com/spf13/cobra"
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
		Short: "通过SSH连接到指定主机",
		Long: `通过SSH连接到指定主机并提供交互式终端。
用法示例:
mtool ssh user@host[:port]
mtool ssh user host [port]
mtool -h host -u user
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
	cmd.Flags().StringVarP(&o.Host, "host", "H", "", "目标主机/连接别名")
	cmd.Flags().Uint16VarP(&o.Port, "port", "P", 0, "SSH端口")
	cmd.Flags().StringVarP(&o.User, "user", "u", "", "SSH用户名")
	cmd.Flags().StringVarP(&o.Password, "password", "w", "", "SSH密码")
	cmd.Flags().StringVarP(&o.KeyFile, "key", "i", "", "SSH私钥文件路径")
	cmd.Flags().StringVarP(&o.KeyPass, "key_pass", "W", "", "SSH私钥密码")
	cmd.Flags().BoolVarP(&o.Sudo, "sudo", "s", false, "是否请求sudo权限")
	cmd.Flags().StringVarP(&o.JumpHost, "jump", "j", "", "跳板机地址[user@]host[:port]")
	cmd.Flags().StringVarP(&o.Alias, "alias", "a", "", "连接别名")
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
		return errors.New("别名中不可含有<@>或<:>符号!")
	}
	return nil
}

func (o *SshOptions) Run() error {
	configStore := config.NewDefaultStore(utils.GetConfigFilePath())
	cfg, err := configStore.Load()
	if err != nil {
		return fmt.Errorf("加载配置文件失败: %v", err)
	}

	provider := config.NewProvider(cfg)

	var nodeId string
	updated := false
	if nodeId = provider.Find(o.Host); nodeId != "" {
		updated = update(nodeId, o, provider)
	} else if nodeId = provider.Find(fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)); nodeId != "" {
		updated = update(nodeId, o, provider)
	} else {
		updated = true
		nodeId = fmt.Sprintf("%s@%s:%d", o.User, o.Host, o.Port)
		node := models.Node{
			HostRef:     fmt.Sprintf("%s:%d", o.Host, o.Port),
			IdentityRef: fmt.Sprintf("%s@%s", o.User, o.Host),
			ProxyJump:   o.JumpHost,
			SudoMode:    "sudo",
		}
		if node.ProxyJump != "" {
			jumpHost := provider.Find(node.ProxyJump)
			if jumpHost == "" {
				return fmt.Errorf("跳板机 %s 信息不存在,请先保存跳板机信息", node.ProxyJump)
			}
			node.ProxyJump = jumpHost
		}
		host := models.Host{
			Address: o.Host,
			Port:    o.Port,
		}
		if o.Alias != "" {
			node.Alias = append(node.Alias, o.Alias)
		}
		identity := models.Identity{
			User: o.User,
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
		provider.AddNode(nodeId, node)
		provider.AddHost(node.HostRef, host)
		provider.AddIdentity(node.IdentityRef, identity)
	}
	connector := ssh.NewConnector(provider)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := connector.Connect(ctx, nodeId)
	if err != nil {
		return fmt.Errorf("连接失败: %v", err)
	}
	defer client.Close()
	if o.Sudo {
		if err := client.ShellWithSudo(ctx); err != nil {
			return fmt.Errorf("启动sudo环境失败: %v", err)
		}
	} else {
		if err := client.Shell(ctx); err != nil {
			return fmt.Errorf("启动交互式终端失败: %v", err)
		}
	}
	if updated {
		if err := configStore.Save(cfg); err != nil {
			return fmt.Errorf("保存配置文件失败: %v", err)
		}
	}
	return nil
}

func update(nodeId string, o *SshOptions, provider config.ConfigProvider) bool {
	nodeUpdated := false
	identityUpdated := false
	node, _ := provider.GetNode(nodeId)
	identity, _ := provider.GetIdentity(nodeId)
	if o.Password != "" || o.KeyFile != "" || o.JumpHost != "" || o.Sudo || o.Alias != "" {
		if o.JumpHost != "" {
			jumpHost := provider.Find(o.JumpHost)
			if jumpHost != "" && jumpHost != node.ProxyJump {
				node.ProxyJump = jumpHost
				nodeUpdated = true
			}
		}
		if o.Sudo {
			node.SudoMode = "sudo"
			nodeUpdated = true
		}
		if o.Alias != "" {
			node.Alias = append(node.Alias, o.Alias)
			nodeUpdated = true
		}
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
		provider.AddIdentity(node.IdentityRef, identity)
	}
	if nodeUpdated {
		provider.AddNode(nodeId, node)
	}
	if identityUpdated {
		provider.AddIdentity(node.IdentityRef, identity)
	}
	return nodeUpdated || identityUpdated
}

func init() {
	rootCmd.AddCommand(NewCmdSsh())
}
