package host

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

func NewCmdInventoryAdd() *cobra.Command {
	var (
		address       string
		port          uint16
		user          string
		password      string
		keyPath       string
		keyPass       string
		identityAlias string
		alias         []string
		tags          []string
		jump          string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "添加一个新节点",
		RunE: func(cmd *cobra.Command, args []string) error {
			if address == "" {
				return fmt.Errorf("必须指定主机地址 (--address)")
			}

			store, provider, cfg, err := utils.GetConfigStore()
			if err != nil {
				return fmt.Errorf("加载配置文件失败: %w", err)
			}

			if port == 0 {
				port = 22
			}

			var identity models.Identity
			var identityRef string

			if identityAlias != "" {
				var ok bool
				identity, ok = cfg.Identities.Get(identityAlias)
				if !ok {
					return fmt.Errorf("认证模板 %s 不存在", identityAlias)
				}
				identityRef = identityAlias
			} else {
				if user == "" {
					user = utils.GetCurrentUser()
				}
				identity = models.Identity{User: user}
				if keyPath != "" {
					identity.KeyPath, identity.Passphrase, identity.AuthType = keyPath, keyPass, "key"
				} else if password != "" {
					identity.Password, identity.AuthType = password, "password"
				} else {
					pass, err := utils.ReadPasswordFromTerminal(fmt.Sprintf("请输入用户 %s 的密码: ", user))
					if err != nil {
						return err
					}
					identity.Password, identity.AuthType = pass, "password"
				}
				identityRef = fmt.Sprintf("id-%s@%s:%d", identity.User, address, port)
			}

			name := fmt.Sprintf("%s@%s:%d", identity.User, address, port)
			if _, ok := provider.GetNode(name); ok {
				return fmt.Errorf("节点 %s 已存在", name)
			}

			hostObj := models.Host{Address: address, Port: port}
			node := models.Node{
				HostRef:     fmt.Sprintf("host-%s:%d", address, port),
				IdentityRef: identityRef,
				Alias:       alias,
				Tags:        tags,
				ProxyJump:   jump,
				SudoMode:    models.SudoModeAuto,
			}

			if identityAlias == "" {
				provider.AddIdentity(identityRef, identity)
			}
			provider.AddHost(node.HostRef, hostObj)
			provider.AddNode(name, node)

			if err := store.Save(cfg); err != nil {
				return fmt.Errorf("保存配置文件失败: %w", err)
			}

			logger.PrintSuccessf("成功添加节点: %s", name)
			return nil
		},
	}

	cmd.Flags().StringVarP(&address, "address", "H", "", "主机 IP 或域名")
	cmd.Flags().Uint16VarP(&port, "port", "p", 22, "SSH 端口")
	cmd.Flags().StringVarP(&user, "user", "u", "", "SSH 用户名")
	cmd.Flags().StringVarP(&password, "password", "P", "", "SSH 密码")
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", "SSH 私钥路径")
	cmd.Flags().StringVarP(&keyPass, "key-pass", "w", "", "SSH 私钥密码")
	cmd.Flags().StringVarP(&identityAlias, "identity", "I", "", "使用已保存的认证模板别名")
	cmd.Flags().StringSliceVarP(&alias, "alias", "a", []string{}, "节点别名 (逗号分隔)")
	cmd.Flags().StringSliceVarP(&tags, "tags", "t", []string{}, "节点标签 (逗号分隔)")
	cmd.Flags().StringVarP(&jump, "jump", "j", "", "跳板机名称")

	return cmd
}
