package host

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

type editFlags struct {
	address, user, password, keyPath, keyPass, jump string
	port                                            uint16
	alias                                           []string
}

func NewCmdInventoryEdit() *cobra.Command {
	flags := &editFlags{}

	cmd := &cobra.Command{
		Use:   "edit [node_id]",
		Short: "修改已存储节点的信息",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := args[0]
			store, provider, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			oldName := provider.Find(query)
			if oldName == "" {
				return fmt.Errorf("节点 %s 不存在", query)
			}

			node, _ := provider.GetNode(oldName)

			host, _ := provider.GetHost(oldName)
			identity, _ := provider.GetIdentity(oldName)

			updated, nameChanged := applyNodeUpdates(cmd, &host, &identity, &node, flags)

			if updated {
				newName := oldName
				if nameChanged {
					newName = fmt.Sprintf("%s@%s:%d", identity.User, host.Address, host.Port)
					if newName != oldName {
						if _, exists := provider.GetNode(newName); exists {
							return fmt.Errorf("修改后的节点名称 %s 已存在", newName)
						}
						provider.DeleteNode(oldName)
					}
				}
				provider.AddHost(node.HostRef, host)
				provider.AddIdentity(node.IdentityRef, identity)
				provider.AddNode(newName, node)
				if err := store.Save(cfg); err != nil {
					return err
				}
				logger.PrintSuccessf("成功更新节点信息，当前 ID 为: %s", newName)
			} else {
				logger.PrintWarnf("未提供任何修改项")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&flags.address, "address", "H", "", "修改主机 IP 或域名")
	cmd.Flags().Uint16VarP(&flags.port, "port", "p", 0, "修改 SSH 端口")
	cmd.Flags().StringVarP(&flags.user, "user", "u", "", "修改 SSH 用户名")
	cmd.Flags().StringVarP(&flags.password, "password", "P", "", "修改 SSH 密码")
	cmd.Flags().StringVarP(&flags.keyPath, "key", "k", "", "修改 SSH 私钥路径")
	cmd.Flags().StringVarP(&flags.keyPass, "key-pass", "w", "", "修改私钥密码")
	cmd.Flags().StringSliceVarP(&flags.alias, "alias", "a", []string{}, "修改节点别名")
	cmd.Flags().StringVarP(&flags.jump, "jump", "j", "", "修改跳板机名称")
	return cmd
}

func applyNodeUpdates(cmd *cobra.Command, host *models.Host, identity *models.Identity, node *models.Node, flags *editFlags) (updated, nameChanged bool) {
	if flags.address != "" {
		host.Address, updated, nameChanged = flags.address, true, true
	}
	if flags.port != 0 {
		host.Port, updated, nameChanged = flags.port, true, true
	}
	if flags.user != "" {
		identity.User, updated, nameChanged = flags.user, true, true
	}
	if flags.keyPath != "" {
		identity.KeyPath, identity.AuthType, identity.Password, updated = flags.keyPath, "key", "", true
	} else if flags.password != "" {
		identity.Password, identity.AuthType, identity.KeyPath, updated = flags.password, "password", "", true
	}
	if flags.keyPass != "" {
		identity.Passphrase, updated = flags.keyPass, true
	}
	if cmd.Flags().Changed("alias") {
		node.Alias, updated = flags.alias, true
	}
	if cmd.Flags().Changed("jump") {
		node.ProxyJump, updated = flags.jump, true
	}
	return updated, nameChanged
}

func NewCmdInventoryDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [name]",
		Short: "删除一个存储的节点",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := args[0]
			store, provider, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			name := provider.Find(query)
			if name == "" {
				return fmt.Errorf("节点 %s 不存在", query)
			}
			provider.DeleteNode(name)
			if err := store.Save(cfg); err != nil {
				return err
			}
			logger.PrintSuccessf("成功删除节点: %s", name)
			return nil
		},
	}
}
