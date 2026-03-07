package host

import (
	"fmt"

	"example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/logger"
	"github.com/spf13/cobra"
)

func NewCmdInventoryEdit() *cobra.Command {
	var (
		address, user, password, keyPath, keyPass, jump string
		port                                            uint16
		alias                                           []string
	)

	cmd := &cobra.Command{
		Use:   "edit [node_id]",
		Short: "修改已存储节点的信息",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldName := args[0]
			store, provider, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			node, ok := provider.GetNode(oldName)
			if !ok {
				return fmt.Errorf("节点 %s 不存在", oldName)
			}

			host, _ := provider.GetHost(oldName)
			identity, _ := provider.GetIdentity(oldName)
			updated, nameChanged := false, false

			if address != "" {
				host.Address, updated, nameChanged = address, true, true
			}
			if port != 0 {
				host.Port, updated, nameChanged = port, true, true
			}
			if user != "" {
				identity.User, updated, nameChanged = user, true, true
			}
			if keyPath != "" {
				identity.KeyPath, identity.AuthType, identity.Password, updated = keyPath, "key", "", true
			} else if password != "" {
				identity.Password, identity.AuthType, identity.KeyPath, updated = password, "password", "", true
			}
			if keyPass != "" {
				identity.Passphrase, updated = keyPass, true
			}
			if cmd.Flags().Changed("alias") {
				node.Alias, updated = alias, true
			}
			if cmd.Flags().Changed("jump") {
				node.ProxyJump, updated = jump, true
			}

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

	cmd.Flags().StringVarP(&address, "address", "H", "", "修改主机 IP 或域名")
	cmd.Flags().Uint16VarP(&port, "port", "p", 0, "修改 SSH 端口")
	cmd.Flags().StringVarP(&user, "user", "u", "", "修改 SSH 用户名")
	cmd.Flags().StringVarP(&password, "password", "P", "", "修改 SSH 密码")
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", "修改 SSH 私钥路径")
	cmd.Flags().StringVarP(&keyPass, "key-pass", "w", "", "修改私钥密码")
	cmd.Flags().StringSliceVarP(&alias, "alias", "a", []string{}, "修改节点别名")
	cmd.Flags().StringVarP(&jump, "jump", "j", "", "修改跳板机名称")
	return cmd
}

func NewCmdInventoryDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [name]",
		Short: "删除一个存储的节点",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			store, provider, cfg, err := utils.GetConfigStore()
			if err != nil {
				return err
			}

			if _, ok := provider.GetNode(name); !ok {
				return fmt.Errorf("节点 %s 不存在", name)
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
