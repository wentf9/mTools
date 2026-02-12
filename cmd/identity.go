package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/config"
	"example.com/MikuTools/pkg/models"
	"github.com/spf13/cobra"
)

func NewCmdIdentity() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "identity",
		Aliases: []string{"id", "auth"},
		Short:   "管理认证信息模板",
		Long:    `管理存储的认证信息模板（用户、密码、私钥）。通过别名可以在添加主机时快速复用。`,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	cmd.AddCommand(NewCmdIdentityList())
	cmd.AddCommand(NewCmdIdentityAdd())
	cmd.AddCommand(NewCmdIdentityEdit())
	cmd.AddCommand(NewCmdIdentityDelete())

	return cmd
}

func NewCmdIdentityEdit() *cobra.Command {
	var (
		user     string
		password string
		keyPath  string
		keyPass  string
	)

	cmd := &cobra.Command{
		Use:   "edit [name]",
		Short: "修改已存储的认证信息模板",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			configPath, keyPathCfg := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPathCfg)
			cfg, err := configStore.Load()
			if err != nil {
				return err
			}

			identity, ok := cfg.Identities.Get(name)
			if !ok {
				return fmt.Errorf("认证模板 %s 不存在", name)
			}

			updated := false
			if user != "" {
				identity.User = user
				updated = true
			}

			if keyPath != "" {
				identity.KeyPath = keyPath
				identity.AuthType = "key"
				identity.Password = "" // 切换到密钥时清空密码
				updated = true
			} else if password != "" {
				identity.Password = password
				identity.AuthType = "password"
				identity.KeyPath = "" // 切换到密码时清空密钥路径
				updated = true
			}

			if keyPass != "" {
				identity.Passphrase = keyPass
				updated = true
			}

			if updated {
				provider := config.NewProvider(cfg)
				provider.AddIdentity(name, identity)

				if err := configStore.Save(cfg); err != nil {
					return err
				}
				fmt.Printf("成功更新认证模板: %s\n", name)
			} else {
				fmt.Println("未提供任何修改项")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&user, "user", "u", "", "修改用户名")
	cmd.Flags().StringVarP(&password, "password", "p", "", "修改密码")
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", "修改私钥路径")
	cmd.Flags().StringVarP(&keyPass, "key-pass", "w", "", "修改私钥密码")

	return cmd
}

func NewCmdIdentityList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "列出所有存储的认证信息",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, keyPath := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				fmt.Printf("加载配置文件失败: %v\n", err)
				return
			}

			provider := config.NewProvider(cfg)
			identities := provider.ListIdentities()

			if len(identities) == 0 {
				fmt.Println("没有找到已存储的认证信息。")
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "别名/名称\t用户\t认证方式\t详细信息")

			keys := make([]string, 0, len(identities))
			for k := range identities {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, name := range keys {
				id := identities[name]
				detail := ""
				switch id.AuthType {
				case "key":
					detail = id.KeyPath
				case "password":
					detail = "******"
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					name,
					id.User,
					id.AuthType,
					detail,
				)
			}
			w.Flush()
		},
	}
}

func NewCmdIdentityAdd() *cobra.Command {
	var (
		name     string
		user     string
		password string
		keyPath  string
		keyPass  string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "添加一个新的认证信息模板",
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("必须指定别名 (--name)")
			}

			configPath, keyPathCfg := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPathCfg)
			cfg, err := configStore.Load()
			if err != nil {
				return err
			}

			if _, ok := cfg.Identities.Get(name); ok {
				return fmt.Errorf("认证信息模板 %s 已存在", name)
			}

			if user == "" {
				user = utils.GetCurrentUser()
			}

			identity := models.Identity{
				User: user,
			}

			if keyPath != "" {
				identity.KeyPath = keyPath
				identity.Passphrase = keyPass
				identity.AuthType = "key"
			} else if password != "" {
				identity.Password = password
				identity.AuthType = "password"
			} else {
				pass, err := utils.ReadPasswordFromTerminal(fmt.Sprintf("请输入用户 %s 的密码: ", user))
				if err != nil {
					return err
				}
				identity.Password = pass
				identity.AuthType = "password"
			}

			provider := config.NewProvider(cfg)
			provider.AddIdentity(name, identity)

			if err := configStore.Save(cfg); err != nil {
				return fmt.Errorf("保存配置文件失败: %v", err)
			}

			fmt.Printf("成功添加认证模板: %s\n", name)
			return nil
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", "认证信息别名")
	cmd.Flags().StringVarP(&user, "user", "u", "", "用户名")
	cmd.Flags().StringVarP(&password, "password", "p", "", "密码")
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", "私钥路径")
	cmd.Flags().StringVarP(&keyPass, "key-pass", "w", "", "私钥密码")

	return cmd
}

func NewCmdIdentityDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [name]",
		Short: "删除一个认证信息模板",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			configPath, keyPath := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				return err
			}

			provider := config.NewProvider(cfg)
			if _, ok := cfg.Identities.Get(name); !ok {
				return fmt.Errorf("认证模板 %s 不存在", name)
			}

			provider.DeleteIdentity(name)

			if err := configStore.Save(cfg); err != nil {
				return err
			}

			fmt.Printf("成功删除认证模板: %s\n", name)
			return nil
		},
	}
}

func init() {
	rootCmd.AddCommand(NewCmdIdentity())
}
