package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/wentf9/xops-cli/cmd/utils"
	"github.com/wentf9/xops-cli/pkg/config"
	"github.com/wentf9/xops-cli/pkg/i18n"
	"github.com/wentf9/xops-cli/pkg/logger"
	"github.com/wentf9/xops-cli/pkg/models"
)

func NewCmdIdentity() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "identity",
		Aliases: []string{"id", "auth"},
		Short:   i18n.T("identity_short"),
		Long:    i18n.T("identity_long"),
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
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
		Short: i18n.T("identity_edit_short"),
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
				logger.PrintSuccess(i18n.Tf("identity_update_success", map[string]any{"Name": name}))
			} else {
				logger.PrintWarn(i18n.T("identity_no_changes"))
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&user, "user", "u", "", i18n.T("flag_identity_user"))
	cmd.Flags().StringVarP(&password, "password", "p", "", i18n.T("flag_identity_password"))
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", i18n.T("flag_identity_key"))
	cmd.Flags().StringVarP(&keyPass, "key-pass", "w", "", i18n.T("flag_identity_key_pass"))

	return cmd
}

func NewCmdIdentityList() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: i18n.T("identity_list_short"),
		Run: func(cmd *cobra.Command, args []string) {
			configPath, keyPath := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				logger.PrintError(i18n.Tf("config_load_error", map[string]any{"Error": err}))
				return
			}

			provider := config.NewProvider(cfg)
			identities := provider.ListIdentities()

			if len(identities) == 0 {
				logger.PrintWarn(i18n.T("identity_no_stored"))
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			_, _ = fmt.Fprintln(w, i18n.T("identity_list_header"))

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

				_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
					name,
					id.User,
					id.AuthType,
					detail,
				)
			}
			_ = w.Flush()
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
		Short: i18n.T("identity_add_short"),
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
				pass, err := utils.ReadPasswordFromTerminal(i18n.Tf("prompt_enter_user_password", map[string]any{"User": user}))
				if err != nil {
					return err
				}
				identity.Password = pass
				identity.AuthType = "password"
			}

			provider := config.NewProvider(cfg)
			provider.AddIdentity(name, identity)

			if err := configStore.Save(cfg); err != nil {
				return fmt.Errorf("保存配置文件失败: %w", err)
			}

			logger.PrintSuccess(i18n.Tf("identity_add_success", map[string]any{"Name": name}))
			return nil
		},
	}

	cmd.Flags().StringVarP(&name, "name", "n", "", i18n.T("flag_identity_name"))
	cmd.Flags().StringVarP(&user, "user", "u", "", i18n.T("flag_identity_add_user"))
	cmd.Flags().StringVarP(&password, "password", "p", "", i18n.T("flag_identity_add_password"))
	cmd.Flags().StringVarP(&keyPath, "key", "k", "", i18n.T("flag_identity_add_key"))
	cmd.Flags().StringVarP(&keyPass, "key-pass", "w", "", i18n.T("flag_identity_add_key_pass"))

	return cmd
}

func NewCmdIdentityDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [name]",
		Short: i18n.T("identity_delete_short"),
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

			logger.PrintSuccess(i18n.Tf("identity_delete_success", map[string]any{"Name": name}))
			return nil
		},
	}
}

func init() {
	rootCmd.AddCommand(NewCmdIdentity())
}
