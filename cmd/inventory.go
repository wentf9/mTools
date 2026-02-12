package cmd

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"example.com/MikuTools/cmd/utils"
	"example.com/MikuTools/pkg/config"
	"example.com/MikuTools/pkg/models"
	"github.com/spf13/cobra"
)

func NewCmdInventory() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "inventory",
		Aliases: []string{"host", "hosts", "inv"},
		Short:   "管理存储的主机和节点信息",
		Long:    `管理存储的主机、身份认证和节点信息。支持列出、添加、修改和删除操作。`,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	cmd.AddCommand(NewCmdInventoryList())
	cmd.AddCommand(NewCmdInventoryAdd())
	cmd.AddCommand(NewCmdInventoryEdit())
	cmd.AddCommand(NewCmdInventoryDelete())
	cmd.AddCommand(NewCmdInventoryTags())
	cmd.AddCommand(NewCmdInventoryTag())

	return cmd
}

func NewCmdInventoryEdit() *cobra.Command {
	var (
		address  string
		port     uint16
		user     string
		password string
		keyPath  string
		keyPass  string
		alias    []string
		jump     string
	)

	cmd := &cobra.Command{
		Use:   "edit [node_id]",
		Short: "修改已存储节点的信息",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldName := args[0]
			configPath, keyPathCfg := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPathCfg)
			cfg, err := configStore.Load()
			if err != nil {
				return err
			}

			provider := config.NewProvider(cfg)
			node, ok := provider.GetNode(oldName)
			if !ok {
				return fmt.Errorf("节点 %s 不存在", oldName)
			}

			host, _ := provider.GetHost(oldName)
			identity, _ := provider.GetIdentity(oldName)
			updated := false
			nameChanged := false

			// 更新主机信息
			if address != "" {
				host.Address = address
				updated = true
				nameChanged = true
			}
			if port != 0 {
				host.Port = port
				updated = true
				nameChanged = true
			}

			// 更新身份信息
			if user != "" {
				identity.User = user
				updated = true
				nameChanged = true
			}
			if keyPath != "" {
				identity.KeyPath = keyPath
				identity.AuthType = "key"
				identity.Password = ""
				updated = true
			} else if password != "" {
				identity.Password = password
				identity.AuthType = "password"
				identity.KeyPath = ""
				updated = true
			}

			if keyPass != "" {
				identity.Passphrase = keyPass
				updated = true
			}

			if cmd.Flags().Changed("alias") {
				node.Alias = alias
				updated = true
			}
			if cmd.Flags().Changed("jump") {
				node.ProxyJump = jump
				updated = true
			}

			if updated {
				newName := oldName
				if nameChanged {
					newName = fmt.Sprintf("%s@%s:%d", identity.User, host.Address, host.Port)
					if newName != oldName {
						if _, exists := provider.GetNode(newName); exists {
							return fmt.Errorf("修改后的节点名称 %s 已存在", newName)
						}
						// 删除旧节点
						provider.DeleteNode(oldName)
					}
				}

				provider.AddHost(node.HostRef, host)
				provider.AddIdentity(node.IdentityRef, identity)
				provider.AddNode(newName, node)

				if err := configStore.Save(cfg); err != nil {
					return err
				}
				fmt.Printf("成功更新节点信息，当前 ID 为: %s\n", newName)
			} else {
				fmt.Println("未提供任何修改项")
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
	cmd.Flags().StringSliceVarP(&alias, "alias", "a", []string{}, "修改节点别名 (覆盖原有别名)")
	cmd.Flags().StringVarP(&jump, "jump", "j", "", "修改跳板机名称")

	return cmd
}

func NewCmdInventoryTag() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tag",
		Short: "管理节点的标签",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	cmd.AddCommand(NewCmdInventoryTagAdd())
	cmd.AddCommand(NewCmdInventoryTagRemove())

	return cmd
}

func NewCmdInventoryTagAdd() *cobra.Command {
	return &cobra.Command{
		Use:   "add [tag_name] [node1,node2...]",
		Short: "将节点加入标签组",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tagName := strings.TrimSpace(args[0])
			nodeNames := strings.Split(args[1], ",")

			if tagName == "" {
				return fmt.Errorf("标签名称不能为空")
			}

			configPath, keyPath := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				return err
			}

			provider := config.NewProvider(cfg)
			updatedCount := 0

			for _, name := range nodeNames {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}

				node, ok := provider.GetNode(name)
				if !ok {
					fmt.Printf("警告: 节点 %s 不存在，跳过\n", name)
					continue
				}

				exists := false
				for _, t := range node.Tags {
					if t == tagName {
						exists = true
						break
					}
				}

				if !exists {
					node.Tags = append(node.Tags, tagName)
					provider.AddNode(name, node)
					updatedCount++
				}
			}

			if updatedCount > 0 {
				if err := configStore.Save(cfg); err != nil {
					return err
				}
				fmt.Printf("成功将 %d 个节点加入标签组 [%s]\n", updatedCount, tagName)
			} else {
				fmt.Println("未对任何节点进行更改")
			}

			return nil
		},
	}
}

func NewCmdInventoryTagRemove() *cobra.Command {
	return &cobra.Command{
		Use:   "remove [tag_name] [node1,node2...]",
		Short: "从指定标签移除节点",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			tagName := strings.TrimSpace(args[0])
			nodeNames := strings.Split(args[1], ",")

			if tagName == "" {
				return fmt.Errorf("标签名称不能为空")
			}

			configPath, keyPath := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				return err
			}

			provider := config.NewProvider(cfg)
			updatedCount := 0

			for _, name := range nodeNames {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}

				node, ok := provider.GetNode(name)
				if !ok {
					fmt.Printf("警告: 节点 %s 不存在，跳过\n", name)
					continue
				}

				newTags := make([]string, 0)
				found := false
				for _, t := range node.Tags {
					if t == tagName {
						found = true
						continue
					}
					newTags = append(newTags, t)
				}

				if found {
					node.Tags = newTags
					provider.AddNode(name, node)
					updatedCount++
				}
			}

			if updatedCount > 0 {
				if err := configStore.Save(cfg); err != nil {
					return err
				}
				fmt.Printf("成功从 %d 个节点中移除了标签 [%s]\n", updatedCount, tagName)
			} else {
				fmt.Println("未对任何节点进行更改")
			}

			return nil
		},
	}
}

func NewCmdInventoryList() *cobra.Command {
	var tagFilter string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "列出所有存储的节点",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, keyPath := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				fmt.Printf("加载配置文件失败: %v\n", err)
				return
			}

			provider := config.NewProvider(cfg)
			var nodes map[string]models.Node
			if tagFilter != "" {
				nodes = provider.GetNodesByTag(tagFilter)
			} else {
				nodes = provider.ListNodes()
			}

			if len(nodes) == 0 {
				if tagFilter != "" {
					fmt.Printf("没有找到带有标签 %s 的节点。\n", tagFilter)
				} else {
					fmt.Println("没有找到已存储的节点。")
				}
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "名称/ID\t别名\t主机地址\t用户\t认证方式\t跳板机\t标签")

			// 排序以便稳定显示
			keys := make([]string, 0, len(nodes))
			for k := range nodes {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, nodeId := range keys {
				node := nodes[nodeId]
				host, _ := provider.GetHost(nodeId)
				identity, _ := provider.GetIdentity(nodeId)

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					nodeId,
					strings.Join(node.Alias, ", "),
					fmt.Sprintf("%s:%d", host.Address, host.Port),
					identity.User,
					identity.AuthType,
					node.ProxyJump,
					strings.Join(node.Tags, ", "),
				)
			}
			w.Flush()
		},
	}
	cmd.Flags().StringVarP(&tagFilter, "tag", "t", "", "按标签筛选节点")
	return cmd
}

func NewCmdInventoryTags() *cobra.Command {
	return &cobra.Command{
		Use:   "tags",
		Short: "列出所有标签及对应的节点数量",
		Run: func(cmd *cobra.Command, args []string) {
			configPath, keyPath := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				fmt.Printf("加载配置文件失败: %v\n", err)
				return
			}

			provider := config.NewProvider(cfg)
			nodes := provider.ListNodes()

			tagMap := make(map[string]int)
			for _, node := range nodes {
				for _, tag := range node.Tags {
					tagMap[tag]++
				}
			}

			if len(tagMap) == 0 {
				fmt.Println("当前没有已定义的标签。")
				return
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "标签\t节点数量")

			tags := make([]string, 0, len(tagMap))
			for t := range tagMap {
				tags = append(tags, t)
			}
			sort.Strings(tags)

			for _, t := range tags {
				fmt.Fprintf(w, "%s\t%d\n", t, tagMap[t])
			}
			w.Flush()
		},
	}
}

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

			configPath, keyPathCfg := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPathCfg)
			cfg, err := configStore.Load()
			if err != nil {
				return fmt.Errorf("加载配置文件失败: %v", err)
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
				identity = models.Identity{
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
				identityRef = fmt.Sprintf("id-%s@%s:%d", identity.User, address, port)
			}

			name := fmt.Sprintf("%s@%s:%d", identity.User, address, port)
			provider := config.NewProvider(cfg)
			if _, ok := provider.GetNode(name); ok {
				return fmt.Errorf("节点 %s 已存在", name)
			}

			hostObj := models.Host{
				Address: address,
				Port:    port,
			}

			node := models.Node{
				HostRef:     fmt.Sprintf("host-%s:%d", address, port),
				IdentityRef: identityRef,
				Alias:       alias,
				Tags:        tags,
				ProxyJump:   jump,
				SudoMode:    "sudo",
			}

			if identityAlias == "" {
				provider.AddIdentity(identityRef, identity)
			}
			provider.AddHost(node.HostRef, hostObj)
			provider.AddNode(name, node)

			if err := configStore.Save(cfg); err != nil {
				return fmt.Errorf("保存配置文件失败: %v", err)
			}

			fmt.Printf("成功添加节点: %s\n", name)
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

func NewCmdInventoryDelete() *cobra.Command {
	return &cobra.Command{
		Use:   "delete [name]",
		Short: "删除一个存储的节点",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			configPath, keyPath := utils.GetConfigFilePath()
			configStore := config.NewDefaultStore(configPath, keyPath)
			cfg, err := configStore.Load()
			if err != nil {
				return fmt.Errorf("加载配置文件失败: %v", err)
			}

			provider := config.NewProvider(cfg)
			if _, ok := provider.GetNode(name); !ok {
				return fmt.Errorf("节点 %s 不存在", name)
			}

			provider.DeleteNode(name)

			if err := configStore.Save(cfg); err != nil {
				return fmt.Errorf("保存配置文件失败: %v", err)
			}

			fmt.Printf("成功删除节点: %s\n", name)
			return nil
		},
	}
}

func init() {
	rootCmd.AddCommand(NewCmdInventory())
}
